// Native Nginx messages contain request/header/path data even when access logs
// redact queries. Only fixed diagnostic codes cross this persistence boundary.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sync"
	"syscall"
	"time"
)

const logPath = "/var/log/nginx/native-errors.json.log"
const maxLine = 8192

var severity = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[(emerg|alert|crit|error|warn|notice|info|debug)\] \d+#\d+: `)

type diagnostic struct {
	Time     string `json:"@timestamp"`
	Observer string `json:"observer.type"`
	Severity string `json:"log.level"`
	Code     string `json:"event.code"`
}

func classify(line []byte) diagnostic {
	d := diagnostic{Time: time.Now().UTC().Format(time.RFC3339Nano), Observer: "nginx", Severity: "warn", Code: "unclassified_native_error"}
	m := severity.FindSubmatchIndex(line)
	if m == nil {
		return d
	}
	d.Severity = string(line[m[2]:m[3]])
	// Never copy even a fragment of native text. Main messages as well as the
	// appended context can contain secrets; unknown formats stay opaque.
	for _, item := range []struct{ text, code string }{
		{"connect() failed", "upstream_connect_failed"},
		{"upstream timed out", "upstream_timeout"},
		{"host not found in upstream", "upstream_dns_failed"},
		{"no resolver defined", "upstream_resolver_missing"},
		{"upstream sent too big header", "upstream_header_too_large"},
		{"client intended to send too large body", "request_body_too_large"},
		{"limiting requests", "request_rate_limited"},
		{"open()", "file_open_failed"},
		{"permission denied", "permission_denied"},
	} {
		if bytes.Contains(line[m[1]:], []byte(item.text)) {
			d.Code = item.code
			break
		}
	}
	return d
}

// Bound memory for missing newlines, including inputs larger than pipe buffers.
// Oversized or unterminated messages never regain a trusted prefix mid-line.
func consume(r io.Reader, emit func(diagnostic) error) error {
	b := bufio.NewReaderSize(r, maxLine)
	oversized := false
	for {
		line, err := b.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			oversized = true
			continue
		}
		if len(line) != 0 || oversized {
			d := classify(nil)
			if !oversized && err == nil {
				d = classify(line)
			}
			if e := emit(d); e != nil {
				return e
			}
		}
		oversized = false
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

type sink struct {
	mu   sync.Mutex
	file *os.File
}

func (s *sink) reopen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Do not follow a replaced symlink in the writable log directory.
	fd, err := syscall.Open(logPath, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0640)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), logPath)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return errors.New("invalid diagnostic sink")
	}
	old := s.file
	s.file = f
	if old != nil {
		old.Close()
	}
	return nil
}
func (s *sink) emit(d diagnostic) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err = s.file.Write(b); err != nil {
		return err
	}
	_, err = os.Stderr.Write(b)
	return err
}

func run(args []string) int {
	if len(args) == 0 {
		return 64
	}
	var output sink
	if err := output.reopen(); err != nil {
		fmt.Fprintln(os.Stderr, "Nginx diagnostic sink unavailable")
		return 111
	}
	defer func() { output.file.Close() }()
	// -e covers bootstrap errors before the main configuration is read.
	if args[0] == "nginx" || args[0] == "nginx-debug" {
		args = append([]string{args[0], "-e", "stderr"}, args[1:]...)
	}
	child := exec.Command("/docker-entrypoint.sh", args...)
	child.Stdout = os.Stdout
	child.Stdin = os.Stdin
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	r, w, err := os.Pipe()
	if err != nil {
		return 111
	}
	defer r.Close()
	child.Stderr = w
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)
	defer signal.Stop(signals)
	if err = child.Start(); err != nil {
		w.Close()
		fmt.Fprintln(os.Stderr, "Nginx process unavailable")
		return 111
	}
	w.Close()
	logs := make(chan error, 1)
	go func() { logs <- consume(r, output.emit) }()
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	failed := false
	for {
		select {
		case err := <-logs:
			logs = nil
			if err != nil {
				failed = true
				syscall.Kill(-child.Process.Pid, syscall.SIGTERM)
			}
		case received := <-signals:
			if received == syscall.SIGUSR1 {
				if output.reopen() != nil {
					failed = true
					syscall.Kill(-child.Process.Pid, syscall.SIGTERM)
					continue
				}
			}
			_ = child.Process.Signal(received)
		case err := <-done:
			// Reap all output before reporting the original command's exit code.
			if logs != nil {
				select {
				case logErr := <-logs:
					if logErr != nil {
						failed = true
					}
				case <-time.After(2 * time.Second):
					// An explicit daemonizing/custom command may leave descendants
					// holding stderr. Preserve stock entrypoint exit semantics.
					r.Close()
				}
			}
			if failed {
				fmt.Fprintln(os.Stderr, "Nginx diagnostic delivery failed")
				return 111
			}
			if err == nil {
				return 0
			}
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
					return 128 + int(status.Signal())
				}
				return exit.ExitCode()
			}
			return 111
		}
	}
}

func main() { os.Exit(run(os.Args[1:])) }
