package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeDiagnosticsNeverCopyFreeText(t *testing.T) {
	for _, sample := range []struct{ native, code string }{
		{`connect() failed (111: Connection refused) while connecting to upstream, request: "GET /api?token=SECRET HTTP/1.1", upstream: "http://app/api?token=SECRET", host: "SECRET", referrer: "https://x/?password=SECRET"`, "upstream_connect_failed"},
		{`upstream timed out while reading response header from upstream, request: "SECRET"`, "upstream_timeout"},
		{`open() "/SECRET" failed (2: No such file or directory)`, "file_open_failed"},
		{`upstream sent too big header while reading response header, upstream: "SECRET"`, "upstream_header_too_large"},
		{`client intended to send too large body: SECRET bytes`, "request_body_too_large"},
		{`limiting requests, excess: SECRET`, "request_rate_limited"},
		{`unknown diagnostic SECRET`, "unclassified_native_error"},
	} {
		t.Run(sample.code, func(t *testing.T) {
			d := classify([]byte("2026/10/29 00:00:00 [error] 12#12: *3 " + sample.native + "\n"))
			if d.Code != sample.code || d.Severity != "error" {
				t.Fatalf("unexpected classification: %+v", d)
			}
			b, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "SECRET") {
				t.Fatal("native data retained")
			}
		})
	}
}

func TestUntrustedAndOversizedLinesAreOpaque(t *testing.T) {
	input := "SECRET\n" + strings.Repeat("SECRET", maxLine) + "\n" +
		"2026/10/29 00:00:00 [warn] 12#12: limiting requests, SECRET\n" +
		"2026/10/29 00:00:00 [error] 12#12: connect() failed SECRET" // unterminated
	var got []diagnostic
	err := consume(strings.NewReader(input), func(d diagnostic) error { got = append(got, d); return nil })
	if err != nil || len(got) != 4 {
		t.Fatalf("got %d events, err=%v", len(got), err)
	}
	for i, code := range []string{"unclassified_native_error", "unclassified_native_error", "request_rate_limited", "unclassified_native_error"} {
		if got[i].Code != code {
			t.Fatalf("event%d: %+v", i, got[i])
		}
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "SECRET") {
		t.Fatal("untrusted data retained")
	}
}

func TestDiagnosticDeliveryFailureIsNotIgnored(t *testing.T) {
	want := errors.New("owned write failure")
	if got := consume(strings.NewReader("owned\n"), func(diagnostic) error { return want }); !errors.Is(got, want) {
		t.Fatal(got)
	}
}

func TestConfiguredLogLimitRejectsUnsafeValues(t *testing.T) {
	for _, value := range []string{"-1", "1", "4095", "16777217", "invalid", "9223372036854775808"} {
		if _, err := configuredLogLimit(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
	for value, want := range map[string]int64{"": 0, "0": 0, "4096": 4096, "1048576": 1048576} {
		if got, err := configuredLogLimit(value); err != nil || got != want {
			t.Fatalf("%q: got %d, %v", value, got, err)
		}
	}
}

func TestOptInRotationBoundsBothFilesAndKeepsCompleteRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "native.log")
	s := sink{path: path, maxBytes: 4096}
	if err := s.reopen(); err != nil {
		t.Fatal(err)
	}
	defer func() { s.file.Close() }()
	for i := 0; i < 200; i++ {
		if err := s.emit(classify(nil)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{path, path + ".1"} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) == 0 || len(data) > 4096 || data[len(data)-1] != '\n' {
			t.Fatal("unbounded or partial log")
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var record diagnostic
			if err := json.Unmarshal([]byte(line), &record); err != nil || record.Code != "unclassified_native_error" {
				t.Fatalf("invalid retained record: %s", line)
			}
		}
	}
}

func TestDefaultAppendAndExternalReopenRemainAvailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "native.log")
	s := sink{path: path}
	if err := s.reopen(); err != nil {
		t.Fatal(err)
	}
	defer func() { s.file.Close() }()
	for i := 0; i < 100; i++ {
		if err := s.emit(classify(nil)); err != nil {
			t.Fatal(err)
		}
	}
	if info, err := os.Stat(path); err != nil || info.Size() <= 4096 {
		t.Fatal("default append changed")
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatal("default rotated internally")
	}
	if err := os.Rename(path, path+".external"); err != nil {
		t.Fatal(err)
	}
	if err := s.reopen(); err != nil {
		t.Fatal(err)
	}
	if err := s.emit(classify(nil)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || strings.Count(string(data), "\n") != 1 {
		t.Fatal("external reopen failed")
	}
}

func TestSinkAndArchiveSymlinksDoNotModifyTheirTargets(t *testing.T) {
	dir := t.TempDir()
	target, path := filepath.Join(dir, "target"), filepath.Join(dir, "native.log")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	s := sink{path: path, maxBytes: 4096}
	if err := s.reopen(); err == nil {
		s.file.Close()
		t.Fatal("followed sink symlink")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := s.reopen(); err != nil {
		t.Fatal(err)
	}
	defer func() { s.file.Close() }()
	for i := 0; i < 100; i++ {
		if err := s.emit(classify(nil)); err != nil {
			t.Fatal(err)
		}
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "unchanged" {
		t.Fatal("modified symlink target")
	}
}
