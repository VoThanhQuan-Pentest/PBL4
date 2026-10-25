package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const preventionLogMaxBytes = 64 * 1024 * 1024
const preventionLogRetention = 7 * 24 * time.Hour

type rotatingWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	file     *os.File
	size     int64
	now      func() time.Time
}

func newRotatingWriter(path string, maxBytes int64) (*rotatingWriter, error) {
	if maxBytes < 1 || filepath.Base(path) != "prevention-events.ndjson" {
		return nil, fmt.Errorf("invalid prevention event log path or rotation size")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	return &rotatingWriter{path: path, maxBytes: maxBytes, file: file,
		size: info.Size(), now: time.Now}, nil
}

func (writer *rotatingWriter) Write(line []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if int64(len(line)) > writer.maxBytes {
		return 0, fmt.Errorf("prevention event exceeds rotation limit")
	}
	if writer.size+int64(len(line)) > writer.maxBytes {
		if err := writer.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := writer.file.Write(line)
	writer.size += int64(n)
	return n, err
}

func (writer *rotatingWriter) rotate() error {
	if err := writer.file.Close(); err != nil {
		return err
	}
	rotated := writer.path + "." + writer.now().UTC().Format("20060102T150405.000000000Z")
	if err := os.Rename(writer.path, rotated); err != nil {
		return err
	}
	file, err := os.OpenFile(writer.path, os.O_CREATE|os.O_EXCL|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		_ = os.Rename(rotated, writer.path)
		return err
	}
	writer.file = file
	writer.size = 0
	return writer.prune()
}

func (writer *rotatingWriter) prune() error {
	files, err := filepath.Glob(writer.path + ".*")
	if err != nil {
		return err
	}
	sort.Strings(files)
	cutoff := writer.now().Add(-preventionLogRetention)
	for _, filename := range files {
		if !strings.HasPrefix(filepath.Base(filename), "prevention-events.ndjson.") {
			continue
		}
		info, err := os.Stat(filename)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filename); err != nil {
				return err
			}
		}
	}
	return nil
}

func (writer *rotatingWriter) Close() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.file.Close()
}
