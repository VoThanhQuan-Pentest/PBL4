package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRotatingWriterKeepsActiveAndRecentEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prevention-events.ndjson")
	writer, err := newRotatingWriter(path, 32)
	if err != nil {
		t.Fatal(err)
	}
	writer.now = func() time.Time { return time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC) }
	if _, err := writer.Write([]byte("first-event-123456789\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("second-event-123456789\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	active, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := filepath.Glob(path + ".*")
	if err != nil {
		t.Fatal(err)
	}
	if string(active) != "second-event-123456789\n" || len(rotated) != 1 {
		t.Fatalf("active=%q rotated=%v", active, rotated)
	}
}

func TestRotatingWriterPrunesOnlyExpiredMatchingFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prevention-events.ndjson")
	writer, err := newRotatingWriter(path, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	old := path + ".old"
	other := filepath.Join(dir, "unrelated.log")
	if err := os.WriteFile(old, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(old, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := writer.prune(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("expired log still exists: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("unrelated file was removed: %v", err)
	}
}
