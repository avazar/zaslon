package recovery

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAtomicReplacementWaitsForBriefReader(t *testing.T) {
	dir := t.TempDir()
	to, from := filepath.Join(dir, "journal.json"), filepath.Join(dir, "new.json")
	if err := os.WriteFile(to, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(from, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(to)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { time.Sleep(50 * time.Millisecond); reader.Close(); close(closed) }()
	t.Cleanup(func() { <-closed })
	if err := replaceFile(from, to); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(to)
	if err != nil || string(data) != "new" {
		t.Fatalf("replacement: %q, %v", data, err)
	}
}

func TestAtomicReplacementDoesNotWaitForeverOrLoseOldJournal(t *testing.T) {
	dir := t.TempDir()
	to, from := filepath.Join(dir, "journal.json"), filepath.Join(dir, "new.json")
	if err := os.WriteFile(to, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(from, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(to)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	start := time.Now()
	if err := replaceFile(from, to); err == nil {
		t.Fatal("replaced a file still locked against deletion")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("replacement wait was not bounded")
	}
	data, err := os.ReadFile(to)
	if err != nil || string(data) != "old" {
		t.Fatalf("old journal lost: %q, %v", data, err)
	}
	if _, err := os.Stat(from); err != nil {
		t.Fatal("replacement source lost on failure")
	}
}
