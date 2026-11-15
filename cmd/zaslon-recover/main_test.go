package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gofrs/flock"
)

func TestActiveGuardLockPreventsRecovery(t *testing.T) {
	dir := t.TempDir()
	lock := flock.New(filepath.Join(dir, "zaslon.lock"))
	if err := lock.Lock(); err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if recoverProcesses(dir, true, false) == nil {
		t.Fatal("ignored active guard lock")
	}
}

func TestInspectionDoesNotReadConfigOrCreateJournal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("bad: ["), 0600); err != nil {
		t.Fatal(err)
	}
	if err := recoverProcesses(dir, false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "process-recovery.json")); !os.IsNotExist(err) {
		t.Fatalf("inspection wrote journal: %v", err)
	}
}
