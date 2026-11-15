package netwatch

import (
	"strings"
	"sync"
	"testing"
)

func TestNotificationDetailsStayWithinObservedRevisions(t *testing.T) {
	e := &Events{}
	e.record(func() Change { return Change{Source: "route", Kind: "add"} })
	observed := e.Version()
	e.record(func() Change { return Change{Source: "address", Kind: "delete"} })
	details := e.Details(0, observed)
	if len(details) != 1 || !strings.Contains(details[0], "source=route") {
		t.Fatalf("wrong observed batch: %v", details)
	}
	if next := e.Details(observed, e.Version()); len(next) != 1 || !strings.Contains(next[0], "source=address") {
		t.Fatalf("newer record was consumed: %v", next)
	}
	for range changeHistory + 10 {
		e.record(func() Change { return Change{Source: "burst", Kind: "parameter"} })
	}
	details = e.Details(0, e.Version())
	if len(details) != changeHistory+1 || !strings.Contains(details[0], "details unavailable") {
		t.Fatalf("burst gap is not explicit: %v", details)
	}
	if old := e.Details(0, observed); len(old) != 1 || !strings.Contains(old[0], "#1..#1") {
		t.Fatalf("entirely expired range: %v", old)
	}
}

func TestConcurrentNotificationsRetainMonotonicRevisions(t *testing.T) {
	e := &Events{}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				e.record(func() Change { return Change{Source: "test", Kind: "add"} })
				_ = e.Details(e.Version(), e.Version())
			}
		})
	}
	wg.Wait()
	if e.Version() != 800 {
		t.Fatalf("lost notification revisions: %d", e.Version())
	}
	if n := len(e.Details(736, 800)); n != 64 {
		t.Fatalf("retained %d records", n)
	}
}

func TestRevisionDoesNotWaitForDiagnosticFormatting(t *testing.T) {
	wake := make(chan struct{}, 1)
	e := &Events{C: wake, wake: wake}
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		e.record(func() Change { close(started); <-release; return Change{Source: "slow-old", Kind: "add"} })
		close(done)
	}()
	<-started
	select {
	case <-e.C:
	default:
		t.Error("diagnostics delayed wake-up of the guard")
	}
	if e.Version() != 1 {
		t.Error("formatting delayed network invalidation")
	}
	if details := e.Details(0, 1); len(details) != 1 || !strings.Contains(details[0], "pending") {
		t.Errorf("pending details were silently lost: %v", details)
	}
	for range changeHistory {
		e.record(func() Change { return Change{Source: "new", Kind: "add"} })
	}
	close(release)
	<-done
	if details := e.Details(changeHistory, changeHistory+1); len(details) != 1 || !strings.Contains(details[0], "source=new") {
		t.Fatalf("slow old callback overwrote a newer diagnostic: %v", details)
	}
}
