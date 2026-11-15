package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/guard"
)

func TestProcessErrorOverridesHealthyAndPausedPresentation(t *testing.T) {
	for _, paused := range []bool{false, true} {
		s := guard.Snapshot{Status: guard.OK, AllowedNow: true, Errors: []string{"resume denied"}}
		if paused {
			s.PausedUntil = time.Now().Add(time.Hour)
		}
		if ToneOf(s) != Red || panelStatus(s) != "error" || statusName(s) != "error" || s.Allowed() || !strings.Contains(StatusLine(s), "resume denied") {
			t.Fatal("process failure presented as healthy or simply paused")
		}
	}
}
