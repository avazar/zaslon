package ui

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/app"
	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/guard"
)

func TestDiagnosticEventsReachHistoryAndPersistentLog(t *testing.T) {
	t.Setenv("ZASLON_DIR", t.TempDir())
	oldLang := Lang
	t.Cleanup(func() { Lang = oldLang })
	for _, lang := range []string{"ru", "en"} {
		Lang = lang
		e := guard.Event{At: time.Now(), Kind: guard.EvDomainCheck, Apps: []string{"fixture"}, Details: []string{"https://service.example/cdn-cgi/trace IPv4: HTTP 403\r\nforged log"}}
		HeadlessRender(guard.Snapshot{Config: config.Default()}, []guard.Event{e})
		line := EventLine(e)
		if !strings.Contains(line, "service.example") || !strings.Contains(line, "HTTP 403  forged log") || strings.ContainsAny(line, "\r\n") {
			t.Fatal(line)
		}
		if _, _, ok := Notification(e); ok {
			t.Fatal("diagnostics generated an extra notification")
		}
		if eventKind(e.Kind) != "warn" {
			t.Fatal("failure history is not marked as warning")
		}
	}
	data, err := os.ReadFile(app.LogPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "HTTP 403") != 2 || strings.Count(string(data), "\n") != 2 {
		t.Fatalf("incorrect persisted log: %s", data)
	}
	e := guard.Event{At: time.Now(), Kind: guard.EvNetChanged, Details: []string{"source=NotifyRouteChange2 kind=add family=IPv6 interface=17 prefix=::/1"}}
	if !strings.Contains(EventLine(e), "source=NotifyRouteChange2") {
		t.Fatal("event history omitted network source")
	}
	if len([]rune(guard.DiagnosticText(strings.Repeat("я", 2000)))) > 1025 {
		t.Fatal("unbounded diagnostic message")
	}
}
