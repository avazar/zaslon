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

func TestHistorySummaryAndFullLogUseTheSameMeasurement(t *testing.T) {
	oldLang := Lang
	t.Cleanup(func() { Lang = oldLang })
	Lang = "ru"
	const endpoint = "https://service.example/cdn-cgi/trace"
	e := guard.Event{Kind: guard.EvDomainCheck, Apps: []string{"Claude", "Codex"}, CheckID: 42,
		Problems: []guard.CheckProblem{{Endpoint: endpoint, Family: "IPv6", Code: "timeout", Info: "context deadline exceeded"}}}
	short, full := eventMessage(e, false), logMessage(e)
	if !strings.Contains(short, "Claude, Codex") || !strings.Contains(short, "service.example IPv6") || !strings.Contains(short, "тайм-аут") || strings.Contains(short, "/trace") || strings.Contains(short, "deadline") {
		t.Fatal(short)
	}
	if strings.Count(full, endpoint) != 1 || !strings.Contains(full, "check=42") || !strings.Contains(strings.Join(eventDetails(e), " "), "context deadline exceeded") {
		t.Fatal(full, eventDetails(e))
	}
	e.Kind, e.Reason = guard.EvFrozen, guard.DomainIPNotAllowed
	if !strings.Contains(eventMessage(e, false), reasonText(guard.DomainIPNotAllowed)) {
		t.Fatal("a later timeout obscured a known denial")
	}
	e = guard.Event{Kind: guard.EvResumed, Apps: []string{"Codex"}, ReleaseCause: "protection paused", PauseMin: time.Minute, PauseMax: time.Minute}
	short = eventMessage(e, false)
	if !strings.Contains(short, "1 мин") || strings.Contains(short, T("hist.verified")) {
		t.Fatal(short)
	}
}

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
