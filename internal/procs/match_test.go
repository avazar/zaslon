package procs

import (
	"fmt"
	"slices"
	"testing"

	"github.com/avazar/zaslon/internal/config"
)

func TestFilterRejectsReusedParentPID(t *testing.T) {
	targets := []Target{
		{ID: "chatgpt", Name: "ChatGPT", Rule: ParseMatch([]string{"ChatGPT"})},
		{ID: "codex", Name: "Codex", Rule: ParseMatch([]string{"codex"})},
	}
	all := []Proc{
		{PID: 10, Created: "100", Name: "ChatGPT.exe"},
		{PID: 20, PPID: 10, Created: "90", Name: "Taskmgr.exe"},
		{PID: 21, PPID: 20, Created: "110", Name: "worker.exe"},
		{PID: 30, PPID: 10, Created: "101", Name: "worker.exe"},
		{PID: 31, PPID: 30, Created: "102", Name: "helper.exe"},
		{PID: 40, PPID: 10, Created: "80", Name: "codex.exe"},
		{PID: 50, PPID: 10, Created: "100", Name: "worker.exe"},
		{PID: 60, PPID: 10, Name: "worker.exe"},
	}
	got := Filter(all, targets, 999)
	var pids []int
	for _, p := range got {
		pids = append(pids, p.PID)
		if p.PID == 40 && !slices.Equal(p.PolicyIDs, []string{"codex"}) {
			t.Fatalf("directly matched process inherited a false policy: %+v", p)
		}
	}
	if !slices.Equal(pids, []int{10, 30, 31, 40, 50, 60}) {
		t.Fatalf("selected PIDs %v", pids)
	}
	if !predatesParent("boot:90", "boot:100") || predatesParent("old:90", "new:100") || predatesParent("unknown", "100") {
		t.Fatal("incomparable identities must preserve strict inheritance")
	}
}

func TestAntigravityPresets(t *testing.T) {
	app, _ := PresetByID("antigravity")
	ide, _ := PresetByID("antigravity-ide")
	for _, tc := range []struct {
		os       string
		app, ide Rule
		roots    []Proc
	}{
		{"windows", app.Windows, ide.Windows, []Proc{{Name: "Antigravity.exe"}, {Name: "Antigravity IDE.exe"}}},
		{"linux", app.Linux, ide.Linux, []Proc{{Name: "antigravity"}, {Name: "antigravity-ide"}}},
		{"darwin", app.Darwin, ide.Darwin, []Proc{{Path: "/Applications/Antigravity.app/Contents/MacOS/Antigravity"}, {Path: "/Applications/Antigravity IDE.app/Contents/MacOS/Electron"}}},
	} {
		t.Run(tc.os, func(t *testing.T) {
			tc.roots[0].PID, tc.roots[1].PID = 10, 20
			ps := append(tc.roots, Proc{PID: 11, PPID: 10, Name: "language_server.exe"}, Proc{PID: 21, PPID: 20, Name: "language_server.exe"},
				Proc{PID: 30, Name: "language_server.exe"}, Proc{PID: 31, Name: "Uninstall Antigravity.exe"})
			targets := []Target{{app.ID, app.Name, tc.app}, {ide.ID, ide.Name, tc.ide}}
			got := Filter(ps, targets, 999)
			if len(got) != 4 {
				t.Fatalf("unexpected processes: %+v", got)
			}
			for i, pid := range []int{10, 11, 20, 21} {
				if got[i].PID != pid || !slices.Equal(got[i].PolicyIDs, []string{targets[i/2].ID}) {
					t.Errorf("unexpected ownership: %+v", got[i])
				}
			}
		})
	}
}

func TestRuleMatch(t *testing.T) {
	mac, _ := PresetByID("claude")
	cases := []struct {
		rule Rule
		p    Proc
		want bool
	}{
		{mac.Darwin, Proc{Name: "Claude", Path: "/Applications/Claude.app/Contents/MacOS/Claude"}, true},
		{mac.Darwin, Proc{Name: "Claude Helper (Renderer)", Path: "/Applications/Claude.app/Contents/Frameworks/Claude Helper (Renderer).app/Contents/MacOS/Claude Helper (Renderer)"}, true},
		{mac.Darwin, Proc{Name: "claude", Path: "/Users/u/.local/share/claude/versions/2.1.3"}, true},
		{mac.Darwin, Proc{Name: "node", Path: "/opt/homebrew/bin/node", Args: "node /opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js"}, true},
		{mac.Darwin, Proc{Name: "node", Path: "/opt/homebrew/bin/node", Args: "node server.js"}, false},
		{mac.Darwin, Proc{Name: "Safari", Path: "/Applications/Safari.app/Contents/MacOS/Safari"}, false},
		{mac.Windows, Proc{Name: "claude.exe", Path: `C:\Users\u\AppData\Local\AnthropicClaude\app-1.0\claude.exe`}, true},
		{mac.Windows, Proc{Name: "Claude.exe"}, true},
		{mac.Windows, Proc{Name: "claudette.exe"}, false},
		{ParseMatch([]string{"/MyApp.app/", "myapp.exe", "args:my-cli.js"}), Proc{Name: "MyApp.exe"}, true},
		{ParseMatch([]string{"/MyApp.app/"}), Proc{Name: "x", Path: "/Applications/MyApp.app/Contents/MacOS/x"}, true},
		{ParseMatch([]string{"args:my-cli.js"}), Proc{Name: "node", Args: "node /x/my-cli.js --flag"}, true},
		{ParseMatch([]string{`\Tools\`}), Proc{Name: "a.exe", Path: `C:\Tools\a.exe`}, true},
	}
	for i, c := range cases {
		if got := c.rule.Match(c.p); got != c.want {
			t.Errorf("case %d: Match(%+v) = %v", i, c.p, got)
		}
	}
}

func TestFilter(t *testing.T) {
	cfg := config.Default()
	cfg.Apps = []string{"claude", "nonexistent"}
	cfg.CustomApps = []config.CustomApp{{Name: "Tool", Match: []string{"tool"}}}
	all := []Proc{
		{PID: 10, Name: "Claude", Path: "/Applications/Claude.app/Contents/MacOS/Claude"},
		{PID: 11, Name: "tool"},
		{PID: 12, Name: "Safari"},
		{PID: 13, Name: "claude"}, // our own pid below
		{PID: 1, Name: "claude"},  // launchd/init is never touched
	}
	got := Filter(all, Targets(cfg), 13)
	if len(got) != 2 || got[0].PID != 10 || got[1].PID != 11 || got[1].App != "Tool" {
		t.Fatalf("Filter = %+v", got)
	}
	if names := AppNames(got); len(names) != 2 || names[0] != "Claude" {
		t.Fatalf("AppNames = %v", names)
	}
}

func TestPresetsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Presets {
		if seen[p.ID] {
			t.Errorf("duplicate preset %s", p.ID)
		}
		seen[p.ID] = true
		for _, r := range []Rule{p.Darwin, p.Windows, p.Linux} {
			if len(r.Names)+len(r.Paths)+len(r.Args) == 0 {
				t.Errorf("preset %s has an empty rule", p.ID)
			}
		}
	}
}

func TestFilterIncludesChildren(t *testing.T) {
	cfg := config.Default()
	cfg.Apps = []string{"claude"}
	all := []Proc{
		{PID: 10, PPID: 1, Name: "Claude", Path: "/Applications/Claude.app/Contents/MacOS/Claude"},
		{PID: 20, PPID: 10, Name: "claude"},
		{PID: 30, PPID: 20, Name: "node", Args: "node mcp-server.js"},
		{PID: 31, PPID: 30, Name: "curl"},
		{PID: 40, PPID: 1, Name: "curl"},   // unrelated curl
		{PID: 50, PPID: 50, Name: "weird"}, // self-parented, must not loop
	}
	got := Filter(all, Targets(cfg), 999)
	var pids []int
	for _, p := range got {
		pids = append(pids, p.PID)
		if p.App != "Claude" {
			t.Errorf("pid %d labelled %q", p.PID, p.App)
		}
	}
	if fmt.Sprint(pids) != "[10 20 30 31]" {
		t.Fatalf("pids = %v", pids)
	}
}
