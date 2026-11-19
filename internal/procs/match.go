// Package procs finds the protected apps' processes and freezes, resumes and closes them.
package procs

import (
	"errors"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/avazar/zaslon/internal/config"
)

// ErrNotApplied means failure occurred before the OS operation took effect.
var ErrNotApplied = errors.New("process operation was not applied")

// ErrAlreadyStopped prevents adopting another tool's existing Unix stop.
var ErrAlreadyStopped = errors.New("process is already stopped by another owner")

// Proc is one running process.
type Proc struct {
	PID        int
	Created    string // OS process birth identity; never infer ownership from PID alone
	PPID       int
	Name       string   // executable file name: "Claude", "claude.exe"
	Path       string   // full executable path, may be empty if the OS hides it
	Args       string   // command line, only collected for interpreters (node, python...)
	ScriptPath string   // identified interpreter entry script (Windows), not arbitrary arguments
	App        string   // which protected app it belongs to (display name)
	AppID      string   // its preset id or lowercased custom name
	PolicyIDs  []string // matching app and ancestor policies; one owner controls suspension
	Control    bool     `json:"-"` // verified own control process/private panel member, never a user app
	control    controlRole
}

// SameProcess also works for synthetic processes used by pure guard tests.
func SameProcess(a, b Proc) bool { return a.PID == b.PID && a.Created == b.Created }

// A parent PID can outlive the process it identified, particularly on Windows.
// Reject only impossible ancestry. Equal or unavailable creation times cannot
// disprove a relationship, so strict descendant protection still applies.
func predatesParent(child, parent string) bool {
	if child == "" || parent == "" {
		return false
	}
	// Linux birth identities include the boot ID before the start tick.
	if boot, ticks, ok := strings.Cut(child, ":"); ok {
		parentTicks, sameBoot := strings.CutPrefix(parent, boot+":")
		if !sameBoot {
			return false
		}
		child, parent = ticks, parentTicks
	}
	c, childErr := strconv.ParseInt(child, 10, 64)
	p, parentErr := strconv.ParseInt(parent, 10, 64)
	return childErr == nil && parentErr == nil && c > 0 && c < p
}

// Rule matches processes of one app. See config template for the syntax.
type Rule struct {
	Names   []string // exact executable name, case-insensitive, ".exe" optional
	Paths   []string // substring of the executable path
	Args    []string // substring of the command line
	Scripts []string // interpreter entry script suffix, separated on path-component boundaries
}

type Preset struct {
	ID, Name string
	Darwin   Rule
	Windows  Rule
	Linux    Rule
}

func (p Preset) Rule() Rule {
	switch runtime.GOOS {
	case "darwin":
		return p.Darwin
	case "windows":
		return p.Windows
	default:
		return p.Linux
	}
}

// Presets are the apps people most often keep behind a VPN.
var Presets = []Preset{
	{ID: "claude", Name: "Claude",
		Darwin:  Rule{Paths: []string{"/Claude.app/"}, Names: []string{"claude"}, Args: []string{"@anthropic-ai/claude-code"}},
		Windows: Rule{Names: []string{"claude"}, Paths: []string{`\AnthropicClaude\`}, Scripts: []string{"@anthropic-ai/claude-code/cli.js"}},
		Linux:   Rule{Names: []string{"claude"}, Args: []string{"@anthropic-ai/claude-code"}}},
	{ID: "chatgpt", Name: "ChatGPT",
		Darwin:  Rule{Paths: []string{"/ChatGPT.app/"}},
		Windows: Rule{Names: []string{"ChatGPT"}},
		Linux:   Rule{Names: []string{"chatgpt"}}},
	{ID: "codex", Name: "Codex",
		Darwin:  Rule{Paths: []string{"/Codex.app/"}, Names: []string{"codex"}, Args: []string{"@openai/codex"}},
		Windows: Rule{Names: []string{"codex"}, Scripts: []string{"@openai/codex/bin/codex.js"}},
		Linux:   Rule{Names: []string{"codex"}, Args: []string{"@openai/codex"}}},
	{ID: "cursor", Name: "Cursor",
		Darwin:  Rule{Paths: []string{"/Cursor.app/"}},
		Windows: Rule{Names: []string{"Cursor"}},
		Linux:   Rule{Names: []string{"cursor"}}},
	{ID: "windsurf", Name: "Windsurf",
		Darwin:  Rule{Paths: []string{"/Windsurf.app/"}},
		Windows: Rule{Names: []string{"Windsurf"}},
		Linux:   Rule{Names: []string{"windsurf"}}},
	{ID: "copilot", Name: "GitHub Copilot",
		Darwin:  Rule{Names: []string{"copilot"}, Args: []string{"@github/copilot"}},
		Windows: Rule{Names: []string{"copilot"}},
		Linux:   Rule{Names: []string{"copilot"}, Args: []string{"@github/copilot"}}},
	{ID: "gemini", Name: "Gemini CLI",
		Darwin:  Rule{Names: []string{"gemini"}, Args: []string{"@google/gemini-cli"}},
		Windows: Rule{Names: []string{"gemini"}},
		Linux:   Rule{Names: []string{"gemini"}, Args: []string{"@google/gemini-cli"}}},
	{ID: "perplexity", Name: "Perplexity",
		Darwin:  Rule{Paths: []string{"/Perplexity.app/"}},
		Windows: Rule{Names: []string{"Perplexity"}},
		Linux:   Rule{Names: []string{"perplexity"}}},
	{ID: "telegram", Name: "Telegram",
		Darwin:  Rule{Paths: []string{"/Telegram.app/", "/Telegram Desktop.app/"}},
		Windows: Rule{Names: []string{"Telegram"}},
		Linux:   Rule{Names: []string{"telegram-desktop", "Telegram"}}},
	{ID: "discord", Name: "Discord",
		Darwin:  Rule{Paths: []string{"/Discord.app/"}},
		Windows: Rule{Names: []string{"Discord"}},
		Linux:   Rule{Names: []string{"Discord", "discord"}}},
	{ID: "slack", Name: "Slack",
		Darwin:  Rule{Paths: []string{"/Slack.app/"}},
		Windows: Rule{Names: []string{"slack"}},
		Linux:   Rule{Names: []string{"slack"}}},
	{ID: "zoom", Name: "Zoom",
		Darwin:  Rule{Paths: []string{"/zoom.us.app/"}},
		Windows: Rule{Names: []string{"Zoom"}},
		Linux:   Rule{Names: []string{"zoom"}}},
}

func PresetByID(id string) (Preset, bool) {
	for _, p := range Presets {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}

// ParseMatch turns the config syntax ("name", "/path/part/", "args:x") into a Rule.
func ParseMatch(items []string) Rule {
	var r Rule
	for _, s := range items {
		s = strings.TrimSpace(s)
		switch {
		case s == "":
		case strings.HasPrefix(s, "args:"):
			r.Args = append(r.Args, strings.TrimPrefix(s, "args:"))
		case strings.ContainsAny(s, `/\`):
			r.Paths = append(r.Paths, s)
		default:
			r.Names = append(r.Names, s)
		}
	}
	return r
}

// NeedsArgs reports whether a rule has a command-line-dependent alternative.
func (r Rule) NeedsArgs() bool { return len(r.Args)+len(r.Scripts) > 0 }

func trimExe(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".exe") }

func (r Rule) Match(p Proc) bool {
	name := trimExe(p.Name)
	for _, n := range r.Names {
		if name == trimExe(n) {
			return true
		}
	}
	path := strings.ToLower(p.Path)
	for _, s := range r.Paths {
		if path != "" && strings.Contains(path, strings.ToLower(s)) {
			return true
		}
	}
	args := strings.ToLower(p.Args)
	for _, s := range r.Args {
		if args != "" && strings.Contains(args, strings.ToLower(s)) {
			return true
		}
	}
	if isInterpreter(p.Name) && p.ScriptPath != "" {
		script := strings.ReplaceAll(strings.ToLower(p.ScriptPath), `\`, "/")
		for _, s := range r.Scripts {
			s = strings.ReplaceAll(strings.ToLower(s), `\`, "/")
			if script == s || strings.HasSuffix(script, "/"+s) {
				return true
			}
		}
	}
	return false
}

// Target is a named rule to look for.
type Target struct {
	ID   string // preset id, or a custom app's lowercased name (the key in app_rules)
	Name string
	Rule Rule
}

// Targets builds the list of apps to protect from the config.
func Targets(c *config.Config) []Target {
	var ts []Target
	for _, id := range c.Apps {
		if p, ok := PresetByID(id); ok {
			ts = append(ts, Target{ID: p.ID, Name: p.Name, Rule: p.Rule()})
		}
	}
	for _, a := range c.CustomApps {
		ts = append(ts, Target{ID: strings.ToLower(a.Name), Name: a.Name, Rule: ParseMatch(a.Match)})
	}
	return ts
}

// Filter keeps the processes that belong to one of the targets and labels them.
// Children count too, whatever their name: Claude Code runs MCP servers, curl,
// git and shells, and those reach the network just as well as the app itself.
func Filter(all []Proc, ts []Target, self int) []Proc {
	children := map[int][]int{}
	byPID := make(map[int]Proc, len(all))
	for _, p := range all {
		byPID[p.PID] = p
		if p.PPID != p.PID {
			children[p.PPID] = append(children[p.PPID], p.PID)
		}
	}
	app := map[int]Target{}
	policies := map[int]map[string]bool{}
	byID := map[string]Target{}
	for _, t := range ts {
		byID[t.ID] = t
	}
	var queue []int
	for _, p := range all {
		if p.PID <= 1 {
			continue
		}
		for _, t := range ts {
			if t.Rule.Match(p) {
				if _, seen := app[p.PID]; !seen {
					app[p.PID] = t
					queue = append(queue, p.PID)
					policies[p.PID] = map[string]bool{}
				}
				policies[p.PID][t.ID] = true
			}
		}
		// Guard supplies remembered labels only after validating PID and birth.
		// Seed these before walking children, so an orphan's new descendants
		// inherit every still-active ancestor policy too.
		for _, id := range append([]string{p.AppID}, p.PolicyIDs...) {
			if id == "" {
				continue
			}
			if t, active := byID[id]; active {
				if _, seen := app[p.PID]; !seen {
					app[p.PID] = t
					queue = append(queue, p.PID)
					policies[p.PID] = map[string]bool{}
				}
				policies[p.PID][id] = true
			}
		}
	}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		for _, c := range children[pid] {
			if c <= 1 || predatesParent(byPID[c].Created, byPID[pid].Created) {
				continue
			}
			if _, seen := app[c]; !seen {
				app[c] = app[pid]
				policies[c] = map[string]bool{}
			}
			changed := false
			for id := range policies[pid] {
				if !policies[c][id] {
					policies[c][id] = true
					changed = true
				}
			}
			if changed {
				queue = append(queue, c)
			}
		}
	}
	out := make([]Proc, 0, len(app))
	for pid, t := range app {
		p := byPID[pid]
		if pid == self || p.Control {
			continue
		}
		p.App, p.AppID = t.Name, t.ID
		p.PolicyIDs = nil
		for id := range policies[pid] {
			p.PolicyIDs = append(p.PolicyIDs, id)
		}
		sort.Strings(p.PolicyIDs)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

// AppNames lists distinct app names in processes, for messages like "Заморожено: Claude, Cursor".
func AppNames(ps []Proc) []string {
	seen := map[string]bool{}
	var names []string
	for _, p := range ps {
		if !seen[p.App] {
			seen[p.App] = true
			names = append(names, p.App)
		}
	}
	sort.Strings(names)
	return names
}

// isInterpreter: command lines are expensive to read, so only these get them.
func isInterpreter(name string) bool {
	switch trimExe(filepath.Base(name)) {
	case "node", "python", "python3", "bun", "deno":
		return true
	}
	return false
}

// Suspender is the only capability given to the guard. Termination belongs to
// explicit recovery, so the protection state machine cannot close/kill an app.
type Suspender interface {
	List() ([]Proc, error)
	Freeze(p Proc) error
	Resume(p Proc) error
}

// Controller includes explicit termination for the recovery tool.
type Controller interface {
	Suspender
	Close(p Proc) error // ask to quit (SIGTERM / WM_CLOSE); a frozen process is resumed first
	Kill(p Proc) error
}
