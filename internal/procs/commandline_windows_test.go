package procs

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

func putCommandLine(buf []byte, text string) {
	hdr := (*commandLineString)(unsafe.Pointer(&buf[0]))
	words := utf16.Encode([]rune(text))
	offset := int(unsafe.Sizeof(*hdr))
	hdr.Length, hdr.MaximumLength = uint16(2*len(words)), uint16(2*len(words))
	hdr.Buffer = uintptr(unsafe.Pointer(&buf[offset]))
	for i, w := range words {
		binary.LittleEndian.PutUint16(buf[offset+2*i:], w)
	}
}

func TestReadProcessCommandLine(t *testing.T) {
	want := `"C:\工具\node.exe" "C:\User Name\@anthropic-ai\claude-code\cli.js" --prompt "Тест ❄ ` + strings.Repeat("длинный аргумент ", 512) + `"`
	header := uint32(unsafe.Sizeof(commandLineString{}))
	size := header + uint32(2*len(utf16.Encode([]rune(want))))
	calls := 0
	query := func(_ windows.Handle, class int32, p unsafe.Pointer, n uint32, returned *uint32) error {
		calls++
		if class != windows.ProcessCommandLineInformation {
			t.Fatal("wrong information class")
		}
		*returned = size
		if p == nil {
			*returned = header // simulate growth before the next read
			return windows.STATUS_INFO_LENGTH_MISMATCH
		}
		if n < size {
			return windows.STATUS_BUFFER_TOO_SMALL
		}
		putCommandLine(unsafe.Slice((*byte)(p), n), want)
		return nil
	}
	got, err := readProcessCommandLine(0, query)
	if err != nil || got != want || calls != 3 {
		t.Fatalf("query: result equal=%v, calls=%d, err=%v", got == want, calls, err)
	}
}

func TestCommandLineQueryFailuresAreBounded(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query commandLineQuery
	}{
		{"denied", func(_ windows.Handle, _ int32, _ unsafe.Pointer, _ uint32, _ *uint32) error {
			return windows.STATUS_ACCESS_DENIED
		}},
		{"oversized", func(_ windows.Handle, _ int32, _ unsafe.Pointer, _ uint32, n *uint32) error {
			*n = maxCommandLineBuffer + 1
			return windows.STATUS_INFO_LENGTH_MISMATCH
		}},
		{"empty header", func(_ windows.Handle, _ int32, _ unsafe.Pointer, _ uint32, n *uint32) error {
			*n = 0
			return windows.STATUS_INFO_LENGTH_MISMATCH
		}},
		{"no progress", func(_ windows.Handle, _ int32, _ unsafe.Pointer, _ uint32, n *uint32) error {
			*n = 32
			return windows.STATUS_INFO_LENGTH_MISMATCH
		}},
		{"changing size", func(_ windows.Handle, _ int32, _ unsafe.Pointer, n uint32, ret *uint32) error {
			*ret = n + 32
			return windows.STATUS_INFO_LENGTH_MISMATCH
		}},
		{"truncated success", func(_ windows.Handle, _ int32, p unsafe.Pointer, _ uint32, ret *uint32) error {
			*ret = 32
			if p == nil {
				return windows.STATUS_INFO_LENGTH_MISMATCH
			}
			*ret = 1
			return nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			got, err := readProcessCommandLine(0, func(h windows.Handle, c int32, p unsafe.Pointer, n uint32, r *uint32) error {
				calls++
				return tc.query(h, c, p, n, r)
			})
			if got != "" || err == nil || calls > 4 {
				t.Fatalf("failed query: got=%q, err=%v, calls=%d", got, err, calls)
			}
		})
	}
}

func TestDecodeCommandLineRejectsInvalidPointers(t *testing.T) {
	for _, name := range []string{"short header", "odd length", "short maximum", "null pointer", "header pointer", "before buffer", "past buffer", "odd pointer", "truncated text"} {
		t.Run(name, func(t *testing.T) {
			buf := make([]byte, 128)
			putCommandLine(buf, "node script.js")
			hdr := (*commandLineString)(unsafe.Pointer(&buf[0]))
			base := uintptr(unsafe.Pointer(&buf[0]))
			switch name {
			case "short header":
				buf = buf[:1]
			case "odd length":
				hdr.Length--
			case "short maximum":
				hdr.MaximumLength = 0
			case "null pointer":
				hdr.Buffer = 0
			case "header pointer":
				hdr.Buffer = base
			case "before buffer":
				hdr.Buffer = base - 2
			case "past buffer":
				hdr.Buffer = base + uintptr(len(buf)) + 2
			case "odd pointer":
				hdr.Buffer++
			case "truncated text":
				buf = buf[:int(unsafe.Sizeof(*hdr))+2]
			}
			if got, err := decodeCommandLine(buf); err == nil || got != "" {
				t.Fatalf("accepted invalid result: %q %v", got, err)
			}
		})
	}
}

func TestWindowsInterpreterEntryScript(t *testing.T) {
	claude := `C:\User Name\npm\node_modules\@anthropic-ai\claude-code\cli.js`
	codex := `C:/新版/node_modules/@openai/codex/bin/codex.js`
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"node.exe", []string{claude, "--prompt", "anything"}, claude},
		{"NODE.EXE", []string{"--require", "preload.js", "--inspect=127.0.0.1", claude}, claude},
		{"node.exe", []string{"--import=preload.mjs", "--", codex}, codex},
		{"bun.exe", []string{claude}, claude},
		{"bun.exe", []string{"--bun", "run", claude}, claude},
		{"bun.exe", []string{"--watch", "run", claude}, claude},
		{"bun.exe", []string{"run", "--bun", "--cwd", `C:\User Name`, claude}, claude},
		{"node.exe", []string{"-e", claude}, ""},
		{"node.exe", []string{"--eval=" + claude}, ""},
		{"node.exe", []string{"--require", claude, "server.js"}, "server.js"},
		{"node.exe", []string{"server.js", "--prompt", claude}, "server.js"},
		{"node.exe", []string{"--unknown-option", claude}, ""},
		{"node.exe", []string{"--require"}, ""},
		{"node.exe", []string{"--"}, ""},
		{"bun.exe", []string{"-e", claude}, ""},
		{"bun.exe", []string{"add", "@anthropic-ai/claude-code"}, "add"},
		{"python.exe", []string{claude}, ""},
	} {
		t.Run(tc.name+"/"+strings.Join(tc.args, " "), func(t *testing.T) {
			line := windows.ComposeCommandLine(append([]string{`C:\Tools\` + tc.name}, tc.args...))
			if got := windowsInterpreterScript(tc.name, line); got != tc.want {
				t.Fatalf("entry script=%q, want=%q", got, tc.want)
			}
		})
	}
}

func TestWindowsCLIPresetsUseEntryScript(t *testing.T) {
	for _, id := range []string{"claude", "codex"} {
		preset, _ := PresetByID(id)
		entry := preset.Windows.Scripts[0]
		for _, runtime := range []string{"node.exe", "bun.exe"} {
			for _, tc := range []struct {
				script string
				want   bool
			}{
				{`C:\Old Version\node_modules\` + strings.ReplaceAll(entry, "/", `\`), true},
				{"C:/New Version/node_modules/" + strings.ToUpper(entry), true},
				{"/not-" + entry, false},
				{entry + ".bak", false},
				{"server.js", false},
				{"", false},
			} {
				p := Proc{Name: runtime, ScriptPath: tc.script, Args: "server.js --prompt " + entry}
				if got := preset.Windows.Match(p); got != tc.want {
					t.Fatalf("%s/%s script=%q: match=%v", id, runtime, tc.script, got)
				}
			}
		}
	}
}
