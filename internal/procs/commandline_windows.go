package procs

import (
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Querying ProcessCommandLineInformation avoids reading another process's PEB
// or depending on its pointer width. Only limited query access is requested.
// https://github.com/golang/sys/blob/master/windows/types_windows.go
const maxCommandLineBuffer = 128 * 1024

type commandLineQuery func(windows.Handle, int32, unsafe.Pointer, uint32, *uint32) error

// Buffer is an address in our returned buffer, never a remote pointer to follow.
type commandLineString struct {
	Length, MaximumLength uint16
	Buffer                uintptr
}

func queryProcessCommandLine(h windows.Handle) (string, error) {
	return readProcessCommandLine(h, windows.NtQueryInformationProcess)
}

func readProcessCommandLine(h windows.Handle, query commandLineQuery) (string, error) {
	var size uint32
	err := query(h, windows.ProcessCommandLineInformation, nil, 0, &size)
	for attempts := 0; attempts < 3; attempts++ {
		if err != nil && !commandLineSizeError(err) {
			return "", err
		}
		if size < uint32(unsafe.Sizeof(commandLineString{})) || size > maxCommandLineBuffer {
			return "", errors.New("invalid command line buffer size")
		}
		buf := make([]byte, size)
		var returned uint32
		err = query(h, windows.ProcessCommandLineInformation, unsafe.Pointer(&buf[0]), size, &returned)
		if commandLineSizeError(err) {
			if returned <= size {
				return "", errors.New("command line size query made no progress")
			}
			size = returned
			continue
		}
		if err != nil {
			return "", err
		}
		if returned > size {
			return "", errors.New("invalid command line result size")
		}
		return decodeCommandLine(buf[:returned])
	}
	return "", errors.New("command line changed during query")
}

func commandLineSizeError(err error) bool {
	return errors.Is(err, windows.STATUS_INFO_LENGTH_MISMATCH) ||
		errors.Is(err, windows.STATUS_BUFFER_TOO_SMALL) || errors.Is(err, windows.STATUS_BUFFER_OVERFLOW)
}

func decodeCommandLine(buf []byte) (string, error) {
	headerSize := uintptr(unsafe.Sizeof(commandLineString{}))
	if uintptr(len(buf)) < headerSize {
		return "", errors.New("truncated command line header")
	}
	hdr := *(*commandLineString)(unsafe.Pointer(&buf[0]))
	if hdr.Length%2 != 0 || hdr.MaximumLength%2 != 0 || hdr.Length > hdr.MaximumLength {
		return "", errors.New("invalid command line string length")
	}
	if hdr.Length == 0 {
		return "", nil
	}
	base := uintptr(unsafe.Pointer(&buf[0]))
	if hdr.Buffer < base || hdr.Buffer-base < headerSize || (hdr.Buffer-base)%2 != 0 {
		return "", errors.New("invalid command line string address")
	}
	offset := hdr.Buffer - base
	if offset > uintptr(len(buf)) || uintptr(hdr.Length) > uintptr(len(buf))-offset {
		return "", errors.New("command line string exceeds buffer")
	}
	raw := buf[offset : offset+uintptr(hdr.Length)]
	words := make([]uint16, len(raw)/2)
	for i := range words {
		words[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	return string(utf16.Decode(words)), nil
}

// Built-in CLI presets use the entry script, not a package name occurring in a
// prompt, eval string, preload module or arguments to an unrelated program.
// Unknown option forms are left unmatched; custom args: rules remain available.
func windowsInterpreterScript(name, commandLine string) string {
	name = trimExe(name)
	if name != "node" && name != "bun" {
		return ""
	}
	argv, err := windows.DecomposeCommandLine(commandLine)
	if err != nil || len(argv) < 2 {
		return ""
	}
	args := argv[1:]
	for len(args) > 0 {
		arg := args[0]
		args = args[1:]
		if arg == "--" {
			if len(args) > 0 {
				return args[0]
			}
			return ""
		}
		if name == "bun" && arg == "run" {
			name = "bun-run" // only one optional run subcommand
			continue
		}
		if !strings.HasPrefix(arg, "-") {
			return arg
		}
		option, _, assigned := strings.Cut(arg, "=")
		if takesInterpreterValue(name, option) {
			if !assigned {
				if len(args) == 0 {
					return ""
				}
				args = args[1:]
			}
			continue
		}
		if interpreterSwitch(name, option) {
			continue
		}
		return ""
	}
	return ""
}

func takesInterpreterValue(name, option string) bool {
	switch option {
	case "-r", "--require", "--import", "--conditions", "--env-file":
		return true
	}
	if name == "node" {
		switch option {
		case "--loader", "--experimental-loader", "--inspect-port", "--title", "--env-file-if-exists":
			return true
		}
	} else {
		switch option {
		case "--cwd", "--preload", "--config", "--tsconfig-override":
			return true
		}
	}
	return false
}

func interpreterSwitch(name, option string) bool {
	if name == "node" {
		switch option {
		case "--inspect", "--inspect-brk", "--no-warnings", "--trace-warnings", "--enable-source-maps", "--preserve-symlinks", "--preserve-symlinks-main":
			return true
		}
	} else {
		switch option {
		case "--bun", "--silent", "--smol", "--hot", "--watch", "--no-clear-screen", "--no-install":
			return true
		}
	}
	return false
}
