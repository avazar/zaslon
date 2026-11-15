package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// The .exe is built as a GUI program (no console window flashing at login), so
// when it's run from a terminal with a command, it borrows that terminal for output.
func attachConsole() {
	if len(os.Args) < 2 {
		return
	}
	redirected := func(file *os.File) bool {
		kind, err := windows.GetFileType(windows.Handle(file.Fd()))
		return err == nil && (kind == windows.FILE_TYPE_PIPE || kind == windows.FILE_TYPE_DISK)
	}
	keepOut, keepErr := redirected(os.Stdout), redirected(os.Stderr)
	if keepOut && keepErr {
		return
	}
	k := windows.NewLazySystemDLL("kernel32.dll")
	const attachParent = ^uintptr(0) // ATTACH_PARENT_PROCESS
	if r, _, _ := k.NewProc("AttachConsole").Call(attachParent); r == 0 {
		return
	}
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		if !keepOut {
			os.Stdout = f
		}
		if !keepErr {
			os.Stderr = f
		}
	}
}

func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	return windows.GetExitCodeProcess(h, &code) == nil && code == 259 // STILL_ACTIVE
}

// stopProcess: there is no SIGTERM on Windows, and a forced kill would leave
// apps frozen, so the user restarts Zaslon from the menu.
func stopProcess(int) bool { return false }
