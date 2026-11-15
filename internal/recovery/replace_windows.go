package recovery

import (
	"errors"
	"time"

	"golang.org/x/sys/windows"
)

const replaceRetryWindow = 250 * time.Millisecond

func replaceFile(from, to string) error {
	f, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	t, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	// A brief reader/antivirus handle can prevent replacement even though the
	// process operation succeeded. Retry only this atomic file operation, never
	// the suspend/resume itself. Permanent locks still surface as recovery errors.
	deadline := time.Now().Add(replaceRetryWindow)
	for {
		err = windows.MoveFileEx(f, t, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
		if err == nil || (!errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_LOCK_VIOLATION)) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}
