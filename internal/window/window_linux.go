package window

import (
	"context"
	"errors"
)

// Open has no window of its own on Linux; the caller falls back to the browser.
func Open(_ context.Context, _ <-chan struct{}, _, _, _, _ string, _ []byte) error {
	return errors.New("no native window on Linux")
}
