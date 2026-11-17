//go:build !windows

package ui

func onTrayMenuOpening(func()) func() { return nil }
