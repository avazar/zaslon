// Package window shows the Zaslon panel in its own window.
//
// The panel is a page served by the running Zaslon on 127.0.0.1; this package
// only puts it in a window. It runs as a separate process (`zaslon panel`)
// because on macOS both the menu bar icon and a web view want the main thread.
// Open follows the server session's context and activation requests. On Windows
// its private browser job also closes the window if the panel helper crashes.
package window

const (
	Width  = 1000
	Height = 720
)
