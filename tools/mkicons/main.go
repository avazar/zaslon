// mkicons packages the approved artwork as PNG sizes, a macOS iconset and Windows ICO.
//
//	go run ./tools/mkicons build/icons
package main

import (
	"flag"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"

	"github.com/avazar/zaslon/internal/ui"
)

func main() {
	panelFavicon := flag.Bool("panel-favicon", false, "update the embedded panel favicon (artwork regeneration only)")
	flag.Parse()
	out := "build/icons"
	if flag.NArg() > 0 {
		out = flag.Arg(0)
	}
	set := filepath.Join(out, "Zaslon.iconset")
	must(os.MkdirAll(set, 0o755))
	for _, n := range []int{16, 32, 128, 256, 512} {
		save(filepath.Join(set, fmt.Sprintf("icon_%dx%d.png", n, n)), n, n)
		save(filepath.Join(set, fmt.Sprintf("icon_%dx%d@2x.png", n, n)), n*2, n)
	}
	var windowsIcons []*image.NRGBA
	var favicon []*image.NRGBA
	for _, n := range []int{16, 20, 24, 32, 48, 64, 128, 256, 512, 1024} {
		save(filepath.Join(out, fmt.Sprintf("icon-%d.png", n)), n, n)
		if n <= 256 {
			windowsIcons = append(windowsIcons, ui.AppIcon(n))
			favicon = append(favicon, ui.AppIconForSize(n, min(n, 32)))
		}
	}
	must(os.WriteFile(filepath.Join(out, "zaslon.ico"),
		ui.ICO(windowsIcons...), 0o644))
	if *panelFavicon {
		must(os.WriteFile("internal/ui/panel/favicon.ico", ui.ICO(favicon...), 0o644))
	}
}

func save(path string, pixels, logicalSize int) {
	f, err := os.Create(path)
	must(err)
	defer f.Close()
	must(png.Encode(f, ui.AppIconForSize(pixels, logicalSize)))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
