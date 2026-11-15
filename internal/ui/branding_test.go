package ui

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/png"
	"math"
	"strings"
	"testing"
)

// A dot has no white strokes outside its central circle; the snowflake does.
// Check the visible result, including logical size on high-DPI displays.
func snowflakeVisible(img image.Image) bool {
	n := img.Bounds().Dx()
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			r, g, b, a := img.At(x, y).RGBA()
			if a > 0xf000 && r > 0xe000 && g > 0xe000 && b > 0xe000 && math.Hypot(float64(x)+.5-float64(n)/2, float64(y)+.5-float64(n)/2) > float64(n)*.135 {
				return true
			}
		}
	}
	return false
}

func checkBrandImage(t *testing.T, img image.Image, size int, snowflake bool) {
	t.Helper()
	if img.Bounds().Dx() != size || img.Bounds().Dy() != size {
		t.Fatalf("wrong icon dimensions: %v", img.Bounds())
	}
	if _, _, _, a := img.At(0, 0).RGBA(); a != 0 {
		t.Fatal("rounded corner is not transparent")
	}
	r, g, b, a := img.At(size/2, size/2).RGBA()
	if r < 0xe000 || g < 0xe000 || b < 0xe000 || a != 0xffff {
		t.Fatal("white center is missing")
	}
	if snowflakeVisible(img) != snowflake {
		t.Fatalf("wrong glyph for %dpx icon: snowflake=%v", size, snowflakeVisible(img))
	}
}

func TestBrandGlyphTracksLogicalSizeAndPreservesTransparency(t *testing.T) {
	for _, test := range []struct {
		pixels, logical int
		snowflake       bool
	}{
		{16, 16, false}, {20, 20, false}, {24, 24, false}, {32, 32, false},
		{48, 48, true}, {64, 64, true}, {128, 128, true},
		{32, 16, false}, {64, 32, false}, {256, 32, false}, // Retina and window favicon
	} {
		checkBrandImage(t, AppIconForSize(test.pixels, test.logical), test.pixels, test.snowflake)
	}
}

func TestPanelFaviconKeepsDotAtEveryDensity(t *testing.T) {
	html, err := panelFiles.ReadFile("panel/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), `href="favicon.ico"`) {
		t.Fatal("window still uses the detailed panel logo")
	}
	data, err := panelFiles.ReadFile("panel/favicon.ico")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 6 || binary.LittleEndian.Uint16(data[2:4]) != 1 {
		t.Fatal("invalid favicon ICO header")
	}
	count := int(binary.LittleEndian.Uint16(data[4:6]))
	if count != 8 || len(data) < 6+16*count {
		t.Fatalf("incomplete favicon set: %d", count)
	}
	for i := 0; i < count; i++ {
		e := data[6+16*i : 6+16*(i+1)]
		n := int(e[0])
		if n == 0 {
			n = 256
		}
		size, offset := int(binary.LittleEndian.Uint32(e[8:12])), int(binary.LittleEndian.Uint32(e[12:16]))
		if offset < 6+16*count || offset+size > len(data) {
			t.Fatal("favicon directory points outside file")
		}
		img, err := png.Decode(bytes.NewReader(data[offset : offset+size]))
		if err != nil {
			t.Fatal(err)
		}
		checkBrandImage(t, img, n, false)
	}
}
