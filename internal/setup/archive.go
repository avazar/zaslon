// Package setup installs Unix archives without signalling any process.
// It shares the profile lock with the guard and preserves recovery records.
package setup

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
)

type payloadFile struct {
	data []byte
	mode fs.FileMode
}
type payload map[string]payloadFile

const maxPayload = 256 << 20

func safeName(name string) bool {
	return fs.ValidPath(name) && name != "." && !strings.ContainsAny(name, "\\:\r\n") && path.Clean(name) == name
}
func executable(platform, command string) string {
	if platform == "darwin" {
		return "Zaslon.app/Contents/MacOS/" + command
	}
	return command
}
func allowedName(platform, name string) bool {
	switch name {
	case "VERSION", "LICENSE", "README.txt", "SHA256SUMS.txt":
		return true
	}
	if platform == "darwin" {
		return strings.HasPrefix(name, "Zaslon.app/Contents/")
	}
	return name == "zaslon" || name == "zaslon-recover"
}
func readPayload(archive, platform, version string) (payload, error) {
	p := payload{}
	total := int64(0)
	add := func(name string, mode fs.FileMode, r io.Reader) error {
		if !safeName(name) || !allowedName(platform, name) || !mode.IsRegular() {
			return fmt.Errorf("unsafe package entry: %q", name)
		}
		if _, exists := p[name]; exists {
			return fmt.Errorf("duplicate entry: %s", name)
		}
		if len(p) >= 256 {
			return errors.New("too many archive entries")
		}
		b, err := io.ReadAll(io.LimitReader(r, maxPayload-total+1))
		if err != nil {
			return err
		}
		total += int64(len(b))
		if total > maxPayload {
			return errors.New("archive exceeds size limit")
		}
		p[name] = payloadFile{b, mode}
		return nil
	}
	if platform == "darwin" {
		z, err := zip.OpenReader(archive)
		if err != nil {
			return nil, err
		}
		defer z.Close()
		for _, f := range z.File {
			r, err := f.Open()
			if err != nil {
				return nil, err
			}
			err = add(f.Name, f.Mode(), r)
			r.Close()
			if err != nil {
				return nil, err
			}
		}
	} else {
		f, err := os.Open(archive)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		g, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer g.Close()
		t := tar.NewReader(g)
		for {
			h, err := t.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
				return nil, errors.New("non-regular tar entry")
			}
			if err = add(h.Name, h.FileInfo().Mode(), t); err != nil {
				return nil, err
			}
		}
	}
	if !bytes.Equal(p["VERSION"].data, []byte(version+"\n")) {
		return nil, errors.New("package/helper version mismatch")
	}
	for _, name := range []string{"LICENSE", "README.txt", "SHA256SUMS.txt", executable(platform, "zaslon"), executable(platform, "zaslon-recover")} {
		if len(p[name].data) == 0 {
			return nil, fmt.Errorf("missing payload: %s", name)
		}
	}
	if platform == "darwin" && len(p["Zaslon.app/Contents/Info.plist"].data) == 0 {
		return nil, errors.New("missing app metadata")
	}
	for _, command := range []string{"zaslon", "zaslon-recover"} {
		if p[executable(platform, command)].mode&0111 == 0 {
			return nil, errors.New("non-executable program")
		}
	}
	var sums strings.Builder
	for _, name := range payloadNames(p) {
		if name != "SHA256SUMS.txt" {
			fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256(p[name].data), name)
		}
	}
	if sums.String() != string(p["SHA256SUMS.txt"].data) {
		return nil, errors.New("internal package checksum mismatch")
	}
	return p, nil
}
func payloadNames(p payload) []string {
	names := make([]string, 0, len(p))
	for name := range p {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
