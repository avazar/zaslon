package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixturePayload() payload {
	p := payload{"zaslon.exe": {[]byte("test application"), 0755}, "zaslon-recover.exe": {[]byte("test recovery"), 0755}, "LICENSE": {[]byte("MIT\n"), 0644}, "README.txt": {[]byte("instructions\n"), 0644}, "VERSION": {[]byte("0.3.0\n"), 0644}}
	p["SHA256SUMS.txt"] = entry{checksums(p), 0644}
	return p
}
func TestArchiveRoundTripAndManifest(t *testing.T) {
	for _, ext := range []string{".zip", ".tar.gz"} {
		t.Run(ext, func(t *testing.T) {
			p := fixturePayload()
			file := filepath.Join(t.TempDir(), "payload"+ext)
			if err := writeArchive(file, p); err != nil {
				t.Fatal(err)
			}
			got, err := readArchive(file)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(p) || !bytes.Equal(got["SHA256SUMS.txt"].data, checksums(got)) {
				t.Fatal("archive payload or checksums changed")
			}
			for name, e := range p {
				if !bytes.Equal(got[name].data, e.data) || got[name].mode.Perm() != e.mode.Perm() {
					t.Fatalf("entry changed: %s", name)
				}
			}
		})
	}
}
func TestMissingRecoveryAndTamperedPayloadAreRejected(t *testing.T) {
	p := fixturePayload()
	delete(p, "zaslon-recover.exe")
	p["SHA256SUMS.txt"] = entry{checksums(p), 0644}
	if err := validate(p, spec{"0.3.0", "windows", "amd64"}); err == nil || !strings.Contains(err.Error(), "missing payload: zaslon-recover.exe") {
		t.Fatalf("missing recovery accepted: %v", err)
	}
	p = fixturePayload()
	p["README.txt"] = entry{[]byte("tampered"), 0644}
	if err := validate(p, spec{"0.3.0", "windows", "amd64"}); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("changed payload accepted: %v", err)
	}
}
func TestUnsafeAndDuplicateArchivePathsAreRejected(t *testing.T) {
	for _, name := range []string{"../outside", "/outside", "C:/outside", "a/../outside", "a\\outside"} {
		file := filepath.Join(t.TempDir(), "unsafe.zip")
		if err := writeArchive(file, payload{name: {[]byte("bad"), 0644}}); err != nil {
			t.Fatal(err)
		}
		if _, err := readArchive(file); err == nil {
			t.Fatalf("accepted path %q", name)
		}
	}
	file := filepath.Join(t.TempDir(), "duplicate.zip")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	for range 2 {
		w, err := z.Create("VERSION")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte("0.3.0\n"))
	}
	_ = z.Close()
	_ = f.Close()
	if _, err := readArchive(file); err == nil {
		t.Fatal("accepted duplicate path")
	}
}
func TestReleaseArchiveNames(t *testing.T) {
	for _, s := range []spec{{"0.3.0", "windows", "amd64"}, {"0.3.0", "windows", "arm64"}, {"0.3.0", "linux", "amd64"}, {"0.3.0", "linux", "arm64"}, {"0.3.0", "darwin", "universal"}} {
		got, err := archiveSpec(archiveName(s))
		if err != nil || got != s {
			t.Fatalf("archive name roundtrip: %+v %v", got, err)
		}
	}
	for _, name := range []string{"zaslon-0.3.0-windows-universal.zip", "zaslon-0.3.0-linux-amd64.zip", "zaslon-0.3.0-macos-amd64.zip", "zaslon-00.3.0-linux-amd64.tar.gz"} {
		if _, err := archiveSpec(name); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
}

func TestCorruptGzipTrailerIsRejected(t *testing.T) {
	file := filepath.Join(t.TempDir(), "payload.tar.gz")
	if err := writeArchive(file, fixturePayload()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 1
	if err := os.WriteFile(file, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readArchive(file); err == nil {
		t.Fatal("corrupt gzip trailer accepted")
	}
}
