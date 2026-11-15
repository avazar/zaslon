// package creates and checks complete portable release archives. It never starts
// protection: optional native smoke checks run only the two version commands.
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/macho"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

type entry struct {
	data []byte
	mode fs.FileMode
}
type payload map[string]entry
type spec struct{ version, platform, arch string }

var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var namePattern = regexp.MustCompile(`^zaslon-([0-9]+\.[0-9]+\.[0-9]+)-(windows|linux|macos)-(amd64|arm64|universal)\.(zip|tar\.gz)$`)

func main() {
	platform := flag.String("os", runtime.GOOS, "windows, linux or darwin")
	arch := flag.String("arch", runtime.GOARCH, "amd64, arm64 or macOS universal")
	version := flag.String("version", "", "version (defaults to VERSION)")
	mainFile := flag.String("main", "", "application binary or macOS .app directory")
	helper := flag.String("recover", "", "recovery helper binary")
	out := flag.String("out", "dist", "archive output directory")
	verify := flag.String("verify", "", "verify an existing archive")
	smoke := flag.Bool("smoke", false, "run version commands when the archive matches this host")
	flag.Parse()
	if err := run(*platform, *arch, *version, *mainFile, *helper, *out, *verify, *smoke); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(platform, arch, version, mainFile, helper, out, verify string, smoke bool) error {
	if verify != "" {
		s, err := archiveSpec(filepath.Base(verify))
		if err != nil {
			return err
		}
		p, err := readArchive(verify)
		if err != nil {
			return err
		}
		if err := validate(p, s); err != nil {
			return err
		}
		if smoke && s.platform == runtime.GOOS && (s.arch == runtime.GOARCH || s.arch == "universal") {
			if err := smokeVersions(p, s); err != nil {
				return err
			}
		} else if smoke {
			fmt.Println("metadata/checksums only (foreign platform or architecture)", verify)
		}
		fmt.Println("verified", verify)
		return nil
	}
	if version == "" {
		b, err := os.ReadFile("VERSION")
		if err != nil {
			return err
		}
		version = strings.TrimSpace(string(b))
	}
	version = strings.TrimPrefix(version, "v")
	s := spec{version, platform, arch}
	if !versionPattern.MatchString(version) || !((platform == "windows" || platform == "linux") && (arch == "amd64" || arch == "arm64") || platform == "darwin" && arch == "universal") {
		return errors.New("unsupported package version/platform/architecture")
	}
	if mainFile == "" || helper == "" {
		return errors.New("-main and -recover are required")
	}
	p := payload{}
	add := func(name, source string, mode fs.FileMode) error {
		b, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		p[name] = entry{b, mode}
		return nil
	}
	readme := "docs/UNIX-PACKAGE.txt"
	appName, helperName := "zaslon", "zaslon-recover"
	if platform == "windows" {
		appName += ".exe"
		helperName += ".exe"
		readme = "docs/WINDOWS-PACKAGE.txt"
	}
	if platform == "darwin" {
		helperName = "Zaslon.app/Contents/MacOS/zaslon-recover"
		err := filepath.WalkDir(mainFile, func(file string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return errors.New("app contains a non-regular file")
			}
			rel, err := filepath.Rel(mainFile, file)
			if err != nil {
				return err
			}
			return add("Zaslon.app/"+filepath.ToSlash(rel), file, info.Mode().Perm())
		})
		if err != nil {
			return err
		}
	} else if err := add(appName, mainFile, 0755); err != nil {
		return err
	}
	if err := add(helperName, helper, 0755); err != nil {
		return err
	}
	for name, source := range map[string]string{"LICENSE": "LICENSE", "README.txt": readme} {
		if err := add(name, source, 0644); err != nil {
			return err
		}
	}
	p["VERSION"] = entry{[]byte(version + "\n"), 0644}
	p["SHA256SUMS.txt"] = entry{checksums(p), 0644}
	if err := validate(p, s); err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0755); err != nil {
		return err
	}
	name := archiveName(s)
	dst := filepath.Join(out, name)
	if err := writeArchive(dst, p); err != nil {
		return err
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst+".sha256", []byte(fmt.Sprintf("%x  %s\n", sha256.Sum256(b), name)), 0644); err != nil {
		return err
	}
	fmt.Println("built", dst)
	return nil
}

func archiveName(s spec) string {
	osName, ext := s.platform, ".zip"
	if osName == "darwin" {
		osName = "macos"
	}
	if osName == "linux" {
		ext = ".tar.gz"
	}
	return "zaslon-" + s.version + "-" + osName + "-" + s.arch + ext
}
func archiveSpec(name string) (spec, error) {
	m := namePattern.FindStringSubmatch(name)
	if m == nil {
		return spec{}, errors.New("unrecognized release archive name")
	}
	platform := m[2]
	if platform == "macos" {
		platform = "darwin"
	}
	s := spec{m[1], platform, m[3]}
	if !versionPattern.MatchString(s.version) || archiveName(s) != name || platform == "darwin" && s.arch != "universal" || platform != "darwin" && s.arch == "universal" {
		return spec{}, errors.New("archive type/architecture mismatch")
	}
	return s, nil
}
func sortedNames(p payload) []string {
	names := make([]string, 0, len(p))
	for name := range p {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
func checksums(p payload) []byte {
	var b strings.Builder
	for _, name := range sortedNames(p) {
		if name != "SHA256SUMS.txt" {
			fmt.Fprintf(&b, "%x  %s\n", sha256.Sum256(p[name].data), name)
		}
	}
	return []byte(b.String())
}
func safeName(name string) bool {
	return name != "" && name != "." && !strings.ContainsAny(name, "\\:\r\n") && !strings.HasPrefix(name, "/") && path.Clean(name) == name && name != ".." && !strings.HasPrefix(name, "../")
}

func validate(p payload, s spec) error {
	if !bytes.Equal(p["VERSION"].data, []byte(s.version+"\n")) || !bytes.Equal(p["SHA256SUMS.txt"].data, checksums(p)) {
		return errors.New("version or checksum manifest mismatch")
	}
	mainName, helperName := "zaslon", "zaslon-recover"
	if s.platform == "windows" {
		mainName += ".exe"
		helperName += ".exe"
	}
	if s.platform == "darwin" {
		mainName = "Zaslon.app/Contents/MacOS/zaslon"
		helperName = "Zaslon.app/Contents/MacOS/zaslon-recover"
	}
	for _, name := range []string{mainName, helperName, "LICENSE", "README.txt", "VERSION", "SHA256SUMS.txt"} {
		if len(p[name].data) == 0 {
			return fmt.Errorf("missing payload: %s", name)
		}
	}
	for name, e := range p {
		if !safeName(name) || !e.mode.IsRegular() {
			return fmt.Errorf("unsafe package entry %q", name)
		}
		if name != mainName && name != helperName && name != "LICENSE" && name != "README.txt" && name != "VERSION" && name != "SHA256SUMS.txt" && !(s.platform == "darwin" && strings.HasPrefix(name, "Zaslon.app/Contents/")) {
			return fmt.Errorf("unexpected package entry %q", name)
		}
	}
	for _, name := range []string{mainName, helperName} {
		if p[name].mode&0111 == 0 {
			return fmt.Errorf("not executable: %s", name)
		}
		command := "zaslon"
		if name == helperName {
			command = "zaslon-recover"
		}
		if err := validateBinary(p[name].data, s, command); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if s.platform == "darwin" && len(p["Zaslon.app/Contents/Info.plist"].data) == 0 {
		return errors.New("missing app metadata")
	}
	return nil
}
func validateBinary(data []byte, s spec, command string) error {
	check := func(reader io.ReaderAt, arch string) error {
		info, err := buildinfo.Read(reader)
		if err != nil {
			return err
		}
		if info.Path != "github.com/avazar/zaslon/cmd/"+command {
			return errors.New("wrong command in package payload")
		}
		settings := map[string]string{}
		for _, setting := range info.Settings {
			settings[setting.Key] = setting.Value
		}
		if settings["GOOS"] != s.platform || settings["GOARCH"] != arch {
			return errors.New("binary OS/architecture mismatch")
		}
		flags := strings.Fields(settings["-ldflags"])
		valid := false
		for i, v := range flags {
			if v == "-X" && i+1 < len(flags) && flags[i+1] == "main.version="+s.version {
				valid = true
			}
		}
		// Go omits linker flags from -trimpath build metadata. Native
		// runtime version commands below verify both binaries in that case.
		if settings["-ldflags"] != "" && !valid {
			return errors.New("binary version does not match package version")
		}
		return nil
	}
	r := bytes.NewReader(data)
	if s.arch != "universal" {
		return check(r, s.arch)
	}
	fat, err := macho.NewFatFile(r)
	if err != nil {
		return err
	}
	if len(fat.Arches) != 2 {
		return errors.New("universal binary requires exactly two architectures")
	}
	seen := map[string]bool{}
	for _, a := range fat.Arches {
		arch := ""
		switch a.Cpu {
		case macho.CpuAmd64:
			arch = "amd64"
		case macho.CpuArm64:
			arch = "arm64"
		default:
			return errors.New("unexpected universal CPU")
		}
		if seen[arch] {
			return errors.New("duplicate universal CPU")
		}
		seen[arch] = true
		if err := check(io.NewSectionReader(r, int64(a.Offset), int64(a.Size)), arch); err != nil {
			return err
		}
	}
	return nil
}

func writeArchive(file string, p payload) (err error) {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	if strings.HasSuffix(file, ".zip") {
		z := zip.NewWriter(f)
		defer func() { err = errors.Join(err, z.Close()) }()
		for _, name := range sortedNames(p) {
			e := p[name]
			h := &zip.FileHeader{Name: name, Method: zip.Deflate}
			h.SetMode(e.mode)
			h.SetModTime(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))
			w, err := z.CreateHeader(h)
			if err != nil {
				return err
			}
			if _, err := w.Write(e.data); err != nil {
				return err
			}
		}
		return nil
	}
	g := gzip.NewWriter(f)
	defer func() { err = errors.Join(err, g.Close()) }()
	t := tar.NewWriter(g)
	defer func() { err = errors.Join(err, t.Close()) }()
	for _, name := range sortedNames(p) {
		e := p[name]
		if err := t.WriteHeader(&tar.Header{Name: name, Mode: int64(e.mode.Perm()), Size: int64(len(e.data)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := t.Write(e.data); err != nil {
			return err
		}
	}
	return nil
}
func readArchive(file string) (payload, error) {
	p := payload{}
	var total int64
	add := func(name string, mode fs.FileMode, r io.Reader) error {
		if !safeName(name) || !mode.IsRegular() {
			return fmt.Errorf("unsafe archive entry %q", name)
		}
		if _, exists := p[name]; exists {
			return errors.New("duplicate archive entry")
		}
		b, err := io.ReadAll(io.LimitReader(r, (512<<20)-total+1))
		if err != nil {
			return err
		}
		total += int64(len(b))
		if total > 512<<20 {
			return errors.New("release archive exceeds size limit")
		}
		p[name] = entry{b, mode}
		return nil
	}
	if strings.HasSuffix(file, ".zip") {
		z, err := zip.OpenReader(file)
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
			_ = r.Close()
			if err != nil {
				return nil, err
			}
		}
		return p, nil
	}
	f, err := os.Open(file)
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
		if h.Typeflag != tar.TypeReg {
			return nil, errors.New("non-regular tar entry")
		}
		if err := add(h.Name, fs.FileMode(h.Mode), t); err != nil {
			return nil, err
		}
	}
	if _, err := io.Copy(io.Discard, g); err != nil {
		return nil, err
	} // consume and validate gzip trailer
	return p, nil
}
func smokeVersions(p payload, s spec) error {
	base, err := filepath.Abs("build")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(base, 0755); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(base, "package-smoke-")
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(base, dir)
	if err != nil || !strings.HasPrefix(rel, "package-smoke-") || strings.ContainsAny(rel, "/\\") {
		return errors.New("unexpected smoke directory")
	}
	defer os.RemoveAll(dir)
	for name, e := range p {
		file := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(file, e.data, e.mode); err != nil {
			return err
		}
	}
	mainName, helperName := "zaslon", "zaslon-recover"
	if s.platform == "windows" {
		mainName += ".exe"
		helperName += ".exe"
	}
	if s.platform == "darwin" {
		mainName = "Zaslon.app/Contents/MacOS/zaslon"
		helperName = "Zaslon.app/Contents/MacOS/zaslon-recover"
	}
	if s.platform == "darwin" {
		if output, err := exec.Command("codesign", "--verify", "--deep", "--strict", filepath.Join(dir, "Zaslon.app")).CombinedOutput(); err != nil {
			return fmt.Errorf("unpacked app signature: %w %s", err, output)
		}
	}
	profile, err := filepath.Abs(filepath.Join(dir, "smoke-profile"))
	if err != nil {
		return err
	}
	for _, item := range []struct{ name, arg string }{{mainName, "version"}, {helperName, "-version"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, filepath.Join(dir, filepath.FromSlash(item.name)), item.arg)
		for _, e := range os.Environ() {
			if !strings.HasPrefix(e, "ZASLON_DIR=") && !strings.HasPrefix(e, "ZASLON_CHILD=") {
				cmd.Env = append(cmd.Env, e)
			}
		}
		cmd.Env = append(cmd.Env, "ZASLON_DIR="+profile, "ZASLON_CHILD=1")
		var output bytes.Buffer
		cmd.Stdout, cmd.Stderr = &output, &output
		err := cmd.Run()
		cancel()
		if err != nil {
			return fmt.Errorf("package smoke %s: %w %s", item.name, err, output.String())
		}
		expected := "zaslon " + s.version
		if item.name == helperName {
			expected = "zaslon-recover " + s.version
		}
		if strings.TrimSpace(output.String()) != expected {
			return fmt.Errorf("runtime version mismatch for %s: %q", item.name, output.String())
		}
	}
	if _, err := os.Stat(profile); !errors.Is(err, os.ErrNotExist) {
		return errors.New("version smoke unexpectedly created a profile")
	}
	return nil
}
