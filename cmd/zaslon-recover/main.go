// Recovery never reads config.yaml, starts the guard, or uses the network.
// Explicit Unix installation mode only verifies and replaces program files.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/avazar/zaslon/internal/app"
	"github.com/avazar/zaslon/internal/procs"
	"github.com/avazar/zaslon/internal/recovery"
	"github.com/avazar/zaslon/internal/setup"
	"github.com/gofrs/flock"
)

var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print the recovery helper version without operating on processes")
	dir := flag.String("dir", app.Dir(), "Zaslon profile directory (or ZASLON_DIR)")
	resume := flag.Bool("resume", false, "resume confirmed Zaslon suspensions; apps may access the current network")
	terminate := flag.Bool("terminate", false, "terminate recorded processes, including uncertain operations; unsaved work is lost")
	archive := flag.String("install-archive", "", "install a verified Unix archive without signalling processes")
	target := flag.String("install-dir", "", "managed Unix installation directory")
	packageVersion := flag.String("package-version", "", "expected version, matching this helper")
	uninstall := flag.Bool("uninstall", false, "remove a managed Unix installation")
	noLinks := flag.Bool("no-links", false, "skip application launchers")
	flag.Parse()
	if *showVersion {
		fmt.Println("zaslon-recover", version)
		return
	}
	if *resume && *terminate {
		fmt.Fprintln(os.Stderr, "Choose -resume or -terminate, not both.")
		os.Exit(2)
	}
	if *archive != "" || *uninstall {
		custom := os.Getenv("ZASLON_DIR") != ""
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "dir" {
				custom = true
			}
		})
		if *resume || *terminate || (*uninstall && *archive != "") || (!*uninstall && *packageVersion != version) || (custom && !*noLinks) {
			fmt.Fprintln(os.Stderr, "Invalid installer options: keep recovery actions separate, use the matching helper version, and use -no-links for custom profiles.")
			os.Exit(2)
		}
		err := setup.Run(setup.Options{Archive: *archive, Target: *target, Profile: *dir, Version: *packageVersion, Uninstall: *uninstall, NoLinks: *noLinks})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("Program files updated. Settings, recovery records and previous-version backups were preserved.")
		return
	}
	if err := recoverProcesses(*dir, *resume, *terminate); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func recoverProcesses(dir string, resume, terminate bool) error {
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("profile: %w", err)
	}
	lock := flock.New(dir + string(os.PathSeparator) + "zaslon.lock")
	ok, err := lock.TryLock()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Zaslon is still running for this profile. Stop it before recovery")
	}
	defer lock.Close()
	c, err := recovery.Open(dir, procs.New())
	if err != nil {
		return err
	}
	for _, e := range c.Entries() {
		fmt.Printf("PID %d  %s  %s\n", e.Process.PID, e.Phase, e.Process.Name)
	}
	if !resume && !terminate {
		fmt.Println("Inspection only. Use -resume to release confirmed suspensions; this ends their protection.")
		return nil
	}
	if err := c.Recover(terminate); err != nil {
		return fmt.Errorf("recovery incomplete; unresolved entries were kept:\n%w", err)
	}
	fmt.Println("Recovery complete. No recorded processes remain. Network settings were not changed.")
	return nil
}
