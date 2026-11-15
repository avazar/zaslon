// zaslon-recover does not read config.yaml, start the guard, or use the network.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/avazar/zaslon/internal/app"
	"github.com/avazar/zaslon/internal/procs"
	"github.com/avazar/zaslon/internal/recovery"
	"github.com/gofrs/flock"
)

var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print the recovery helper version without operating on processes")
	dir := flag.String("dir", app.Dir(), "Zaslon profile directory (or ZASLON_DIR)")
	resume := flag.Bool("resume", false, "resume confirmed Zaslon suspensions; apps may access the current network")
	terminate := flag.Bool("terminate", false, "terminate recorded processes, including uncertain operations; unsaved work is lost")
	flag.Parse()
	if *showVersion {
		fmt.Println("zaslon-recover", version)
		return
	}
	if *resume && *terminate {
		fmt.Fprintln(os.Stderr, "Choose -resume or -terminate, not both.")
		os.Exit(2)
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
