// Zaslon suspends chosen apps on network changes and keeps them suspended
// until a current check permits the network. It does not terminate them.
//
//	zaslon                 start in the menu bar / tray
//	zaslon status          what's going on right now
//	zaslon allow [IP|CC]   allow the current IP, a given IP/subnet or a country
//	zaslon config          print the config path
//	zaslon autostart on|off
//	zaslon headless        run without a tray icon (servers, Linux without a tray)
//	zaslon version
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gofrs/flock"

	"github.com/avazar/zaslon/internal/app"
	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/guard"
	"github.com/avazar/zaslon/internal/netwatch"
	"github.com/avazar/zaslon/internal/procs"
	"github.com/avazar/zaslon/internal/recovery"
	"github.com/avazar/zaslon/internal/setup"
	"github.com/avazar/zaslon/internal/ui"
	"github.com/avazar/zaslon/internal/update"
	"github.com/avazar/zaslon/internal/window"
)

var version = "dev"

func main() {
	attachConsole()
	if len(os.Args) > 1 {
		if err := cli(os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, "zaslon:", err)
			os.Exit(1)
		}
		return
	}
	run(true)
}

func setupLang(cfg *config.Config) {
	ui.Lang = app.Language(cfg.Language)
	config.CommentLang = ui.Lang
}

func run(tray bool) {
	if err := os.MkdirAll(app.Dir(), 0o755); err != nil {
		fatal(err)
	}
	ui.Lang = app.Language("auto")
	if supervise() {
		return
	}
	installation, err := setup.AcquireRuntime()
	if err != nil {
		app.Logf("Protection startup refused: %v", err)
		app.Notify("Zaslon", err.Error())
		return
	}
	if installation != nil {
		defer installation.Close()
	}
	// One instance only. A second one (double-click, autostart) just says where the first is.
	lock := flock.New(app.LockPath())
	// After an update the old version may still be exiting: wait a little for the lock.
	ok := false
	for i := 0; i < 10 && !ok; i++ {
		if ok, _ = lock.TryLock(); !ok {
			time.Sleep(500 * time.Millisecond)
		}
	}
	if !ok {
		if data, err := os.ReadFile(app.ConfigPath()); err == nil {
			if c, err := config.Parse(data); err == nil {
				setupLang(c)
			}
		}
		app.Notify(ui.T("already.t"), ui.T("already.b"))
		return // exit 0: launchd must not restart us for this
	}
	defer lock.Unlock()
	processes, err := recovery.Open(app.Dir(), procs.New())
	if err == nil {
		err = processes.Prune()
	}
	if err != nil {
		reportProtectionRecoveryError(err, tray)
		return // normal exit also stops the supervisor; do not add more suspend counts
	}

	// The comment language of a fresh config.yaml follows the system.
	ui.Lang = app.Language("auto")
	config.CommentLang = ui.Lang
	recorded := len(processes.Entries()) != 0
	cfg, created, err := loadStartupConfig(app.ConfigPath(), recorded)
	if err != nil {
		if recorded {
			reportProtectionRecoveryError(err, tray)
			return
		}
		app.Logf("config.yaml: %v - default settings are used", err)
		app.Notify(ui.T("cfg.error.t"), ui.T("cfg.error.b", err))
		cfg = config.Default()
	}
	setupLang(cfg)
	if created && os.Getenv("ZASLON_DIR") == "" {
		// First start: run at login by default, it's a kill switch after all.
		_ = app.SetAutostart(true)
	}
	update.Cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	r := app.NewRunner(ctx, cfg, processes)
	adopted, err := r.G.RestoreProtection()
	if err != nil {
		cancel()
		reportProtectionRecoveryError(err, tray)
		return
	}
	if adopted > 0 {
		app.Logf("Protection recovery: adopted %d confirmed suspended processes; waiting for fresh checks", adopted)
	}
	app.Logf("Zaslon %s started", version)
	r.OnConfigError = func(err error) { app.Notify(ui.T("cfg.error.t"), ui.T("cfg.error.b", err)) }
	stats := app.LoadStats()
	srv := &ui.Server{G: r.G, Stats: stats, Version: version}
	if err := srv.Start(ctx); err != nil {
		app.Logf("panel server: %v", err)
	}

	done := make(chan struct{})
	go func() { r.Run(); close(done) }()
	stop := func() {
		cancel()
		<-done // Run un-freezes everything before returning
		srv.WaitClosed()
		if err := processes.Recover(false); err != nil {
			app.Logf("Recovery incomplete: %v", err)
			app.Notify("Zaslon: recovery incomplete", "Run zaslon-recover for this profile. "+err.Error())
		}
		app.Logf("Zaslon stopped")
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	if !tray {
		r.G.OnChange(func(snap guard.Snapshot, evs []guard.Event) {
			stats.Record(snap.Counters, time.Now())
			ui.HeadlessRender(snap, evs)
		})
		<-sig
		stop()
		return
	}
	t := &ui.Tray{G: r.G, Version: version, OnQuit: stop, UpdateCheck: cfg.UpdateCheck, Stats: stats}
	srv.UpdateAvailable, srv.InstallUpdate = t.UpdateAvailable, t.InstallUpdate
	go func() {
		<-sig
		stop()
		os.Exit(0)
	}()
	t.Run()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "zaslon:", err)
	os.Exit(1)
}

func cli(args []string) error {
	// Read, never create: the first start of the app itself must see a missing
	// config, that's how it knows to turn on autostart.
	cfg := config.Default()
	if data, err := os.ReadFile(app.ConfigPath()); err == nil {
		if cfg, err = config.Parse(data); err != nil {
			return fmt.Errorf("%s: %w", app.ConfigPath(), err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s: %w", app.ConfigPath(), err)
	}
	setupLang(cfg)
	switch args[0] {
	case "status":
		return status(cfg, os.Stdout)
	case "allow":
		return allow(cfg, args[1:])
	case "config":
		fmt.Println(app.ConfigPath())
		return nil
	case "autostart":
		if len(args) < 2 || (args[1] != "on" && args[1] != "off") {
			return errors.New("usage: zaslon autostart on|off")
		}
		return app.SetAutostart(args[1] == "on")
	case "headless":
		run(false)
		return nil
	case "update":
		return selfUpdate()
	case "panel":
		return openPanel()
	case "version", "--version", "-v":
		fmt.Println("zaslon", version)
		return nil
	case "help", "--help", "-h":
		fmt.Print(usage)
		return nil
	}
	return fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
}

const usage = `Zaslon - kill switch for apps: freezes them when your network or IP changes.

  zaslon                 start in the menu bar / tray
  zaslon status          current IP, country and state
  zaslon allow           allow only the current IPv4
  zaslon allow 1.2.3.4   allow an IP or a subnet (1.2.3.0/24)
  zaslon allow NL        allow a country
  zaslon config          print the config file path
  zaslon autostart on|off
  zaslon panel           open the Zaslon panel
  zaslon update          install the latest version
  zaslon headless        run without a tray icon
  zaslon version

https://github.com/avazar/zaslon
`

func status(cfg *config.Config, out io.Writer) error {
	s, err := app.ReadState()
	if err == nil && processAlive(s.PID) && time.Since(s.Updated) < 24*time.Hour {
		fmt.Fprintln(out, "Zaslon: ", s.Line)
		fmt.Fprintln(out, "Last guard measurement:")
		if !s.MeasuredAt.IsZero() {
			fmt.Fprintln(out, "Checked:", s.MeasuredAt.Local().Format(time.RFC3339))
		} else {
			fmt.Fprintln(out, "Checked: unknown")
		}
		if s.IP == "" {
			fmt.Fprintln(out, "IPv4:    unknown")
		} else {
			if s.Country == "" && s.DomainCountry != "" {
				fmt.Fprintln(out, "IPv4:   ", ui.IPWithCountry(s.IP, s.DomainCountry), "(from service checks)")
			} else {
				fmt.Fprintln(out, "IPv4:   ", ui.IPWithCountry(s.IP, s.Country))
			}
		}
		if s.IP6 != "" {
			fmt.Fprintln(out, "IPv6:   ", ui.IPWithCountry(s.IP6, s.Country6))
		}
		if len(s.Apps) > 0 {
			fmt.Fprintln(out, "Apps:   ", strings.Join(s.Apps, ", "))
		}
		fmt.Fprintln(out, "Config: ", app.ConfigPath())
		return nil
	}
	fmt.Fprintln(out, "Zaslon:  not running")
	fmt.Fprintln(out, "Standalone IP measurement using the configured services:")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	geo := netwatch.NewGeo()
	measured := currentIPs(ctx, cfg.IPServices, cfg.IPv6Services, cfg.CheckIPv6)
	r, err := measured.v4, measured.err4
	if err != nil {
		fmt.Fprintln(out, "IPv4:    unknown")
	} else {
		fmt.Fprintln(out, "IP:     ", ui.IPWithCountry(r.IP, geo.Country(ctx, r.IP, 4*time.Second)))
		if len(r.Others) > 0 {
			fmt.Fprintln(out, "         other services say:", strings.Join(r.Others, ", "))
		}
	}
	if r6, err := measured.v6, measured.err6; err == nil {
		fmt.Fprintln(out, "IPv6:   ", ui.IPWithCountry(r6.IP, geo.Country(ctx, r6.IP, 4*time.Second)))
	}
	fmt.Fprintln(out, "Config: ", app.ConfigPath())
	return nil
}

type measuredIPs struct {
	v4, v6     netwatch.IPResult
	err4, err6 error
}

// Each family can consume the full four-second collection window. Run them
// together so one slow family cannot exhaust the command's shared deadline.
func currentIPs(ctx context.Context, v4Services, v6Services []string, check6 bool) measuredIPs {
	result := measuredIPs{err6: netwatch.ErrOffline}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		result.v4, result.err4 = netwatch.PublicIP(ctx, v4Services, 4*time.Second, false)
	}()
	if check6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result.v6, result.err6 = netwatch.PublicIP(ctx, v6Services, 4*time.Second, true)
		}()
	}
	wg.Wait()
	return result
}

func allow(cfg *config.Config, args []string) error {
	var what string
	switch {
	case len(args) == 0:
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		measured := currentIPs(ctx, cfg.IPServices, cfg.IPv6Services, false)
		r, err := measured.v4, measured.err4
		if err != nil {
			return errors.New("no internet - nothing to allow")
		}
		if !r.Confirmed(cfg.Need()) {
			return fmt.Errorf("IPv4 not confirmed: %d of %d required votes, conflicting addresses: %v", r.Votes, cfg.Need(), r.Others)
		}
		cfg.Allow.AddIP(r.IP)
		what = r.IP
	case len(args[0]) == 2 && !strings.ContainsAny(args[0], ".:/"):
		cfg.Allow.AddCountry(args[0])
		what = strings.ToUpper(args[0])
	default:
		if _, err := config.ParseIPOrNet(args[0]); err != nil {
			return err
		}
		cfg.Allow.AddIP(args[0])
		what = args[0]
	}
	if err := config.Save(app.ConfigPath(), cfg); err != nil {
		return err
	}
	fmt.Println("allowed:", what)
	return nil
}

func selfUpdate() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	rel, err := update.Latest(ctx)
	if err != nil {
		return err
	}
	if !update.Newer(version, rel.Version()) {
		fmt.Println("zaslon", version, "is the latest version")
		return nil
	}
	fmt.Println("installing", rel.Version(), "…")
	restart, err := update.Install(ctx, rel)
	if err != nil {
		return err
	}
	fmt.Println("installed", rel.Version())
	// A running instance still runs the old code: stop it politely (it un-freezes
	// apps on the way out) and start the new one.
	if s, err := app.ReadState(); err == nil && processAlive(s.PID) {
		if stopProcess(s.PID) {
			return restart()
		}
		fmt.Println("restart Zaslon (Quit in the menu and open it again) to use it")
	}
	return nil
}

// openPanel shows the running Zaslon's panel in a window (or the browser on Linux).
func openPanel() error {
	p, err := ui.ReadPanelInfo()
	if err != nil {
		return errors.New("Zaslon is not running - start it first")
	}
	url := p.URL + "?t=" + p.Token
	if runtime.GOOS == "linux" {
		return app.OpenURL(url)
	} // ordinary browser tab; no native window to own
	session, existing, err := ui.AttachNativePanel(context.Background(), p)
	if err != nil {
		return err
	}
	if existing {
		return nil
	}
	defer session.Close()
	return window.Open(session.Context, session.Focus, url, "Zaslon", ui.T("panel.close"), ui.T("panel.quit"), ui.PanelIconICO())
}
