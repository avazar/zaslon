package ui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"

	"github.com/avazar/zaslon/internal/app"
	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/guard"
	"github.com/avazar/zaslon/internal/procs"
	"github.com/avazar/zaslon/internal/update"
)

const (
	historyItems = 12
	customItems  = 10
)

// Tray is the menu bar (macOS) / notification area (Windows, Linux) app.
type Tray struct {
	G           *guard.Guard
	Version     string
	OnQuit      func()
	UpdateCheck bool
	Stats       *app.Stats

	mu          sync.Mutex
	lastIcon    string
	lastTooltip string
	lastBarText string

	menuMu        sync.Mutex // never held during guard, shell icon or notification calls
	menuOnOpen    bool
	menuSnapshot  *guard.Snapshot
	menuRows      map[*systray.MenuItem]trayMenuRow
	updateVersion string
	installing    bool

	mStatus, mNow, mNow6, mOthers, mAllowed *systray.MenuItem
	mAllowIP, mAllowCountry, mCheck         *systray.MenuItem
	mPause, mP15, mP60, mPForever, mUnpause *systray.MenuItem
	mApps                                   *systray.MenuItem
	appItems                                map[string]*systray.MenuItem
	customs                                 []*systray.MenuItem
	mAddApp                                 *systray.MenuItem
	mHistory                                *systray.MenuItem
	hist                                    []*systray.MenuItem
	mSettings, mLog, mAutostart             *systray.MenuItem
	mBar, mBarIP, mBarCountry, mBarIcon     *systray.MenuItem
	mAbout, mQuit                           *systray.MenuItem
	mUpdate, mPanel, mTrust, mDNS, mReport  *systray.MenuItem
	latest                                  update.Release
	quitNow                                 chan struct{}
}

// Run blocks on the main thread until Quit.
func (t *Tray) Run() {
	t.quitNow = make(chan struct{})
	systray.SetOnTapped(OpenPanel)
	stop := onTrayMenuOpening(t.refreshMenu)
	t.menuOnOpen = stop != nil
	if stop != nil {
		defer stop()
	}
	systray.Run(t.onReady, func() {})
}

func (t *Tray) onReady() {
	systray.SetTooltip("Zaslon")
	t.setIcon(guard.Snapshot{Config: config.Default()})

	t.mUpdate = systray.AddMenuItem("", "")
	t.mUpdate.Hide()
	t.mPanel = systray.AddMenuItem(T("panel"), "")
	systray.AddSeparator()
	t.mStatus = systray.AddMenuItem(T("starting"), "")
	t.mStatus.Disable()
	t.mNow = systray.AddMenuItem(T("now.unknown"), "")
	t.mNow.Disable()
	t.mNow6 = systray.AddMenuItem("", "")
	t.mNow6.Disable()
	t.mNow6.Hide()
	t.mOthers = systray.AddMenuItem("", "")
	t.mOthers.Disable()
	t.mOthers.Hide()
	t.mDNS = systray.AddMenuItem("", "")
	t.mDNS.Disable()
	t.mDNS.Hide()
	t.mAllowed = systray.AddMenuItem("", "")
	t.mAllowed.Disable()
	systray.AddSeparator()

	t.mAllowIP = systray.AddMenuItem("", "")
	t.mAllowCountry = systray.AddMenuItem("", "")
	t.mAllowIP.Hide()
	t.mAllowCountry.Hide()
	t.mTrust = systray.AddMenuItem(T("trust"), "")
	t.mTrust.Hide()
	t.mCheck = systray.AddMenuItem(T("check"), "")
	t.mPause = systray.AddMenuItem(T("pause"), "")
	t.mP15 = t.mPause.AddSubMenuItem(T("pause.15m"), "")
	t.mP60 = t.mPause.AddSubMenuItem(T("pause.1h"), "")
	t.mPForever = t.mPause.AddSubMenuItem(T("pause.forever"), "")
	t.mUnpause = systray.AddMenuItem(T("unpause"), "")
	t.mUnpause.Hide()
	systray.AddSeparator()

	t.mApps = systray.AddMenuItem(T("apps"), "")
	t.appItems = map[string]*systray.MenuItem{}
	for _, p := range procs.Presets {
		t.appItems[p.ID] = t.mApps.AddSubMenuItemCheckbox(p.Name, "", false)
	}
	t.mApps.AddSeparator()
	for i := 0; i < customItems; i++ {
		it := t.mApps.AddSubMenuItem("", "")
		it.Disable()
		it.Hide()
		t.customs = append(t.customs, it)
	}
	t.mAddApp = t.mApps.AddSubMenuItem(T("apps.edit"), "")

	t.mHistory = systray.AddMenuItem(T("history"), "")
	for i := 0; i < historyItems; i++ {
		it := t.mHistory.AddSubMenuItem("", "")
		it.Disable()
		t.hist = append(t.hist, it)
	}
	t.hist[0].SetTitle(T("history.empty"))
	for _, it := range t.hist[1:] {
		it.Hide()
	}
	systray.AddSeparator()

	t.mSettings = systray.AddMenuItem(T("settings"), "")
	t.mLog = systray.AddMenuItem(T("log"), "")
	t.mReport = systray.AddMenuItem(T("report"), "")
	t.mAutostart = systray.AddMenuItemCheckbox(T("autostart"), "", app.AutostartEnabled())
	t.mBar = systray.AddMenuItem(T("menubar"), "")
	t.mBarIP = t.mBar.AddSubMenuItemCheckbox(T("menubar.ip"), "", false)
	t.mBarCountry = t.mBar.AddSubMenuItemCheckbox(T("menubar.country"), "", false)
	t.mBarIcon = t.mBar.AddSubMenuItemCheckbox(T("menubar.icon"), "", false)
	systray.AddSeparator()
	t.mAbout = systray.AddMenuItem(T("about", t.Version), "")
	systray.AddSeparator()
	t.mQuit = systray.AddMenuItem(T("quit"), "")

	t.G.OnChange(t.render)
	t.render(t.G.Snapshot(time.Now()), nil)
	go t.loop()
	if t.UpdateCheck {
		go t.updateLoop()
	}
}

func (t *Tray) loop() {
	appClicks := make(chan string)
	for id, it := range t.appItems {
		go func(id string, it *systray.MenuItem) {
			for range it.ClickedCh {
				appClicks <- id
			}
		}(id, it)
	}
	reportSaveError := func(err error) {
		if err != nil {
			app.Logf("%v", err)
			app.Notify("Zaslon", err.Error())
		}
	}
	setBar := func(v string) {
		reportSaveError(t.G.Update(time.Now(), func(c *config.Config) { c.MenuBar = v }))
	}
	for {
		select {
		case <-t.mAllowIP.ClickedCh:
			OpenPanel() // permissions are reviewed and confirmed in the panel
		case <-t.mAllowCountry.ClickedCh:
			OpenPanel()
		case <-t.mPanel.ClickedCh:
			OpenPanel()
		case <-t.mTrust.ClickedCh:
			OpenPanel()
		case <-t.mReport.ClickedCh:
			_ = app.OpenURL(app.ReportURL(t.Version))
		case <-t.mCheck.ClickedCh:
			t.G.CheckNow(time.Now())
		case <-t.mP15.ClickedCh:
			t.G.Pause(time.Now(), 15*time.Minute)
		case <-t.mP60.ClickedCh:
			t.G.Pause(time.Now(), time.Hour)
		case <-t.mPForever.ClickedCh:
			t.G.Pause(time.Now(), guard.Forever)
		case <-t.mUnpause.ClickedCh:
			t.G.Unpause(time.Now())
		case id := <-appClicks:
			t.menuMu.Lock()
			enable := !t.appItems[id].Checked()
			t.menuMu.Unlock()
			reportSaveError(t.G.SetAppEnabled(time.Now(), id, enable))
		case <-t.mAddApp.ClickedCh:
			_ = app.OpenFile(app.ConfigPath())
		case <-t.mSettings.ClickedCh:
			_ = app.OpenFile(app.ConfigPath())
		case <-t.mLog.ClickedCh:
			_ = app.OpenFile(app.LogPath())
		case <-t.mAutostart.ClickedCh:
			t.menuMu.Lock()
			on := !t.mAutostart.Checked()
			t.menuMu.Unlock()
			if err := app.SetAutostart(on); err == nil {
				t.menuMu.Lock()
				t.refreshMenuIfLive()
				t.menuMu.Unlock()
			}
		case <-t.mBarIP.ClickedCh:
			setBar("ip")
		case <-t.mBarCountry.ClickedCh:
			setBar("country")
		case <-t.mBarIcon.ClickedCh:
			setBar("icon")
		case <-t.mUpdate.ClickedCh:
			if t.installUpdate() {
				return
			}
		case <-t.quitNow:
			return
		case <-t.mAbout.ClickedCh:
			_ = app.OpenURL(app.RepoURL)
		case <-t.mQuit.ClickedCh:
			if t.OnQuit != nil {
				t.OnQuit()
			}
			systray.Quit()
			return
		}
	}
}

// updateLoop checks GitHub a minute after start and then once a day.
func (t *Tray) updateLoop() {
	time.Sleep(time.Minute)
	notified := ""
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		rel, err := update.Latest(ctx)
		cancel()
		if err == nil && update.Newer(t.Version, rel.Version()) {
			t.mu.Lock()
			t.latest = rel
			t.mu.Unlock()
			t.menuMu.Lock()
			t.updateVersion = rel.Version()
			t.refreshMenuIfLive()
			t.menuMu.Unlock()
			if notified != rel.Version() {
				notified = rel.Version()
				app.Notify(T("update.t", rel.Version()), T("update.b", rel.Version()))
				app.Logf("доступна версия %s", rel.Version())
			}
		}
		time.Sleep(24 * time.Hour)
	}
}

// UpdateAvailable is the newer version found, or "".
func (t *Tray) UpdateAvailable() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if update.Newer(t.Version, t.latest.Version()) {
		return t.latest.Version()
	}
	return ""
}

// InstallUpdate is the panel's "Update" button.
func (t *Tray) InstallUpdate() {
	if t.installUpdate() {
		close(t.quitNow)
	}
}

// installUpdate replaces Zaslon with the new version and restarts it; true means we're exiting.
func (t *Tray) installUpdate() bool {
	t.mu.Lock()
	rel := t.latest
	t.mu.Unlock()
	if rel.Tag == "" {
		return false
	}
	t.menuMu.Lock()
	if t.installing {
		t.menuMu.Unlock()
		return false
	}
	t.installing = true
	t.refreshMenuIfLive()
	t.menuMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	restart, err := update.Install(ctx, rel)
	if err != nil {
		app.Logf("обновление не установилось: %v", err)
		app.Notify(T("update.failed.t"), T("update.failed.b", err))
		_ = app.OpenURL(rel.Page)
		t.menuMu.Lock()
		t.installing = false
		t.refreshMenuIfLive()
		t.menuMu.Unlock()
		return false
	}
	app.Logf("установлена версия %s, перезапуск", rel.Version())
	if t.OnQuit != nil {
		t.OnQuit() // un-freeze apps before handing over
	}
	_ = restart()
	systray.Quit()
	return true
}

func setChecked(it *systray.MenuItem, on bool) {
	if it.Checked() == on {
		return
	}
	if on {
		it.Check()
	} else {
		it.Uncheck()
	}
}

type trayMenuRow struct {
	title   string
	visible bool
}

// On Windows SetTitle can insert a hidden item into the native menu.
func (t *Tray) row(it *systray.MenuItem, title string, visible bool) {
	next := trayMenuRow{title, visible}
	last, known := t.menuRows[it]
	if known && last == next {
		return
	}
	if visible {
		if !known || !last.visible || last.title != title {
			it.SetTitle(title)
		}
		if !known || !last.visible {
			it.Show()
		}
	} else if !known || last.visible {
		it.Hide()
	}
	t.menuRows[it] = next
}

// render is called by the guard after every change.
func (t *Tray) render(s guard.Snapshot, evs []guard.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cfg := s.Config

	for _, e := range evs {
		app.LogAt(e.At, logMessage(e))
		if title, body, ok := Notification(e); ok && cfg.Notifications {
			app.Notify(title, body)
		}
	}

	t.setIcon(s)
	t.menuMu.Lock()
	t.menuSnapshot = &s
	t.refreshMenuIfLive()
	t.menuMu.Unlock()

	if t.Stats != nil {
		t.Stats.Record(s.Counters, time.Now())
	}
	app.WriteState(app.State{
		Status: statusName(s), Line: StatusLine(s), IP: s.IP, Country: s.Country, DomainCountry: s.DomainCountry, IP6: s.IP6, Country6: s.Country6, MeasuredAt: s.MeasuredAt,
		Allowed: s.Allowed(), Apps: procs.AppNames(s.Running), Frozen: s.Frozen, Paused: s.Paused(),
	})
}

// Platforms without a pre-open callback apply changed rows as snapshots arrive.
func (t *Tray) refreshMenuIfLive() {
	if !t.menuOnOpen {
		t.applyMenu()
	}
}

func (t *Tray) refreshMenu() {
	t.menuMu.Lock()
	defer t.menuMu.Unlock()
	t.applyMenu()
}

func (t *Tray) applyMenu() {
	if t.menuSnapshot == nil {
		return
	}
	s := t.menuSnapshot
	cfg := s.Config
	if t.menuRows == nil {
		t.menuRows = make(map[*systray.MenuItem]trayMenuRow)
	}
	updateTitle := "⬆ " + T("update.available", t.updateVersion)
	if t.installing {
		updateTitle = T("update.installing", t.updateVersion)
	}
	// Enable/Disable also updates the native item. Only touch visible updates.
	t.row(t.mUpdate, updateTitle, t.updateVersion != "")
	if t.updateVersion != "" && t.mUpdate.Disabled() != t.installing {
		if t.installing {
			t.mUpdate.Disable()
		} else {
			t.mUpdate.Enable()
		}
	}
	t.row(t.mStatus, dotFor(ToneOf(*s))+" "+StatusLine(*s), true)
	now := T("now.unknown")
	if s.Offline {
		now = T("now.offline")
	} else if s.IP != "" {
		now = T("now", IPWithCountry(s.IP, s.DisplayCountry()))
	}
	t.row(t.mNow, now, true)
	t.row(t.mNow6, T("now6", IPWithCountry(s.IP6, s.Country6)), s.IP6 != "" && cfg.CheckIPv6)
	t.row(t.mOthers, T("others", strings.Join(s.Others, ", ")), len(s.Others) > 0)
	allowed := T("allowed.summary", allowedSummary(cfg.Allow))
	if s.Network != "" {
		allowed = T("trusted.on", s.Network)
	}
	t.row(t.mAllowed, allowed, true)
	t.row(t.mDNS, T("dns.leak", IPWithCountry(s.DNS, s.DNSCountry)), s.DNSLeak)
	t.row(t.mTrust, T("trust"), s.NetID != "" && s.Network == "" && !s.Paused())
	t.row(t.mAllowIP, T("allow.ip", s.IP), s.IP != "" && !s.Allowed() && !s.Paused() && (s.Reason == guard.IPNotAllowed || s.Reason == guard.IPv6Leak))
	t.row(t.mAllowCountry, T("allow.country", Country(s.Country)), s.Country != "" && !slices.Contains(cfg.Allow.Countries, s.Country) && !s.Paused())
	t.row(t.mPause, T("pause"), !s.Paused())
	t.row(t.mUnpause, T("unpause"), s.Paused())
	apps := T("apps")
	if running := procs.AppNames(s.Running); len(running) > 0 {
		apps = T("apps.running", strings.Join(running, ", "))
	}
	t.row(t.mApps, apps, true)
	for id, it := range t.appItems {
		setChecked(it, slices.Contains(cfg.Apps, id))
	}
	for i, it := range t.customs {
		title := ""
		if i < len(cfg.CustomApps) {
			title = "✓ " + T("apps.custom", cfg.CustomApps[i].Name)
		}
		t.row(it, title, i < len(cfg.CustomApps))
	}
	for i, it := range t.hist {
		j := len(s.History) - 1 - i
		title := ""
		if j >= 0 {
			e := s.History[j]
			title = e.At.Local().Format("15:04:05") + "  " + eventMessage(e, false)
		} else if i == 0 {
			title = T("history.empty")
		}
		t.row(it, title, i == 0 || j >= 0)
	}
	setChecked(t.mAutostart, app.AutostartEnabled())
	setChecked(t.mBarIP, cfg.MenuBar == "ip")
	setChecked(t.mBarCountry, cfg.MenuBar == "country")
	setChecked(t.mBarIcon, cfg.MenuBar == "icon")
}

func statusName(s guard.Snapshot) string {
	if len(s.Errors) != 0 {
		return "error"
	}
	if s.Status == guard.OK && len(s.Warnings) > 0 {
		return "warning"
	}
	return [...]string{"starting", "ok", "frozen", "blocked"}[s.Status]
}

func dotFor(t Tone) string {
	return map[Tone]string{Gray: "⚪", Green: "🟢", Amber: "🟠", Red: "🔴"}[t]
}

func allowedSummary(a config.Allow) string {
	var parts []string
	if len(a.IPs) > 0 {
		parts = append(parts, T("n.ips", len(a.IPs)))
	}
	if len(a.Countries) > 0 {
		parts = append(parts, T("n.countries", strings.Join(a.Countries, ", ")))
	}
	if len(parts) == 0 {
		return T("allowed.none")
	}
	return strings.Join(parts, ", ")
}

// barText is what sits next to the icon in the macOS menu bar.
func barText(s guard.Snapshot) string {
	mode := s.Config.MenuBar
	if mode == "icon" {
		return ""
	}
	if s.Offline {
		return T("now.offline")[strings.Index(T("now.offline"), ":")+2:]
	}
	if s.IP == "" {
		return "…"
	}
	var b strings.Builder
	if f := Flag(s.DisplayCountry()); f != "" {
		b.WriteString(f + " ")
	}
	if mode == "country" {
		b.WriteString(s.DisplayCountry())
	} else {
		b.WriteString(s.IP)
	}
	return b.String()
}

func (t *Tray) setIcon(s guard.Snapshot) {
	tone := ToneOf(s)
	cc := s.DisplayCountry()
	if s.Config.MenuBar == "icon" || s.Offline {
		cc = ""
	}
	key := fmt.Sprint(tone, cc)
	if runtime.GOOS == "darwin" {
		if key != t.lastIcon {
			systray.SetIcon(Dot(tone))
		}
		if title := barText(s); title != t.lastBarText {
			systray.SetTitle(title)
			t.lastBarText = title
		}
	} else if key != t.lastIcon {
		if runtime.GOOS == "windows" {
			systray.SetIcon(ICO(Badge(tone, cc, 16), Badge(tone, cc, 32), Badge(tone, cc, 48)))
		} else {
			systray.SetIcon(pngBytes(Badge(tone, cc, 64)))
		}
	}
	t.lastIcon = key

	tip := map[Tone]string{Gray: T("tip.paused"), Green: T("tip.ok"), Amber: T("tip.frozen"), Red: T("tip.blocked")}[tone]
	if s.Status == guard.OK && len(s.Warnings) > 0 && !s.Paused() {
		tip = "Zaslon: " + StatusLine(s)
	}
	if s.Status == guard.Starting && !s.Paused() {
		tip = "Zaslon: " + T("starting")
	}
	if s.IP != "" && s.Config.MenuBar != "icon" {
		if s.Config.MenuBar == "country" {
			tip += "\n" + Country(s.DisplayCountry())
		} else {
			tip += "\n" + IPWithCountry(s.IP, s.DisplayCountry())
		}
	}
	if s.DomainCountry != "" && s.Config.MenuBar != "icon" {
		tip += "\n" + T("country.domain_source")
	}
	if tip != t.lastTooltip {
		systray.SetTooltip(tip)
		t.lastTooltip = tip
	}
}

// HeadlessRender logs and notifies without a tray icon (zaslon headless).
func HeadlessRender(s guard.Snapshot, evs []guard.Event) {
	for _, e := range evs {
		message := logMessage(e)
		fmt.Println(e.At.Local().Format("15:04:05"), message)
		app.LogAt(e.At, message)
		if title, body, ok := Notification(e); ok && s.Config.Notifications {
			app.Notify(title, body)
		}
	}
	app.WriteState(app.State{
		Status: statusName(s), Line: StatusLine(s), IP: s.IP, Country: s.Country, DomainCountry: s.DomainCountry, IP6: s.IP6, Country6: s.Country6, MeasuredAt: s.MeasuredAt,
		Allowed: s.Allowed(), Apps: procs.AppNames(s.Running), Frozen: s.Frozen, Paused: s.Paused(),
	})
}

// OpenPanel starts `zaslon panel`, which shows the panel window.
func OpenPanel() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, "panel")
	cmd.Env = append(os.Environ(), "ZASLON_CHILD=1") // the panel needs no supervisor
	if cmd.Start() == nil {
		go func() { _ = cmd.Wait() }()
	}
}
