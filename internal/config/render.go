package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// CommentLang picks the language of the comments in config.yaml ("ru" or "en").
// main sets it from the detected UI language before the first Save.
var CommentLang = "ru"

type tpl struct {
	rules, trusted, dns string
	header, apps, appsList, custom, allow, ips, countries,
	domainInterval, interval, services, agree, ipv6, services6, menubar, update, theme, lang, notify string
}

var templates = map[string]tpl{
	"ru": {
		rules:   "# Свои правила для отдельных приложений вместо общих allow. Ключ - id из apps\n# или имя своего приложения. Пример:\n#   cursor:\n#     countries: [NL, DE, US]",
		trusted: "# Доверенные сети: здесь приложения работают без проверки IP (дом, офис).\n# Сеть узнаётся по её роутеру. Проще добавлять из панели Zaslon: «Доверять этой сети».",
		dns:     "# Утечка DNS (запросы к сайтам идут мимо VPN): warn - предупредить,\n# block - заморозить, как при чужом IP, off - не проверять.",
		header: "# Zaslon - настройки. Сохраните файл, и Zaslon подхватит изменения сам, перезапуск не нужен.\n" +
			"# Справка: https://github.com/avazar/zaslon/blob/dev/README.md",
		apps: "# Какие приложения защищать. Готовые: claude, chatgpt, codex, cursor, windsurf,\n" +
			"# copilot, gemini, perplexity, telegram, discord, slack, zoom.",
		appsList: "# Список и как их ищет Zaslon - в меню «Защищаемые приложения».",
		custom: "# Свои приложения. match - имя файла (myapp, myapp.exe) или часть пути (/MyApp.app/),\n" +
			"# для скриптов - часть командной строки с префиксом args: (args:my-cli.js).\n" +
			"# Пример:\n#   - name: My App\n#     match: [\"/MyApp.app/\", \"myapp.exe\"]",
		allow: "# Где приложениям можно работать. Подходит хоть что-то одно - значит можно.",
		ips:   "# IP или подсети: \"64.137.54.87\", \"64.137.54.0/24\"",
		countries: "# Коды стран: NL, DE, US. VPN часто меняет IP внутри страны -\n" +
			"# разрешите страну, и не придётся подтверждать каждый новый адрес.",
		domainInterval: "# Интервал проверок доменов запущенных приложений (не меньше 3s).",
		interval:       "# Как часто сверять внешний IP, когда всё в порядке (не меньше 3s).",
		services:       "# Откуда узнавать внешний IP. Можно поставить свой сервер, отдающий IP текстом.",
		agree:          "# Минимум совпадающих ответов об IP. Ответы собираются до завершения всех\n# запросов или общего тайм-аута; любое полученное расхождение запрещает возобновление.",
		ipv6:           "# Проверять и внешний IPv6. Многие VPN заворачивают только IPv4, а по IPv6\n# программы продолжают ходить напрямую с вашим настоящим адресом.",
		services6:      "# Откуда узнавать внешний IPv6.",
		menubar:        "# Что показывать рядом со значком (строка меню macOS, подсказка в Windows):\n# ip - страну и IP, country - только страну, icon - ничего (удобно на созвонах с показом экрана).",
		theme:          "# Тема панели: auto, light, dark.",
		lang:           "# Язык: auto, ru, en.",
		notify:         "# Показывать уведомления.",
	},
	"en": {
		rules:   "# Per-app rules instead of the shared allow list. The key is an id from apps\n# or a custom app's name. Example:\n#   cursor:\n#     countries: [NL, DE, US]",
		trusted: "# Trusted networks: apps run here without the IP check (home, office).\n# A network is recognised by its router. Easier from the Zaslon panel: \"Trust this network\".",
		dns:     "# DNS leaks (lookups bypass the VPN): warn - notify, block - freeze like a\n# foreign IP, off - don't check.",
		header: "# Zaslon settings. Save the file and Zaslon picks the changes up, no restart needed.\n" +
			"# Docs: https://github.com/avazar/zaslon/blob/dev/README.en.md#settings",
		apps: "# Which apps to protect. Built-in: claude, chatgpt, codex, cursor, windsurf,\n" +
			"# copilot, gemini, perplexity, telegram, discord, slack, zoom.",
		appsList: "# See the \"Protected apps\" menu for how each one is matched.",
		custom: "# Your own apps. match is a file name (myapp, myapp.exe) or part of a path (/MyApp.app/),\n" +
			"# for scripts - part of the command line prefixed with args: (args:my-cli.js).\n" +
			"# Example:\n#   - name: My App\n#     match: [\"/MyApp.app/\", \"myapp.exe\"]",
		allow: "# Where apps may run. Matching any one entry is enough.",
		ips:   "# IPs or subnets: \"64.137.54.87\", \"64.137.54.0/24\"",
		countries: "# Country codes: NL, DE, US. VPNs often rotate IPs within a country -\n" +
			"# allow the country so you don't have to confirm every new address.",
		domainInterval: "# Check service domains of running apps at this interval (3s minimum).",
		interval:       "# How often to re-check the public IP while everything is fine (3s minimum).",
		services:       "# Where to get the public IP from. Any server that returns the IP as plain text works.",
		agree:          "# Minimum matching IP responses. Collect until all requests finish or the shared\n# timeout expires; any received disagreement prevents resuming apps.",
		ipv6:           "# Check the public IPv6 too. Many VPNs only tunnel IPv4, and apps keep\n# going out over IPv6 with your real address.",
		services6:      "# Where to get the public IPv6 from.",
		menubar:        "# What to show next to the icon (macOS menu bar, Windows tooltip):\n# ip - country and IP, country - country only, icon - nothing (handy when sharing your screen).",
		theme:          "# Panel theme: auto, light, dark.",
		lang:           "# Language: auto, ru, en.",
		notify:         "# Show notifications.",
	},
}

func list(items []string) string {
	if len(items) == 0 {
		return " []"
	}
	var b strings.Builder
	for _, it := range items {
		b.WriteString("\n  - ")
		b.WriteString(strconv.Quote(it))
	}
	return b.String()
}

func indentList(items []string) string {
	if len(items) == 0 {
		return " []"
	}
	var b strings.Builder
	for _, it := range items {
		b.WriteString("\n    - ")
		b.WriteString(strconv.Quote(it))
	}
	return b.String()
}

func indent3(items []string) string {
	if len(items) == 0 {
		return " []"
	}
	var b strings.Builder
	for _, it := range items {
		b.WriteString("\n      - ")
		b.WriteString(strconv.Quote(it))
	}
	return b.String()
}

// Render writes the config as commented YAML.
func Render(c *Config) string {
	t, ok := templates[CommentLang]
	if !ok {
		t = templates["en"]
	}
	var custom strings.Builder
	if len(c.CustomApps) == 0 {
		custom.WriteString(" []")
	}
	for _, a := range c.CustomApps {
		fmt.Fprintf(&custom, "\n  - name: %s\n    match:", strconv.Quote(a.Name))
		custom.WriteString(indentList(a.Match))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", t.header)
	fmt.Fprintf(&b, "%s\n%s\napps:%s\n\n", t.apps, t.appsList, list(c.Apps))
	fmt.Fprintf(&b, "%s\ncustom_apps:%s\n\n", t.custom, custom.String())
	fmt.Fprintf(&b, "%s\nallow:\n  %s\n  ips:%s\n  %s\n  countries:%s\n\n",
		t.allow, t.ips, indentList(c.Allow.IPs), strings.ReplaceAll(t.countries, "\n", "\n  "), indentList(c.Allow.Countries))
	fmt.Fprintf(&b, "%s\napp_rules:", t.rules)
	if len(c.AppRules) == 0 {
		b.WriteString(" {}")
	}
	keys := make([]string, 0, len(c.AppRules))
	for k := range c.AppRules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a := c.AppRules[k]
		fmt.Fprintf(&b, "\n  %s:\n    ips:%s\n    countries:%s", strconv.Quote(k), indent3(a.IPs), indent3(a.Countries))
	}
	b.WriteString("\n\n")
	if CommentLang == "ru" {
		b.WriteString("# Списки доменов приложения. Включение задаётся отдельно в domain_checks_enabled.\n# Свой прокси приложения может дать другой маршрут.\n")
	} else {
		b.WriteString("# Editable app domain lists. Enable separately in domain_checks_enabled.\n# An app's own proxy may use a different route.\n")
	}
	b.WriteString("domain_checks:")
	if len(c.DomainChecks) == 0 {
		b.WriteString(" {}")
	}
	domainKeys := make([]string, 0, len(c.DomainChecks))
	for k := range c.DomainChecks {
		domainKeys = append(domainKeys, k)
	}
	sort.Strings(domainKeys)
	for _, k := range domainKeys {
		fmt.Fprintf(&b, "\n  %s:%s", strconv.Quote(k), indentList(c.DomainChecks[k]))
	}
	b.WriteString("\n\ndomain_checks_enabled:")
	if len(c.DomainChecksEnabled) == 0 {
		b.WriteString(" {}")
	}
	enabledKeys := make([]string, 0, len(c.DomainChecksEnabled))
	for k := range c.DomainChecksEnabled {
		enabledKeys = append(enabledKeys, k)
	}
	sort.Strings(enabledKeys)
	for _, k := range enabledKeys {
		fmt.Fprintf(&b, "\n  %s: %t", strconv.Quote(k), c.DomainChecksEnabled[k])
	}
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "%s\ntrusted_networks:", t.trusted)
	if len(c.TrustedNetworks) == 0 {
		b.WriteString(" []")
	}
	for _, n := range c.TrustedNetworks {
		fmt.Fprintf(&b, "\n  - name: %s\n    id: %s", strconv.Quote(n.Name), strconv.Quote(n.ID))
	}
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "%s\ncheck_interval: %s\n\n", t.interval, c.CheckInterval)
	fmt.Fprintf(&b, "%s\ndomain_check_interval: %s\n\n", t.domainInterval, c.DomainCheckInterval)
	fmt.Fprintf(&b, "%s\nip_services:%s\n\n", t.services, list(c.IPServices))
	fmt.Fprintf(&b, "%s\nmin_agree: %d\n\n", t.agree, c.MinAgree)
	fmt.Fprintf(&b, "%s\ncheck_ipv6: %t\n\n", t.ipv6, c.CheckIPv6)
	if CommentLang == "ru" {
		b.WriteString("# Нет результата IP (нет связи или недоступен сервис): suspend - приостановить,\n# ignore - продолжать с предупреждением, без подтверждения разрешённого выхода.\n")
	} else {
		b.WriteString("# IP result unavailable (offline or checker failure): suspend apps, or ignore\n# and continue with a warning, without proof that the exit is allowed.\n")
	}
	fmt.Fprintf(&b, "ip_unavailable_action: %s\n\n", c.IPUnavailableAction)
	if CommentLang == "ru" {
		b.WriteString("# IPv6 не удалось проверить: suspend или ignore. При ignore проверки продолжаются;\n# полученный запрещённый IPv6 или противоречие ответов всё равно приостанавливают.\n")
	} else {
		b.WriteString("# IPv6 result unavailable: suspend or ignore. Ignore keeps checking; a received\n# disallowed IPv6 or conflicting results still suspend apps.\n")
	}
	fmt.Fprintf(&b, "ipv6_unavailable_action: %s\n\n", c.IPv6UnavailableAction)
	fmt.Fprintf(&b, "%s\ndns_check: %s\n\n", t.dns, c.DNSCheck)
	fmt.Fprintf(&b, "%s\nipv6_services:%s\n\n", t.services6, list(c.IPv6Services))
	fmt.Fprintf(&b, "%s\nmenubar: %s\n\n", t.menubar, c.MenuBar)
	fmt.Fprintf(&b, "%s\nupdate_check: %t\n\n", t.update, c.UpdateCheck)
	fmt.Fprintf(&b, "%s\nlanguage: %s\n\n", t.lang, c.Language)
	fmt.Fprintf(&b, "%s\ntheme: %s\n\n", t.theme, c.Theme)
	fmt.Fprintf(&b, "%s\nnotifications: %t\n", t.notify, c.Notifications)
	return b.String()
}
