"use strict";

// Zaslon panel. Talks to the local Zaslon over /api; every value from it is
// escaped before it goes into the page (custom app names come from config.yaml).

const L = {
  ru: {
    confirm_title: "Подтвердите разрешение", confirm_accept: "Разрешить", confirm_cancel: "Отмена",
    confirm_ip: "Будет добавлен только указанный IP или диапазон. Другие адреса не добавляются.",
    confirm_country: "Будет разрешена указанная страна для IPv4 и IPv6. Другие страны не добавляются.",
    confirm_rule: "Эти разрешения заменят общие правила для приложения.",
    confirm_trust: "В этой сети проверки IP, доменов, IPv6 и DNS обходятся после успешного запроса IP. Добавляйте только сеть, в которой намеренно разрешаете прямой выход.",
    confirm_scope: "Общие разрешения",
    o_ip_unavailable: "Если IP не удалось определить", o_ip_unavailable_d: "Нет связи или не отвечает сервис проверки, включая домены приложения. Продолжение разрешает работу без подтверждения разрешённого выхода.",
    o_ipv6_unavailable: "Если IPv6 не удалось проверить", o_ipv6_unavailable_d: "Например, VPN блокирует IPv6. Проверки продолжатся; полученный запрещённый IPv6 или противоречащие ответы всё равно приостанавливают приложения.",
    failure_suspend: "Приостанавливать", failure_ignore: "Продолжать с предупреждением", warning_running: "работает с предупреждением",
    warning_offline: "IP не определён: сбой проигнорирован по настройке", warning_domain_unknown: "IP на домене не подтверждён: сбой проигнорирован по настройке", warning_v6unknown: "IPv6 не подтверждён: сбой проигнорирован по настройке", v6conflict: "Сервисы IPv6 сообщили разные адреса",
    parent_policy: "Процесс удерживается правилами другого приложения или родителя",
    domain_title: "IP на доменах приложения", domain_save: "Сохранить", domain_defaults: "Вернуть стандартные",
    domain_edit: "Редактировать домены", domain_cancel: "Отмена", domain_count: "Доменов", domain_host: "Домен", domain_checked: "Проверено",
    domain_off: "Проверки доменов выключены. Список сохранён.", domain_app_off: "Проверки начнутся после включения защиты приложения.", domain_required: "Добавьте хотя бы один домен перед включением проверок.",
    domain_unavailable: "Недоступен", domain_v6_disabled: "Проверка выключена", domain_v6_missing: "Не обнаружен", domain_stale: "Результат устарел",
    domain_hint: "По одному домену на строку. Сохранение списка не меняет переключатель. Измеряется соединение Zaslon: свой прокси приложения, другой API-адрес или правила VPN по процессам могут дать иной выход.",
    settings_changed: "Изменены правила защиты", country_unknown: "Страна выхода IPv4 не определена", country6_unknown: "Страна выхода IPv6 не определена",
    domain_unknown: "Не удалось проверить внешний IP приложения", domain_ip: "IP сервиса не разрешён", domain_wait: "Ожидается новая проверка", domain_v6_absent: "нет IPv6 у домена или проверка отключена",
    process_error: "ошибка защиты", ipv6_unknown: "Не удалось проверить IPv6",
    overview: "Обзор", apps: "Приложения", allow: "Разрешено", networks: "Сети", stats: "Статистика",
    history: "История", settings: "Настройки", about: "О программе",
    lead_overview: "Что сейчас с сетью и защищёнными приложениями",
    lead_apps: "Zaslon замораживает выбранные программы, когда сеть или IP не те. У каждой могут быть свои правила.",
    lead_allow: "Где приложениям можно работать. Подходит хоть что-то одно - значит можно.",
    lead_networks: "В доверенных сетях (дом, офис) приложения работают без проверки IP. Сеть узнаётся по её роутеру.",
    lead_stats: "Сколько раз Zaslon вмешивался за последние 14 дней",
    lead_history: "Последние события",
    lead_settings: "Изменения сохраняются сразу",
    country_domains: "По доменным проверкам", country_missing: "Страна не определена", ip: "Общий внешний IP", ipv6: "IPv6", dns: "DNS", network: "Сеть", none: "нет", offline: "IP не определён", checking: "проверяю…",
    ipv6_none: "IPv6 нет или он выключен", dns_ok: "идёт через VPN", dns_leak: "идёт мимо VPN", dns_unknown: "не удалось определить",
    trusted_net: "Доверенная сеть", usual_net: "Обычная сеть", unknown_net: "Роутер не виден",
    trust: "Доверять этой сети", allow_ip: "Разрешить этот IP", allow_country: "Разрешить страну", check: "Проверить",
    pause: "Пауза", pause15: "15 минут", pause60: "1 час", pauseF: "До перезапуска", unpause: "Снять паузу",
    others: "Другие сервисы видят", running: "запущено", not_running: "не запущено", frozen: "заморожено", blocked: "закрыто", ok: "работает",
    own_rules: "Свои разрешения", shared_rules: "Общие разрешения", rule_hint: "Действуют вместо общих разрешений. Пустой список ничего не разрешает.",
    permissions_title: "Разрешённые IP и страны", permissions_hint: "Эти IP, подсети и страны применяются и к обычной проверке IP, и к доменам приложения.",
    rule_source: "Использовать разрешения", shared_rules_hint: "Общий список со страницы «Разрешено». Его изменения применяются ко всем приложениям без собственных правил.", edit_shared_rules: "Открыть общие разрешения",
    domain_permissions_hint: "Полученные на доменах адреса проверяются по разрешениям из блока выше.",
    remove_rule: "Вернуть общие правила", custom: "Свои приложения", add_custom: "Добавить", custom_name: "Название", custom_match: "Имя файла или часть пути, через запятую",
    remove: "Удалить", ips: "IP и подсети", countries: "Страны", add: "Добавить", ip_ph: "64.137.54.87 или 64.137.54.0/24",
    country_ph: "Начните вводить страну", no_ips: "Нет разрешённых IP", no_countries: "Нет разрешённых стран",
    current_net: "Текущая сеть", router: "Роутер", net_name: "Название, например «Дом»", no_trusted: "Доверенных сетей пока нет",
    here: "вы здесь", rename: "Переименовать",
    s_saves: "возобновлений", s_freezes: "заморозок", s_blocks: "раз закрыл приложения", s_time: "в заморозке всего",
    legend_saves: "возобновлено", legend_blocks: "закрыто", legend_other: "заморожено", trusted_list: "Доверенные сети", session: "С запуска Zaslon",
    g_protect: "Защита", g_iface: "Интерфейс", g_system: "Система", g_files: "Файлы и помощь",
    o_ipv6: "Проверять IPv6", o_ipv6_d: "Ловит VPN, которые заворачивают только IPv4",
    o_dns: "Утечка DNS", o_dns_d: "Запросы к сайтам идут мимо VPN", dns_warn: "Предупреждать", dns_block: "Замораживать", dns_off: "Не проверять",
    o_interval: "Интервал проверки общего IP", o_interval_d: "Внешний IP этой сети", o_domain_interval: "Интервал проверки доменов", o_domain_interval_d: "Только для запущенных защищаемых приложений", o_agree: "Сервисов должны совпасть", o_agree_d: "Чтобы поверить IP",
    o_menubar: "Рядом со значком", mb_ip: "Страна и IP", mb_country: "Только страна", mb_icon: "Ничего",
    o_theme: "Тема панели", theme_light: "Светлая", theme_dark: "Тёмная", o_lang: "Язык", lang_auto: "Как в системе", o_notify: "Уведомления",
    o_autostart: "Запускать при входе в систему", o_update: "Проверять обновления", o_update_d: "Раз в сутки, ставятся только по клику",
    open_config: "Открыть config.yaml", open_log: "Открыть журнал", report: "Сообщить о проблеме", sec: "с",
    update_avail: "Доступна версия", update_btn: "Обновить", saved: "Сохранено", about_text: "Kill switch для приложений: замораживает выбранные программы, когда отваливается VPN или меняется IP. Открытый код, без телеметрии.",
    github: "Zaslon на GitHub",
    history_empty: "Пока ничего не случилось", paused_until: "Пауза до", paused_forever: "Пауза до перезапуска",
  },
  en: {
    confirm_title: "Confirm permission", confirm_accept: "Allow", confirm_cancel: "Cancel",
    confirm_ip: "Only the listed IP or range will be added. No other addresses are added.",
    confirm_country: "The listed country will be allowed for IPv4 and IPv6. No other countries are added.",
    confirm_rule: "These permissions will replace the shared rules for this app.",
    confirm_trust: "On this network, IP, domain, IPv6 and DNS rules are bypassed after a successful IP request. Add it only if you deliberately permit a direct connection there.",
    confirm_scope: "Shared permissions",
    o_ip_unavailable: "If the IP check is unavailable", o_ip_unavailable_d: "No connection or a failed checker, including app domains. Continuing permits apps without confirmation of the allowed exit.",
    o_ipv6_unavailable: "If IPv6 cannot be checked", o_ipv6_unavailable_d: "For example, the VPN blocks IPv6. Checks continue; a received disallowed IPv6 or conflicting responses still suspend apps.",
    failure_suspend: "Suspend apps", failure_ignore: "Continue with a warning", warning_running: "running with a warning",
    warning_offline: "IP unknown: failure ignored by your setting", warning_domain_unknown: "Service IP unconfirmed: failure ignored by your setting", warning_v6unknown: "IPv6 unconfirmed: failure ignored by your setting", v6conflict: "IPv6 services returned conflicting addresses",
    parent_policy: "Another matching app or parent policy holds this process",
    domain_title: "IP seen on app domains", domain_save: "Save", domain_defaults: "Restore defaults",
    domain_edit: "Edit domains", domain_cancel: "Cancel", domain_count: "Domains", domain_host: "Domain", domain_checked: "Checked",
    domain_off: "Domain checks are off. Your list is saved.", domain_app_off: "Checks start when protection is enabled for this app.", domain_required: "Add at least one domain before enabling checks.",
    domain_unavailable: "Unavailable", domain_v6_disabled: "Check disabled", domain_v6_missing: "Not detected", domain_stale: "Result expired",
    domain_hint: "One domain per line. Saving the list does not change the switch. This measures Zaslon's connection: an app's own proxy, another API address or per-process VPN routing may use a different exit.",
    settings_changed: "Protection settings changed", country_unknown: "IPv4 exit country unknown", country6_unknown: "IPv6 exit country unknown",
    domain_unknown: "App’s public IP could not be verified", domain_ip: "Service IP not allowed", domain_wait: "Waiting for a fresh check", domain_v6_absent: "no service IPv6 or check disabled",
    process_error: "protection error", ipv6_unknown: "IPv6 check inconclusive",
    overview: "Overview", apps: "Apps", allow: "Allowed", networks: "Networks", stats: "Statistics",
    history: "History", settings: "Settings", about: "About",
    lead_overview: "Your network and protected apps right now",
    lead_apps: "Zaslon freezes the chosen apps when the network or IP isn't right. Each one can have its own rules.",
    lead_allow: "Where apps may run. Matching any one entry is enough.",
    lead_networks: "On trusted networks (home, office) apps run without the IP check. A network is recognised by its router.",
    lead_stats: "How often Zaslon stepped in over the last 14 days",
    lead_history: "Recent events",
    lead_settings: "Changes are saved right away",
    country_domains: "From service checks", country_missing: "Country unknown", ip: "General public IP", ipv6: "IPv6", dns: "DNS", network: "Network", none: "none", offline: "IP unknown", checking: "checking…",
    ipv6_none: "No IPv6, or it's off", dns_ok: "goes through the VPN", dns_leak: "bypasses the VPN", dns_unknown: "couldn't tell",
    trusted_net: "Trusted network", usual_net: "Regular network", unknown_net: "Router not visible",
    trust: "Trust this network", allow_ip: "Allow this IP", allow_country: "Allow country", check: "Check",
    pause: "Pause", pause15: "15 minutes", pause60: "1 hour", pauseF: "Until restart", unpause: "Resume",
    others: "Other services see", running: "running", not_running: "not running", frozen: "frozen", blocked: "closed", ok: "running",
    own_rules: "App permissions", shared_rules: "Shared permissions", rule_hint: "Replace the shared permissions for this app. An empty list permits no exit.",
    permissions_title: "Allowed IPs and countries", permissions_hint: "These IPs, subnets and countries apply to both the general IP check and this app's domains.",
    rule_source: "Use permissions", shared_rules_hint: "The shared list from the Allowed page. Changes apply to every app without its own permissions.", edit_shared_rules: "Open shared permissions",
    domain_permissions_hint: "Addresses seen on these domains are checked against the permissions above.",
    remove_rule: "Use shared rules", custom: "Your apps", add_custom: "Add", custom_name: "Name", custom_match: "File name or part of the path, comma-separated",
    remove: "Remove", ips: "IPs and subnets", countries: "Countries", add: "Add", ip_ph: "64.137.54.87 or 64.137.54.0/24",
    country_ph: "Start typing a country", no_ips: "No allowed IPs", no_countries: "No allowed countries",
    current_net: "Current network", router: "Router", net_name: "Name, e.g. \"Home\"", no_trusted: "No trusted networks yet",
    here: "you're here", rename: "Rename",
    s_saves: "resumes", s_freezes: "freezes", s_blocks: "times apps were closed", s_time: "spent frozen",
    legend_saves: "resumed", legend_blocks: "closed", legend_other: "frozen", trusted_list: "Trusted networks", session: "Since Zaslon started",
    g_protect: "Protection", g_iface: "Interface", g_system: "System", g_files: "Files and help",
    o_ipv6: "Check IPv6", o_ipv6_d: "Catches VPNs that tunnel IPv4 only",
    o_dns: "DNS leaks", o_dns_d: "Lookups bypass the VPN", dns_warn: "Warn", dns_block: "Freeze", dns_off: "Don't check",
    o_interval: "Public IP check interval", o_interval_d: "External IP of this network", o_domain_interval: "Service domain check interval", o_domain_interval_d: "Only for running protected apps", o_agree: "Services must agree", o_agree_d: "To trust an IP",
    o_menubar: "Next to the icon", mb_ip: "Country and IP", mb_country: "Country only", mb_icon: "Nothing",
    o_theme: "Panel theme", theme_light: "Light", theme_dark: "Dark", o_lang: "Language", lang_auto: "System", o_notify: "Notifications",
    o_autostart: "Start at login", o_update: "Check for updates", o_update_d: "Once a day, installed only when you click",
    open_config: "Open config.yaml", open_log: "Open log", report: "Report a problem", sec: "s",
    update_avail: "Version available:", update_btn: "Update", saved: "Saved", about_text: "A kill switch for apps: freezes the apps you choose when the VPN drops or your IP changes. Open source, no telemetry.",
    github: "Zaslon on GitHub",
    history_empty: "Nothing has happened yet", paused_until: "Paused until", paused_forever: "Paused until restart",
  },
};

const ICONS = {
  overview: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  apps: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  allow: '<path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/>',
  networks: '<path d="M2 9a15 15 0 0120 0"/><path d="M5.5 12.5a10 10 0 0113 0"/><path d="M9 16a5 5 0 016 0"/><circle cx="12" cy="19.5" r="1"/>',
  stats: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
  history: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 110-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 114 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z"/>',
  about: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5v.5"/>',
  check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
  snow: '<path d="M12 2v20M4.9 7l14.2 10M4.9 17L19.1 7"/>',
  stop: '<path d="M6 6l12 12M18 6L6 18"/>',
  pause: '<path d="M9 5v14M15 5v14"/>',
  warning: '<path d="M12 3L2 21h20L12 3zM12 9v5M12 17v1"/>',
};
const svg = (name) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${ICONS[name]}</svg>`;
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const PAGES = ["overview", "apps", "allow", "networks", "stats", "history", "settings", "about"];
let S = null; // last state
let page = (location.hash || "#overview").slice(1);
let countries = [];
let openAppSettings = null;
let openDomains = null;
const domainDrafts = new Map();
let lastJSON = "";
let deferredJSON = "";
let refreshID = 0, receivedID = 0;
const t = (k) => (L[S?.lang] || L.ru)[k] || L.en[k] || k;

async function api(op, data = {}) {
  return ZaslonPermissions.perform(op, data, S, confirmPermission, send);
}

function confirmPermission(grant) {
  const overlay = document.getElementById("permissionConfirm");
  // Do not replace the text of an earlier, still-pending confirmation.
  if (!overlay.hidden) return Promise.resolve(false);
  const cancel = document.getElementById("permissionCancel");
  const accept = document.getElementById("permissionAccept");
  const scope = grant.scope || t("confirm_scope");
  const kind = grant.op === "trust_network" ? "trust" : grant.op === "set_rule" ? "rule" : grant.op === "add_country" ? "country" : "ip";
  document.getElementById("permissionTitle").textContent = t("confirm_title");
  document.getElementById("permissionDetail").textContent = t("confirm_" + kind);
  document.getElementById("permissionValues").textContent = kind === "trust" ? grant.network
    : [scope, grant.value, ...grant.ips, ...grant.countries].filter(Boolean).join("\n");
  cancel.textContent = t("confirm_cancel");
  accept.textContent = t("confirm_accept");
  overlay.hidden = false;
  const previous = document.activeElement;
  return new Promise((resolve) => {
    const finish = (ok) => {
      overlay.hidden = true;
      cancel.onclick = accept.onclick = overlay.onclick = null;
      document.removeEventListener("keydown", escape);
      previous?.focus();
      resolve(ok);
    };
    const escape = (e) => {
      if (e.key === "Escape") { e.preventDefault(); finish(false); }
      if (e.key === "Tab") {
        e.preventDefault();
        (document.activeElement === cancel ? accept : cancel).focus();
      }
    };
    cancel.onclick = () => finish(false);
    accept.onclick = () => finish(true);
    overlay.onclick = (e) => { if (e.target === overlay) finish(false); };
    document.addEventListener("keydown", escape);
    cancel.focus();
  });
}

async function send(op, data = {}) {
  const r = await fetch("/api/do", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ op, ...data }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    toast(j.error || r.statusText);
    return false;
  }
  await refresh(true);
  return true;
}

let toastTimer;
function toast(msg) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.hidden = true), 3500);
}

function country(c) {
  if (!c) return "";
  return S.goos === "windows" ? `${esc(c.name)} (${esc(c.code)})` : `${esc(c.flag)} ${esc(c.name)}`;
}

function fmtDur(sec) {
  sec = Math.round(sec || 0);
  const en = S.lang === "en";
  if (sec < 60) return `${sec} ${t("sec")}`;
  const m = Math.floor(sec / 60), h = Math.floor(m / 60);
  if (!h) return `${m} ${en ? "min" : "мин"}`;
  return `${h} ${en ? "h" : "ч"} ${m % 60} ${en ? "min" : "мин"}`;
}

// ---------- pages ----------

function heroActions() {
  const a = [];
  if (S.paused) return `<button class="btn primary" data-op="unpause">${t("unpause")}</button>`;
  if (S.ip && !S.allowedNow && (S.reason === "ip" || S.reason === "v6")) {
    a.push(`<button class="btn primary" data-op="allow_current_ip">${t("allow_ip")}</button>`);
    if (S.country) a.push(`<button class="btn" data-op="allow_current_country">${t("allow_country")}: ${country(S.country)}</button>`);
  }
  a.push(`<button class="btn" data-op="check_now">${t("check")}</button>`);
  a.push(`<select class="btn" id="pauseSel"><option value="">${t("pause")}…</option><option value="15">${t("pause15")}</option><option value="60">${t("pause60")}</option><option value="0">${t("pauseF")}</option></select>`);
  return a.join("");
}

function heroSub(state = S) {
  if (state.status === "error") return (state.errors || []).map(esc).join("<br>");
  if (state.paused) return state.pausedUntil === "forever" ? t("paused_forever") : `${t("paused_until")} ${esc(state.pausedUntil)}`;
  const frozen = state.apps.filter((a) => a.frozen > 0).map((a) => esc(a.name));
  const running = state.apps.filter((a) => a.running && !a.frozen).map((a) => esc(a.name));
  return [
    frozen.length && `${frozen.join(", ")} · ${t("frozen")}`,
    running.length && `${running.join(", ")} · ${t("running")}`,
    ...(state.warnings || []).map((w) => `${(w.apps || []).map(esc).join(", ")}: ${esc(t("warning_" + w.reason))}`),
  ].filter(Boolean).join("<br>");
}

const heroIcon = (status) => ({ ok: "check", warning: "warning", frozen: "snow", starting: "snow", blocked: "stop", error: "stop", paused: "pause" })[status];

function overview() {
  const upd = S.update ? `<div class="banner"><b>${t("update_avail")} ${esc(S.update)}</b><span class="grow"></span><button class="btn primary" data-op="install_update">${t("update_btn")}</button></div>` : "";
  const ipV = S.offline ? t("offline") : S.ip ? esc(S.ip) : t("checking");
  const ipCountry = S.country ? country(S.country) : S.domainCountry ? country(S.domainCountry) + " · " + t("country_domains") : S.ip ? t("country_missing") : "";
  const others = S.others && S.others.length ? `<div class="s">${t("others")}: ${S.others.map(esc).join(", ")}</div>` : "";
  const dnsTile = S.dns
    ? `<div class="card tile ${S.dnsLeak ? "warn" : ""}"><div class="k">${t("dns")}</div><div class="v">${esc(S.dns)}</div><div class="s">${country(S.dnsCountry)} · ${S.dnsLeak ? t("dns_leak") : t("dns_ok")}</div></div>`
    : `<div class="card tile"><div class="k">${t("dns")}</div><div class="v">-</div><div class="s">${t("dns_unknown")}</div></div>`;
  const netTile = S.network
    ? `<div class="card tile"><div class="k">${t("network")}</div><div class="v">${esc(S.network)}</div><div class="s">${t("trusted_net")}</div></div>`
    : `<div class="card tile"><div class="k">${t("network")}</div><div class="v">${S.netId ? t("usual_net") : t("unknown_net")}</div>${S.netId ? `<div class="s selectable">${t("router")} ${esc(S.netId)}</div><div class="row"><button class="btn small" data-go="networks">${t("trust")}…</button></div>` : ""}</div>`;
  return `${upd}
  <div class="card hero ${S.status}">
    <div class="orb">${svg(heroIcon(S.status))}</div>
    <div><div class="title">${esc(S.statusText)}</div><div class="sub">${heroSub()}</div></div>
    <div class="actions">${heroActions()}</div>
  </div>
  <div class="grid">
    <div class="card tile"><div class="k">${t("ip")}</div><div class="v selectable">${ipV}</div><div class="s">${ipCountry}</div>${others}</div>
    <div class="card tile ${S.reason === "v6" || S.ipv6Unknown || S.ipv6Conflicting ? "warn" : ""}"><div class="k">${t("ipv6")}</div><div class="v selectable">${S.ip6 ? esc(S.ip6) : "-"}</div><div class="s">${S.ipv6Conflicting ? t("v6conflict") : S.ip6 ? country(S.country6) : S.ipv6Unknown ? t("ipv6_unknown") : t("ipv6_none")}</div></div>
    ${dnsTile}
    ${netTile}
  </div>
  <h2>${t("stats")}</h2>
  ${statsNumbers()}`;
}

function ruleEditor(app) {
  const own = !!app.rule, r = app.rule || S.allow;
  const shared = `<div class="shared-rule-summary"><div class="k">${t("countries")}</div><div class="chips">${r.countries.length ? r.countries.map((c) => `<span class="chip">${country(c)}</span>`).join("") : `<span class="empty">${t("no_countries")}</span>`}</div>
    <div class="k">${t("ips")}</div><div class="chips">${r.ips.length ? r.ips.map((ip) => `<span class="chip selectable">${esc(ip)}</span>`).join("") : `<span class="empty">${t("no_ips")}</span>`}</div>
    <button class="btn small" data-go="allow">${t("edit_shared_rules")}</button></div>`;
  return `<section class="app-permissions"><h3>${t("permissions_title")}</h3><p class="hint">${t("permissions_hint")}</p>
    <div class="rule-source"><label for="rule-source-${encodeURIComponent(app.id)}">${t("rule_source")}</label>
    <select id="rule-source-${encodeURIComponent(app.id)}" data-rule-source="${esc(app.id)}"><option value="shared" ${!own ? "selected" : ""}>${t("shared_rules")}</option><option value="own" ${own ? "selected" : ""}>${t("own_rules")}</option></select></div>
    <p class="hint">${t(own ? "rule_hint" : "shared_rules_hint")}</p>
    ${own ? allowEditor(r, app.id) : shared}</section>`;
}

function appSettings(a) {
  return `<section class="app-settings" id="app-settings-${encodeURIComponent(a.id)}" aria-labelledby="app-settings-button-${encodeURIComponent(a.id)}">${ruleEditor(a)}${domainSection(a)}</section>`;
}

// A steady colour per app name, so the list is easy to scan.
function avatarStyle(name) {
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) % 360;
  return `background:hsl(${h} 60% 50% / .16);color:hsl(${h} 55% 45%)`;
}

function appRow(a) {
  const status = a.status === "error" ? "error" : a.frozen > 0 ? "frozen" : a.status === "warning" ? "warning" : "ok";
  const st = !a.running && !a.frozen ? `<span class="badge">${t("not_running")}</span>`
    : `<span class="badge ${status}">${t(status === "error" ? "process_error" : status === "warning" ? "warning_running" : status)}</span>`;
  const expanded = openAppSettings === a.id;
  const settingsButton = `<button class="btn small" id="app-settings-button-${encodeURIComponent(a.id)}" data-app-settings="${esc(a.id)}" aria-expanded="${expanded}" aria-controls="app-settings-${encodeURIComponent(a.id)}" aria-label="${esc(t("settings") + ": " + a.name)}">${t("settings")} <span aria-hidden="true">${expanded ? "▴" : "▾"}</span></button>`;
  const toggle = a.custom
    ? `<button class="btn small danger" data-op="remove_custom" data-app="${esc(a.id)}">${t("remove")}</button>`
    : `<label class="switch"><input type="checkbox" data-toggle="${esc(a.id)}" ${a.enabled ? "checked" : ""}><span></span></label>`;
  const meta = a.custom ? esc((a.match || []).join(", ")) : (a.enabled ? st : "");
  const avatar = a.custom
    ? `<div class="avatar" aria-hidden="true" style="${avatarStyle(a.name)}">${esc(a.name[0])}</div>`
    : `<div class="avatar"><img class="app-logo" src="icons/apps/${encodeURIComponent(a.id)}.svg" alt=""></div>`;
  return `<div class="item">${avatar}
    <div><div class="name">${esc(a.name)}</div><div class="meta">${meta}</div></div>
    <div class="end">${a.custom ? st : ""}${settingsButton}${toggle}</div></div>
    ${expanded ? appSettings(a) : ""}`;
}

function domainHost(endpoint) {
  try { return new URL(endpoint).host; } catch (_) { return endpoint; }
}

function editableDomains(endpoints) {
  return (endpoints || []).map((s) => s.startsWith("https://") ? domainHost(s) : s).join("\n");
}

function domainEditor(a) {
  const draft = domainDrafts.has(a.id) ? domainDrafts.get(a.id) : editableDomains(a.domains);
  return `<div class="domain-editor"><label for="domains-${encodeURIComponent(a.id)}">${t("domain_edit")}</label>
    <textarea id="domains-${encodeURIComponent(a.id)}" data-domains="${esc(a.id)}" rows="3" spellcheck="false">${esc(draft)}</textarea>
    <div class="domain-editor-actions"><button class="btn small primary" data-save-domains="${esc(a.id)}">${t("domain_save")}</button>
    <button class="btn small" data-cancel-domains="${esc(a.id)}">${t("domain_cancel")}</button>
    ${(a.defaultDomains || []).length ? `<button class="btn small" data-default-domains="${esc(a.id)}">${t("domain_defaults")}</button>` : ""}</div>
    <p class="hint">${t("domain_hint")}</p></div>`;
}

function domainSection(a) {
  const on = a.domainChecksEnabled;
  const hint = on && !a.enabled ? t("domain_app_off") : !on ? t("domain_off") : "";
  return `<section class="domain-section" aria-label="${esc(t("domain_title") + ": " + a.name)}">
    <div class="domain-controls"><div><div class="domain-heading">${t("domain_title")}</div><div class="domain-meta">${t("domain_count")}: ${(a.domains || []).length}</div></div>
    <div class="domain-actions"><button class="btn small" data-edit-domains="${esc(a.id)}" aria-expanded="${openDomains === a.id}">${t("domain_edit")}</button>
    <label class="switch"><input type="checkbox" data-domain-toggle="${esc(a.id)}" aria-label="${esc(t("domain_title") + ": " + a.name)}" ${on ? "checked" : ""}><span></span></label></div></div>
    <p class="hint">${t("domain_permissions_hint")}</p>
    ${hint ? `<div class="hint">${hint}</div>` : ""}
    ${openDomains === a.id ? domainEditor(a) : ""}
    ${on && a.enabled ? domainResults(a) : ""}</section>`;
}

function domainResults(a) {
  const results = a.measurements || [];
  const cell = (d, v6) => {
    if (v6 && !S.settings.check_ipv6) return `<span class="measurement-muted">${t("domain_v6_disabled")}</span>`;
    if (!d) return `<span class="measurement-muted">${t("domain_wait")}</span>`;
    const error = v6 ? d.ipv6Error : d.error, ip = v6 ? d.ip6 : d.ip, cc = v6 ? d.country6 : d.country;
    if (error) return `<span class="measurement-error" title="${esc(error)}">${t("domain_unavailable")}</span>`;
    if (!ip) return `<span class="measurement-muted">${v6 ? t("domain_v6_missing") : "—"}</span>`;
    return `<code class="selectable">${esc(ip)}</code>${cc ? `<span class="measurement-country">${esc(cc)}</span>` : ""}`;
  };
  return `${a.domainIssue ? `<div class="hint">${esc(a.domainIssue)}</div>` : ["domain_unknown", "domain_ip", "parent_policy", "settings_changed", "country_unknown", "country6_unknown"].includes(a.reason) ? `<div class="hint">${t(a.reason)}</div>` : ""}
    <div class="domain-table-wrap" tabindex="0" role="region" aria-label="${esc(t("domain_title") + ": " + a.name)}"><table class="domain-table">
    <colgroup><col class="domain-col-host"><col class="domain-col-ip"><col class="domain-col-ip"><col class="domain-col-time"></colgroup>
    <thead><tr><th scope="col">${t("domain_host")}</th><th scope="col">IPv4</th><th scope="col">IPv6</th><th scope="col">${t("domain_checked")}</th></tr></thead><tbody>
    ${(a.domains || []).map((endpoint) => {
      const d = results.find((x) => x.endpoint === endpoint), date = new Date(d?.checkedAt);
      const validDate = Number.isFinite(date.getTime()), stale = validDate && Date.now() - date.getTime() >= 30000;
      return `<tr class="${stale ? "measurement-stale" : ""}"><th scope="row" title="${esc(endpoint)}">${esc(domainHost(endpoint))}</th>
        <td>${cell(d, false)}</td><td>${cell(d, true)}</td><td class="measurement-time">${validDate ? `<time datetime="${esc(date.toISOString())}" title="${esc(stale ? t("domain_stale") : date.toLocaleString())}">${esc(date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }))}</time>` : "—"}</td></tr>`;
    }).join("")}</tbody></table></div>`;
}

function apps() {
  const pre = S.apps.filter((a) => !a.custom), cus = S.apps.filter((a) => a.custom);
  pre.sort((a, b) => (b.enabled - a.enabled) || a.name.localeCompare(b.name));
  return `<div class="card list">${pre.map(appRow).join("")}</div>
  <h2>${t("custom")}</h2>
  <div class="card list">${cus.map(appRow).join("")}
    <div class="item"><div class="add" style="flex:1;margin:0">
      <input id="cName" placeholder="${t("custom_name")}" style="max-width:180px">
      <input id="cMatch" placeholder="${t("custom_match")}">
      <button class="btn" id="cAdd">${t("add_custom")}</button></div></div>
  </div>`;
}

function allowEditor(r, app = "") {
  const ips = r.ips.length ? r.ips.map((ip) => `<span class="chip selectable">${esc(ip)}<button title="${t("remove")}" data-op="remove_ip" data-app="${esc(app)}" data-value="${esc(ip)}">×</button></span>`).join("") : `<div class="empty">${t("no_ips")}</div>`;
  const cs = r.countries.length ? r.countries.map((c) => `<span class="chip">${country(c)}<button title="${t("remove")}" data-op="remove_country" data-app="${esc(app)}" data-value="${esc(c.code)}">×</button></span>`).join("") : `<div class="empty">${t("no_countries")}</div>`;
  const opts = countries.map((c) => `<option value="${esc(c.name)} (${esc(c.code)})">`).join("");
  return `<div class="k" style="margin-top:6px">${t("countries")}</div><div class="chips">${cs}</div>
    <div class="add"><input list="cl-${esc(app)}" data-addc="${esc(app)}" placeholder="${t("country_ph")}"><datalist id="cl-${esc(app)}">${opts}</datalist><button class="btn" data-addcbtn="${esc(app)}">${t("add")}</button></div>
    <div class="k" style="margin-top:14px">${t("ips")}</div><div class="chips">${ips}</div>
    <div class="add"><input data-addip="${esc(app)}" placeholder="${t("ip_ph")}"><button class="btn" data-addipbtn="${esc(app)}">${t("add")}</button></div>`;
}

function allow() {
  return `<div class="card pad">${allowEditor(S.allow)}</div>`;
}

function networks() {
  const list = (S.trusted || []).map((n) => `<div class="item"><div class="avatar">${svg("networks")}</div>
    <div><div class="name">${esc(n.name)} ${n.current ? `<span class="badge ok">${t("here")}</span>` : ""}</div><div class="meta selectable">${t("router")} ${esc(n.id)}</div></div>
    <div class="end"><button class="btn small" data-rename="${esc(n.id)}" data-name="${esc(n.name)}">${t("rename")}</button><button class="btn small danger" data-op="untrust_network" data-value="${esc(n.id)}">${t("remove")}</button></div></div>`).join("");
  const cur = S.network ? "" : `<h2>${t("current_net")}</h2><div class="card pad">${S.netId
    ? `<div class="meta selectable">${t("router")} ${esc(S.netId)}</div><div class="add"><input id="netName" placeholder="${t("net_name")}"><button class="btn primary" id="trustBtn">${t("trust")}</button></div>`
    : `<div class="empty">${t("unknown_net")}</div>`}</div>`;
  return `${cur}<h2>${t("trusted_list")}</h2><div class="card list">${list || `<div class="item"><div class="empty">${t("no_trusted")}</div></div>`}</div>`;
}

function statsNumbers() {
  const tot = S.stats.days.reduce((a, d) => ({ saves: a.saves + d.saves, freezes: a.freezes + d.freezes, blocks: a.blocks + d.blocks, sec: a.sec + d.frozen_seconds }), { saves: 0, freezes: 0, blocks: 0, sec: 0 });
  return `<div class="stats">
    <div class="card stat"><div class="n">${tot.saves}</div><div class="l">${t("s_saves")}</div></div>
    <div class="card stat"><div class="n">${tot.freezes}</div><div class="l">${t("s_freezes")}</div></div>
    <div class="card stat"><div class="n">${tot.blocks}</div><div class="l">${t("s_blocks")}</div></div>
    <div class="card stat"><div class="n">${fmtDur(tot.sec)}</div><div class="l">${t("s_time")}</div></div>
  </div>`;
}

function chart() {
  const days = S.stats.days;
  const max = Math.max(1, ...days.map((d) => d.saves + d.blocks + Math.max(0, d.freezes - d.saves - d.blocks)));
  const W = 700, H = 150, bw = W / days.length;
  const bars = days.map((d, i) => {
    const x = i * bw + bw * 0.2, w = bw * 0.6;
    const other = Math.max(0, d.freezes - d.saves - d.blocks);
    const hs = (d.saves / max) * (H - 24), hb = (d.blocks / max) * (H - 24), ho = (other / max) * (H - 24);
    let y = H - 20;
    const seg = (h, c) => { if (h <= 0) return ""; y -= h; return `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="3" fill="${c}"/>`; };
    const label = d.date.slice(8) + "." + d.date.slice(5, 7);
    return seg(hs, "var(--ok)") + seg(hb, "var(--bad)") + seg(ho, "var(--warn)") +
      `<text x="${x + w / 2}" y="${H - 4}" text-anchor="middle" font-size="10" fill="var(--muted)">${label}</text>`;
  }).join("");
  return `<div class="card chart"><svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">${bars}<line x1="0" x2="${W}" y1="${H - 20}" y2="${H - 20}" stroke="var(--line)"/></svg>
    <div class="legend"><span><i style="background:var(--ok)"></i>${t("legend_saves")}</span><span><i style="background:var(--bad)"></i>${t("legend_blocks")}</span><span><i style="background:var(--warn)"></i>${t("legend_other")}</span></div></div>`;
}

function stats() {
  const s = S.stats.session;
  return `${statsNumbers()}<h2>14 ${S.lang === "en" ? "days" : "дней"}</h2>${chart()}
    <h2>${t("session")}</h2><div class="card pad">${t("s_freezes")}: <b>${s.Freezes}</b> · ${t("legend_saves")}: <b>${s.Saves}</b> · ${t("legend_blocks")}: <b>${s.Blocks}</b> · ${t("s_time")}: <b>${fmtDur(s.FrozenSeconds)}</b></div>`;
}

function history() {
  if (!S.history || !S.history.length) return `<div class="card pad empty">${t("history_empty")}</div>`;
  return `<div class="card list hist">${S.history.map((h) => {
    const row = `<span class="dot ${esc(h.kind)}" aria-hidden="true"></span><span class="time">${esc(h.date)} ${esc(h.time)}</span><span class="hist-body selectable">${esc(h.text)}</span>`;
    if (!h.details?.length) return `<div class="hist-row">${row}</div>`;
    return `<details data-event="${esc(h.id)}"><summary class="hist-row">${row}</summary><ul class="selectable">${h.details.map(d => `<li>${esc(d)}</li>`).join("")}</ul></details>`;
  }).join("")}</div>`;
}

function toggleSet(key, title, desc, value) {
  return `<div class="set"><div class="txt"><b>${title}</b>${desc ? `<span>${desc}</span>` : ""}</div><label class="switch"><input type="checkbox" data-set="${key}" ${value ? "checked" : ""}><span></span></label></div>`;
}
function numSet(key, title, desc, value, unit = t("sec")) {
  return `<div class="set"><div class="txt"><b>${title}</b><span>${desc}</span></div><div class="field"><input type="number" min="${key === "min_agree" ? 1 : 3}" data-num="${key}" value="${value}"> ${unit}</div></div>`;
}
function selSet(key, title, desc, value, opts) {
  return `<div class="set"><div class="txt"><b>${title}</b>${desc ? `<span>${desc}</span>` : ""}</div><div class="field"><select data-sel="${key}">${opts.map(([v, l]) => `<option value="${v}" ${v === value ? "selected" : ""}>${l}</option>`).join("")}</select></div></div>`;
}

function settings() {
  const s = S.settings;
  return `<h2>${t("g_protect")}</h2><div class="card">
    ${toggleSet("check_ipv6", t("o_ipv6"), t("o_ipv6_d"), s.check_ipv6)}
    ${selSet("ip_unavailable_action", t("o_ip_unavailable"), t("o_ip_unavailable_d"), s.ip_unavailable_action, [["suspend", t("failure_suspend")], ["ignore", t("failure_ignore")]])}
    ${selSet("ipv6_unavailable_action", t("o_ipv6_unavailable"), t("o_ipv6_unavailable_d"), s.ipv6_unavailable_action, [["suspend", t("failure_suspend")], ["ignore", t("failure_ignore")]])}
    ${selSet("dns_check", t("o_dns"), t("o_dns_d"), s.dns_check, [["warn", t("dns_warn")], ["block", t("dns_block")], ["off", t("dns_off")]])}
    ${numSet("check_interval", t("o_interval"), t("o_interval_d"), s.check_interval)}
    ${numSet("domain_check_interval", t("o_domain_interval"), t("o_domain_interval_d"), s.domain_check_interval)}
    ${numSet("min_agree", t("o_agree"), t("o_agree_d"), s.min_agree, "")}
  </div>
  <h2>${t("g_iface")}</h2><div class="card">
    ${selSet("menubar", t("o_menubar"), "", s.menubar, [["ip", t("mb_ip")], ["country", t("mb_country")], ["icon", t("mb_icon")]])}
    ${selSet("theme", t("o_theme"), "", s.theme, [["auto", t("lang_auto")], ["light", t("theme_light")], ["dark", t("theme_dark")]])}
    ${selSet("language", t("o_lang"), "", s.language, [["auto", t("lang_auto")], ["ru", "Русский"], ["en", "English"]])}
    ${toggleSet("notifications", t("o_notify"), "", s.notifications)}
  </div>
  <h2>${t("g_system")}</h2><div class="card">
    <div class="set"><div class="txt"><b>${t("o_autostart")}</b></div><label class="switch"><input type="checkbox" id="autostart" ${S.autostart ? "checked" : ""}><span></span></label></div>
    ${toggleSet("update_check", t("o_update"), t("o_update_d"), s.update_check)}
  </div>
  <h2>${t("g_files")}</h2><div class="card pad" style="display:flex;gap:8px;flex-wrap:wrap">
    <button class="btn" data-op="open_config">${t("open_config")}</button>
    <button class="btn" data-op="open_log">${t("open_log")}</button>
    <button class="btn" data-op="report">${t("report")}</button>
  </div>`;
}

function about() {
  return `<div class="card about"><img src="icon.png" alt=""><div class="big">Zaslon ${esc(S.version)}</div>
    <p>${t("about_text")}</p>
    <div class="links"><button class="btn" data-url="https://github.com/avazar/zaslon">${t("github")}</button><button class="btn" data-url="https://github.com/avazar/zaslon/blob/dev/LICENSE">MIT License</button></div></div>`;
}

const RENDER = { overview, apps, allow, networks, stats, history, settings, about };

function nav(state = S) {
  const bad = ["frozen", "blocked", "error", "warning"].includes(state.status);
  document.getElementById("nav").innerHTML = PAGES.map((p) =>
    `<button type="button" data-go="${p}"${p === page ? ' class="on" aria-current="page"' : ""}>${svg(p)}<span>${t(p)}</span>${p === "overview" && bad ? `<span class="badge ${state.status}">!</span>` : ""}</button>`).join("");
  document.getElementById("ver").textContent = state.version;
}

function render() {
  if (!PAGES.includes(page)) page = "overview";
  document.documentElement.lang = S.lang;
  nav();
  const main = document.getElementById("main");
  main.dataset.page = page;
  const keep = main.scrollTop;
  const expanded = page === "history" ? new Set(Array.from(main.querySelectorAll("details[data-event][open]"), el => el.dataset.event)) : null;
  const focused = page === "history" && document.activeElement?.closest("details[data-event]")?.dataset.event;
  main.innerHTML = `<div class="page"><h1>${t(page)}</h1><p class="lead">${t("lead_" + page) === "lead_" + page ? "" : t("lead_" + page)}</p>${RENDER[page]()}</div>`;
  if (expanded) {
    for (const el of main.querySelectorAll("details[data-event]")) {
      el.open = expanded.has(el.dataset.event);
      if (el.dataset.event === focused) el.querySelector("summary").focus({preventScroll:true});
    }
  }
  main.scrollTop = keep;
}

// Re-render on changes, but never under the user's fingers.
async function refresh(force = false) {
  const id = ++refreshID;
  try {
    const r = await fetch("/api/state");
    if (!r.ok) return;
    const txt = await r.text();
    if (id < receivedID) return;
    receivedID = id;
    if (!force && !deferredJSON && txt === lastJSON) return;
    const state = JSON.parse(txt);
    const theme = state.settings?.theme;
    document.getElementById("dark-theme").media = theme === "dark" ? "all" : theme === "light" ? "not all" : "(prefers-color-scheme: dark)";
    const a = document.activeElement;
    if (!force && a?.closest("main") && ["INPUT", "SELECT", "TEXTAREA"].includes(a.tagName)) {
      if (txt === deferredJSON) return;
      nav(state);
      const hero = page === "overview" && document.querySelector("main .hero");
      if (hero) {
        hero.className = `card hero ${state.status}`;
        hero.querySelector(".orb").innerHTML = svg(heroIcon(state.status));
        hero.querySelector(".title").textContent = state.statusText;
        hero.querySelector(".sub").innerHTML = heroSub(state);
      }
      deferredJSON = txt;
      return;
    }
    S = state;
    render();
    lastJSON = txt;
    deferredJSON = "";
  } catch (_) { /* Zaslon restarting: try again on the next tick */ }
}

// ---------- events ----------

function countryCode(v) {
  const m = /\(([A-Za-z]{2})\)\s*$/.exec(v.trim());
  if (m) return m[1].toUpperCase();
  const byName = countries.find((c) => c.name.toLowerCase() === v.trim().toLowerCase());
  return byName ? byName.code : v.trim().toUpperCase();
}

document.addEventListener("click", async (e) => {
  const el = e.target.closest("[data-op],[data-url],[data-go],[data-app-settings],[data-addcbtn],[data-addipbtn],[data-rename],[data-edit-domains],[data-cancel-domains],[data-save-domains],[data-default-domains],#cAdd,#trustBtn");
  if (!el) return;
  e.preventDefault();
  if (el.dataset.editDomains !== undefined) {
    const a = S.apps.find((x) => x.id === el.dataset.editDomains);
    if (!domainDrafts.has(a.id)) domainDrafts.set(a.id, editableDomains(a.domains));
    openDomains = openDomains === a.id ? null : a.id;
    return render();
  }
  if (el.dataset.cancelDomains !== undefined) { domainDrafts.delete(el.dataset.cancelDomains); openDomains = null; return render(); }
  if (el.dataset.defaultDomains !== undefined) {
    const a = S.apps.find((x) => x.id === el.dataset.defaultDomains);
    const draft = editableDomains(a.defaultDomains);
    domainDrafts.set(a.id, draft);
    document.querySelector(`[data-domains="${CSS.escape(a.id)}"]`).value = draft;
    return;
  }
  if (el.dataset.saveDomains !== undefined) {
    const app = el.dataset.saveDomains, input = document.querySelector(`[data-domains="${CSS.escape(app)}"]`);
    if (await api("set_domains", { app, domains: input.value.split(/[\s,;]+/).filter(Boolean) })) {
      domainDrafts.delete(app); openDomains = null; render(); toast(t("saved"));
    }
    return;
  }
  if (el.dataset.url) return api("open_url", { value: el.dataset.url });
  if (el.dataset.go) { location.hash = el.dataset.go; return; }
  if (el.dataset.appSettings !== undefined) { openAppSettings = openAppSettings === el.dataset.appSettings ? null : el.dataset.appSettings; openDomains = null; return render(); }
  if (el.dataset.addcbtn !== undefined) {
    const app = el.dataset.addcbtn, inp = document.querySelector(`[data-addc="${CSS.escape(app)}"]`);
    if (!inp.value.trim()) return;
    if (app && !S.apps.find((a) => a.id === app).rule) await api("set_rule", { app, countries: [countryCode(inp.value)] });
    else await api("add_country", { app, value: countryCode(inp.value) });
    return;
  }
  if (el.dataset.addipbtn !== undefined) {
    const app = el.dataset.addipbtn, inp = document.querySelector(`[data-addip="${CSS.escape(app)}"]`);
    if (!inp.value.trim()) return;
    if (app && !S.apps.find((a) => a.id === app).rule) await api("set_rule", { app, ips: [inp.value.trim()] });
    else await api("add_ip", { app, value: inp.value.trim() });
    return;
  }
  if (el.dataset.rename) {
    // Inline rename (WebKit windows have no prompt()).
    const row = el.closest(".item"), nameEl = row.querySelector(".name");
    nameEl.innerHTML = `<input class="rn" value="${esc(el.dataset.name)}" style="border:1px solid var(--line);border-radius:8px;padding:4px 8px">`;
    const inp = nameEl.querySelector("input");
    inp.focus();
    inp.select();
    const done = async () => { inp.onblur = null; if (inp.value.trim()) await api("rename_network", { app: el.dataset.rename, value: inp.value }); else render(); };
    inp.onblur = done;
    inp.onkeydown = (k) => { if (k.key === "Enter") inp.blur(); if (k.key === "Escape") { inp.onblur = null; render(); } };
    return;
  }
  if (el.id === "cAdd") {
    const name = document.getElementById("cName").value, match = document.getElementById("cMatch").value.split(",");
    if (await api("add_custom", { value: name, ips: match })) toast(t("saved"));
    return;
  }
  if (el.id === "trustBtn") return api("trust_network", { value: document.getElementById("netName").value });
  const d = el.dataset;
  await api(d.op, { app: d.app || "", value: d.value || "" });
});

document.addEventListener("input", (e) => {
  if (e.target.dataset.domains !== undefined) domainDrafts.set(e.target.dataset.domains, e.target.value);
});

document.addEventListener("change", async (e) => {
  const el = e.target;
  if (el.dataset.ruleSource !== undefined) {
    const app = el.dataset.ruleSource;
    const ok = el.value === "shared" ? await api("remove_rule", { app })
      : await api("set_rule", { app, ips: [...S.allow.ips], countries: S.allow.countries.map((c) => c.code) });
    if (!ok) await refresh(true);
    return;
  }
  if (el.dataset.domainToggle !== undefined) {
    const a = S.apps.find((x) => x.id === el.dataset.domainToggle);
    if (el.checked && !(a.domains || []).length) {
      el.checked = false; openDomains = a.id;
      if (!domainDrafts.has(a.id)) domainDrafts.set(a.id, "");
      render(); toast(t("domain_required")); return;
    }
    if (!await api("set_domain_checks", { app: a.id, enabled: el.checked })) await refresh(true);
    return;
  }
  if (el.id === "pauseSel" && el.value !== "") return api("pause", { minutes: +el.value });
  if (el.dataset.toggle) return api("toggle_app", { app: el.dataset.toggle });
  if (el.id === "autostart") return api("autostart", { value: el.checked ? "on" : "off" });
  const set = (k, v) => api("settings", { settings: { [k]: v } }).then((ok) => ok && toast(t("saved")));
  if (el.dataset.set) return set(el.dataset.set, el.checked);
  if (el.dataset.num) return set(el.dataset.num, +el.value);
  if (el.dataset.sel) return set(el.dataset.sel, el.value);
});

document.addEventListener("keydown", (e) => {
  if (e.key !== "Enter") return;
  const el = e.target;
  const btn = el.dataset.addc !== undefined ? document.querySelector(`[data-addcbtn="${CSS.escape(el.dataset.addc)}"]`)
    : el.dataset.addip !== undefined ? document.querySelector(`[data-addipbtn="${CSS.escape(el.dataset.addip)}"]`)
    : el.id === "netName" ? document.getElementById("trustBtn") : el.id === "cMatch" ? document.getElementById("cAdd") : null;
  if (btn) btn.click();
});

window.addEventListener("hashchange", () => { page = location.hash.slice(1); openAppSettings = null; openDomains = null; render(); });

(async () => {
  setInterval(refresh, 1000);
  await refresh(true);
  countries = await fetch("/api/countries").then((r) => r.json()).catch(() => []);
  if (S && (page === "allow" || page === "apps")) render();
})();
