"use strict";

const NetworkChecks = (() => {
  const labels = {
    run: ["Проверить сейчас", "Check now"],
    running: ["Идёт проверка…", "Checking…"],
    routes: ["Маршруты к сервисам", "Service routes"],
    general: ["Общий IP", "Public IP"],
    shared: ["Общее правило", "Shared rule"],
    host: ["Назначение", "Destination"],
    latency: ["Время ответа, мс", "Response time, ms"],
    timing: ["сейчас / среднее", "current / average"],
    timingHint: [
      "Среднее по успешным ответам за последние пять измерений",
      "Average of successful responses in the last five measurements"
    ],
    waiting: ["Загрузка…", "Loading…"],
    pending: ["Ещё нет измерений", "Not measured yet"],
    disabled: ["Выключено", "Disabled"],
    idle: ["Приложение закрыто", "App not running"],
    timeout: ["Тайм-аут", "Timed out"],
    error: ["Ошибка запроса", "Request failed"],
    unavailable: ["Нет ответа", "No response"],
    noIPv6: ["IPv6 недоступен", "IPv6 unavailable"],
    unknown: ["Выход не подтверждён", "Exit unconfirmed"],
    quorum: ["Недостаточно совпавших ответов", "Too few matching responses"],
    conflict: ["Сервисы вернули разные IP", "Services returned different IPs"],
    countryUnknown: ["Страна неизвестна", "Country unknown"],
    allowed: ["IP разрешён", "IP allowed"],
    denied: ["IP вне списка", "IP outside allowlist"],
    stale: ["Устарело", "Out of date"],
    healthy: ["Все измеренные выходы разрешены", "All measured exits are allowed"],
    measured: ["Измерено", "Measured"],
    info: ["Сведения об IP", "IP details"],
    select: ["Выберите IP", "Select an IP"],
    empty: ["Сведения появятся, когда проверка получит IP.", "IP details will be available once a route returns an IP."],
    lookup: ["Запросить у IPQuery", "Look up with IPQuery"],
    renew: ["Обновить сведения", "Refresh details"],
    disclose: ["Выбранный адрес будет отправлен в ipquery.io", "The selected address will be sent to ipquery.io"],
    provider: ["Провайдер", "Provider"],
    missing: ["Нет данных", "No data"],
    mobile: ["Мобильная сеть", "Mobile network"],
    hosting: ["Дата-центр", "Data center"],
    typeUnknown: ["Тип сети не определён", "Network type unknown"],
    listed: ["Есть в базе", "Listed"],
    unlisted: ["Нет в базе", "Not listed"],
    proxy: ["Прокси", "Proxy"],
    compare: ["Выход без системного прокси", "Exit without the system proxy"],
    compareStart: ["Сравнить выходы", "Compare exits"],
    compareConfirm: ["Отправить оба запроса", "Send both requests"],
    cancel: ["Отмена", "Cancel"],
    compareHint: [
      "Zaslon проверит IPv4 через системный прокси и напрямую. В обоих случаях адрес увидит www.cloudflare.com.",
      "Zaslon will check IPv4 through the system proxy and directly. Both requests disclose their exit IP to www.cloudflare.com."
    ],
    withProxy: ["Через прокси", "Through proxy"],
    direct: ["Без прокси", "Without proxy"],
    noProxy: ["Системный прокси не настроен", "No system proxy configured"],
    networkChanged: ["Сеть изменилась. Повторите проверку.", "The network changed. Run the check again."],
    cacheError: ["Не удалось прочитать или сохранить локальный кэш.", "Could not read or save the local cache."],
    invalidReport: ["IPQuery вернул некорректный ответ.", "IPQuery returned an invalid response."],
    invalidIP: ["Для этого адреса справка недоступна.", "Lookup is unavailable for this address."]
  };
  const l = (key) => labels[key]?.[S.lang === "en" ? 1 : 0] || key;
  const when = (time) =>
    new Date(time).toLocaleString(S.lang, {
      day: "2-digit",
      month: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    });
  function region(code) {
    if (!code) return l("countryUnknown");
    try {
      return new Intl.DisplayNames([S.lang], { type: "region" }).of(code) || code;
    } catch {
      return code;
    }
  }
  let view,
    viewJSON = "",
    viewError = "",
    checkError = "",
    timer,
    pollID = 0,
    checking = false;
  let selection = "",
    comparison,
    comparing = false,
    confirmDirect = false,
    compareError = "";
  const reports = new Map();
  let lastHTML = "";
  const active = () => page === "checks" && !!S;
  function repaint() {
    if (active()) renderPage(document.getElementById("main"));
  }
  async function request(path, method = "GET") {
    const res = await fetch("/api/routes" + path, { method });
    if (!res.ok) throw new Error((await res.text()).trim() || res.statusText);
    return res.json();
  }
  function accept(data) {
    if (view?.network !== data.network) {
      checkError = "";
      comparison = null;
      confirmDirect = false;
      compareError = "";
    }
    const json = JSON.stringify(data);
    const changed = viewJSON !== json || !!viewError;
    view = data;
    viewJSON = json;
    viewError = "";
    if (changed) repaint();
  }
  async function poll() {
    if (!active()) {
      timer = null;
      return;
    }
    const id = ++pollID;
    try {
      const data = await request("");
      if (id === pollID) accept(data);
    } catch (e) {
      if (id === pollID) {
        viewError = e.message;
        repaint();
      }
    }
    timer = setTimeout(poll, 2000);
  }
  async function report(ip, remote = false) {
    const old = reports.get(ip);
    if (!ip || old?.busy) return;
    const state = { ...old, busy: true, error: "" };
    reports.set(ip, state);
    if (remote) repaint();
    try {
      const data = await request("/ip?ip=" + encodeURIComponent(ip), remote ? "POST" : "GET");
      Object.assign(state, data);
      if (data.cacheError) state.error = "cacheError";
    } catch (e) {
      state.error = e.message;
    }
    state.busy = false;
    if (selection === ip) repaint();
  }
  function level(status) {
    if (status === "denied" || status === "conflict") return 3;
    if (["timeout", "error", "unknown", "countryUnknown", "quorum", "unavailable", "stale"].includes(status)) return 2;
    if (status === "pending") return 1;
    return 0;
  }
  function outcome(row, i) {
    const activeApps = row.apps.filter((a) => !a.status);
    if (!activeApps.length) return row.apps.some((a) => a.status === "idle") ? "idle" : "disabled";
    if (row.stale && row.family[i].status !== "disabled") return "stale";
    const result = activeApps.map((a) => a.verdict[i]).sort((a, b) => level(b) - level(a))[0];
    return i === 1 && result === "unavailable" ? "noIPv6" : result;
  }
  function mark(status) {
    const key = status === "allowed" ? "check" : level(status) === 3 ? "stop" : level(status) === 2 ? "history" : "";
    return key
      ? `<span class="nc-mark nc-level-${level(status)}" role="img" aria-label="${esc(l(status))}" title="${esc(l(status))}">${svg(key)}</span>`
      : "";
  }
  const host = (row) => (row.endpoint ? domainHost(row.endpoint) : l("general"));
  const appNames = (row) => row.apps.map((a) => a.name || l("shared")).join(", ");
  function cell(row, i) {
    const f = row.family[i],
      status = outcome(row, i);
    return `<span class="nc-cell"><span>${mark(status)}${esc(f.ip || l(status))}</span>${f.ip ? `<small>${esc(region(f.country))}${status === "allowed" ? "" : " · " + esc(l(status))}</small>` : ""}</span>`;
  }
  function summary(rows) {
    let worst = null,
      rank = -1,
      measured = false;
    for (const row of rows)
      for (const i of [0, 1]) {
        const status = outcome(row, i),
          priority = level(status);
        measured ||= status === "allowed";
        if (priority > 0 && priority > rank) {
          worst = { row, i, status };
          rank = priority;
        }
      }
    if (!worst)
      return `<div class="nc-summary ${measured ? "good" : ""}">${measured ? svg("check") : svg("history")}<strong>${l(measured ? "healthy" : "pending")}</strong></div>`;
    const { row, i, status } = worst;
    const names = row.apps
      .filter((a) => !a.status && (status === "stale" || a.verdict[i] === status))
      .map((a) => a.name)
      .filter(Boolean);
    return `<div class="nc-summary nc-level-${rank}">${svg(rank === 3 ? "stop" : "history")}<div><strong>${esc([...names, host(row)].join(" · "))}</strong><small>IPv${i === 0 ? 4 : 6} · ${esc(l(status))}</small></div></div>`;
  }
  function route(row) {
    const timings = row.family.filter((f, i) => i === 0 || f.ms != null || f.average != null);
    const latency = timings
      .map((f, i) => {
        const prefix = timings.length === 1 ? "" : `v${i === 0 ? 4 : 6} · `;
        const current = f.status === "timeout" ? l("timeout") : (f.ms ?? "—");
        return `<span>${prefix}${current} / ${f.average ?? "—"}</span>`;
      })
      .join("");
    const rules = row.apps
      .map(
        (a) =>
          `<div><b>${esc(a.name || l("shared"))}</b> · ${a.status ? l(a.status) : [0, 1].map((i) => "IPv" + (i === 0 ? 4 : 6) + " · " + l(a.verdict[i] === "unavailable" && i === 1 ? "noIPv6" : a.verdict[i])).join(" / ")}</div>`
      )
      .join("");
    return `<details data-route="${esc(row.endpoint || "general")}"><summary class="nc-grid"><span class="nc-host">${esc(host(row))}<small>${esc(appNames(row))}</small></span>${cell(row, 0)}${cell(row, 1)}<span class="nc-latency" aria-label="${l("latency")} · ${l("timing")}" title="${l("timingHint")}">${latency}</span></summary><div class="nc-detail">${row.at ? `<small>${l("measured")} · ${esc(when(row.at))}${row.stale ? " · " + l("stale") + " · " + fmtDur((Date.now() - Date.parse(row.at)) / 1000) : ""}</small>` : ""}${rules}${row.family.map((f, i) => (f.detail ? `<small>IPv${i === 0 ? 4 : 6} · ${esc(f.detail)}</small>` : "")).join("")}</div></details>`;
  }
  function ipCard(rows) {
    const ips = new Set(rows.flatMap((row) => row.family.map((f) => f.ip)).filter(Boolean));
    for (const f of [comparison?.proxy, comparison?.direct]) if (f?.ip) ips.add(f.ip);
    if (!ips.has(selection)) selection = ips.values().next().value || "";
    if (selection && !reports.has(selection)) void report(selection);
    const state = reports.get(selection),
      v = state?.report,
      risk = v?.risk || {};
    const types = [risk.is_mobile && l("mobile"), risk.is_datacenter && l("hosting")].filter(Boolean);
    const flags = [
      ["VPN", risk.is_vpn],
      [l("proxy"), risk.is_proxy],
      ["Tor", risk.is_tor]
    ]
      .map(
        ([name, val]) =>
          `<div><dt>${name}</dt><dd class="${val === true ? "nc-listed" : ""}">${l(val === true ? "listed" : val === false ? "unlisted" : "missing")}</dd></div>`
      )
      .join("");
    const stale = v && (state.stale || Date.now() - Date.parse(v.fetched) >= 7 * 86400000);
    return `<section class="card nc-profile"><div class="nc-profile-head"><h3>${l("info")}</h3>${selection ? `<select id="nc-address" aria-label="${l("select")}">${[...ips].map((ip) => `<option${ip === selection ? " selected" : ""}>${esc(ip)}</option>`).join("")}</select>` : ""}</div>
      ${v ? `<div class="nc-report"><div><small>${l("provider")}</small><strong>${esc(v.isp?.isp || l("missing"))}</strong><div class="nc-meta">${esc(region(v.location?.country_code))} · ${esc(types.join(" · ") || l("typeUnknown"))} <code>${esc(v.isp?.asn || l("missing"))}</code></div></div><dl>${flags}</dl></div>` : ""}
      <div class="nc-foot"><small>${v ? "IPQuery · " + esc(when(v.fetched)) + (stale ? " · " + l("stale") : "") : selection ? l("disclose") + " · " + esc(selection) : l("empty")}</small>
      ${selection ? `<button type="button" class="btn" data-nc="lookup" ${state?.busy ? "disabled" : ""}>${state?.busy ? l("waiting") : l(v ? "renew" : "lookup")}</button>` : ""}</div>
      ${state?.error ? `<p class="nc-error" role="status">${esc(l(state.error))}</p>` : ""}</section>`;
  }
  function directSection() {
    const button = (id, key) => `<button class="btn" data-nc="${id}" ${comparing ? "disabled" : ""}>${l(key)}</button>`;
    const results = comparison
      ? [
          ["withProxy", comparison.proxy],
          ["direct", comparison.direct]
        ]
          .map(
            ([label, f]) =>
              `<div>${l(label)} · ${esc(f.ip ? f.ip + " · " + region(f.country) : l(f.status) + (f.detail ? " · " + f.detail : ""))}</div>`
          )
          .join("")
      : "";
    return `<details class="nc-direct" data-route="compare"><summary>${l("compare")}</summary>
      ${view.proxy ? `<p>${l("compareHint")}</p>${confirmDirect ? button("send", "compareConfirm") + " " + button("cancel", "cancel") : button("compare", comparing ? "running" : "compareStart")}` : `<p>${l("noProxy")}</p>`}
      <div aria-live="polite">${results}${esc(l(compareError))}</div></details>`;
  }
  function html() {
    if (timer == null) timer = setTimeout(poll, 0);
    const rows = view?.rows;
    const latest = Math.max(0, ...(rows || []).filter((row) => row.at).map((row) => Date.parse(row.at)));
    const busy = checking || view?.busy;
    const action = `<button class="btn primary" data-nc="check" ${busy ? "disabled" : ""}>${l(busy ? "running" : "run")}</button>`;
    return `<div class="page nc">${pageHeader("checks", action)}
     ${viewError || checkError ? `<p class="nc-error" role="status">${esc(l(viewError || checkError))}</p>` : ""}
     ${
       rows
         ? summary(rows) +
           `<div class="nc-section-title"><h3>${l("routes")}</h3><small>${latest ? l("measured") + " · " + esc(when(latest)) : ""}</small></div>
     <div class="card nc-routes"><div class="nc-head nc-grid"><span>${l("host")}</span><span>IPv4</span><span>IPv6</span><span>${l("latency")}<small>${l("timing")}</small></span></div>${rows.map(route).join("")}</div>` +
           ipCard(rows) +
           directSection()
         : `<p>${l("waiting")}</p>`
     }</div>`;
  }
  function renderPage(main) {
    const next = html();
    if (next === lastHTML && main.querySelector(".nc")) return;
    const open = new Set([...main.querySelectorAll("details[data-route][open]")].map((d) => d.dataset.route));
    const focus = document.activeElement,
      routeKey = focus?.tagName === "SUMMARY" && focus.parentElement.dataset.route;
    const action = focus?.dataset.nc,
      picker = focus?.id === "nc-address";
    main.innerHTML = next;
    lastHTML = next;
    for (const d of main.querySelectorAll("details[data-route]")) {
      d.open = open.has(d.dataset.route);
      if (routeKey === d.dataset.route) d.querySelector("summary").focus({ preventScroll: true });
    }
    if (picker) main.querySelector("#nc-address")?.focus({ preventScroll: true });
    else if (action) main.querySelector(`[data-nc="${CSS.escape(action)}"]`)?.focus({ preventScroll: true });
  }
  document.addEventListener("change", (e) => {
    if (e.target.id === "nc-address") {
      selection = e.target.value;
      repaint();
    }
  });
  document.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-nc]");
    if (!btn || !active()) return;
    switch (btn.dataset.nc) {
      case "lookup":
        await report(selection, true);
        break;
      case "check":
        if (checking) return;
        checkError = "";
        checking = true;
        repaint();
        try {
          const data = await request("/check", "POST");
          ++pollID;
          accept(data);
        } catch (e) {
          checkError = e.message;
        } finally {
          checking = false;
          repaint();
        }
        break;
      case "compare":
        confirmDirect = true;
        repaint();
        break;
      case "cancel":
        confirmDirect = false;
        repaint();
        break;
      case "send":
        if (!confirmDirect || comparing) return;
        comparing = true;
        confirmDirect = false;
        comparison = null;
        compareError = "";
        repaint();
        try {
          const data = await request("/compare?network=" + encodeURIComponent(view.network), "POST");
          if (view.network === data.network) comparison = data;
          else compareError = "networkChanged";
        } catch (e) {
          compareError = e.message;
        } finally {
          comparing = false;
          repaint();
        }
        break;
    }
  });
  return { render: renderPage };
})();
