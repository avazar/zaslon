"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const vm = require("node:vm");
const { join } = require("node:path");

const app = readFileSync(join(__dirname, "../internal/ui/panel/app.js"), "utf8");

test("old Networks links open trusted networks within Allowed in either language", async () => {
  for (const lang of ["ru", "en"]) {
    const main = { dataset: {}, scrollTop: 0 };
    let scrolled = false;
    const elements = { main, nav: {}, ver: {}, "dark-theme": {}, "trusted-heading": { scrollIntoView() { scrolled = true; } } };
    const location = { hash: "#networks" };
    const state = { lang, apps: [], allow: { ips: [], countries: [] }, netId: "router", trusted: [{ id: "other", name: "Home" }] };
    const ctx = vm.createContext({
      document: { documentElement: {}, getElementById: id => elements[id], addEventListener() {} },
      location, window: { history: { replaceState(_state, _title, hash) { location.hash = hash; } }, addEventListener() {} },
      setInterval() {}, fetch: async () => ({ ok: true, text: async () => JSON.stringify(state), json: async () => [] }),
    });
    await vm.runInContext(app, ctx);
    assert.equal(location.hash, "#allow/trusted");
    assert.equal(main.dataset.page, "allow");
    assert.ok(scrolled);
    assert.match(elements.nav.innerHTML, /data-go="allow" class="on"/);
    assert.doesNotMatch(elements.nav.innerHTML, /data-go="networks"/);
    assert.match(main.innerHTML, /data-addip=""/);
    assert.match(main.innerHTML, /class="trust-notice"[^]*VPN[^]*id="trustBtn"/);
    assert.match(main.innerHTML, /data-rename="other"/);
    assert.match(main.innerHTML, /data-op="untrust_network"/);
  }
});

test("network check only sends IPQuery requests on click and keeps pending responses bound to their IP", async () => {
  const handlers = {}, timers = [], posts = [];
  const main = { innerHTML: "", querySelector: () => null, querySelectorAll: () => [] };
  let finishLookup;
  const ip4 = "203.0.113.10", ip6 = "2001:db8::10";
  const view = { network: "fixture", rows: [{ endpoint: "", apps: [{name: "", verdict:["allowed", "allowed"]}],
    family: [ip4,ip6].map(ip => ({ip, status:"measured", country:"NL"})) }] };
  const ctx = vm.createContext({
    S: {lang:"en"}, page:"checks", Intl, pageHeader: (_, action) => action, svg: () => "", esc: String,
    document: {addEventListener: (key, fn) => { handlers[key]=fn; }, getElementById: () => main},
    setTimeout: fn => timers.push(fn),
    fetch: async (url, {method}) => {
      if (method === "POST") posts.push(url);
      let data = view;
      if (url.includes("/ip?")) {
        if (method === "POST") await new Promise(resolve => { finishLookup=resolve; });
        data = {report: method === "POST" ? {isp:{isp:"Example Transit"}, fetched:new Date().toISOString()} : null};
      }
      return {ok:true, json:async () => data};
    },
    main,
  });
  vm.runInContext(readFileSync(join(__dirname, "../internal/ui/panel/checks.js"), "utf8"), ctx);
  vm.runInContext("NetworkChecks.render(main)", ctx);
  await timers.shift()();
  const settle = () => new Promise(resolve => setImmediate(resolve));
  const click = key => handlers.click({target:{closest: () => ({dataset:{nc:key}})}});
  const select = ip => handlers.change({target:{id:"nc-address",value:ip}});
  await settle();
  select(ip6);
  await settle();
  await click("check");
  assert.deepEqual(posts, ["/api/routes/check"]);
  const pending=click("lookup");
  select(ip4);
  finishLookup();
  await pending;
  assert.doesNotMatch(main.innerHTML,/Example Transit/);
  select(ip6);
  assert.match(main.innerHTML,/Example Transit/);
  assert.deepEqual(posts, ["/api/routes/check","/api/routes/ip?ip="+encodeURIComponent(ip6)]);
});

test("history keeps raw diagnostics inside escaped, initially closed details", async () => {
  const main = { dataset: {}, scrollTop: 0, querySelectorAll: () => [] };
  const elements = { main, nav: {}, ver: {}, "dark-theme": {} };
  const state = {
    lang: "ru", apps: [], history: [
      { id: 3, kind: "ok", text: "Возобновлено · пауза 12 с", details: ["processes=2 <test>"] },
      { id: 2, kind: "warn", text: "Сеть изменилась" },
    ],
  };
  const ctx = vm.createContext({
    document: { documentElement: {}, getElementById: name => elements[name], addEventListener() {} },
    location: { hash: "#history" }, window: { addEventListener() {} }, setInterval() {},
    fetch: async () => ({ ok: true, text: async () => JSON.stringify(state), json: async () => [] }),
  });
  await vm.runInContext(app, ctx);
  assert.match(main.innerHTML, /<details data-event="3"><summary class="hist-row">[^]*?Возобновлено · пауза 12 с<\/span><\/summary>/);
  assert.doesNotMatch(main.innerHTML, /Подробности|Details/);
  assert.match(main.innerHTML, /<li>processes=2 &lt;test&gt;<\/li>/);
  assert.equal(main.innerHTML.match(/<details/g).length, 1);
});

test("overview follows actual suspension and release while a control keeps focus", async () => {
  const details = { ".orb": {}, ".title": {}, ".sub": {} };
  const hero = { querySelector: (name) => details[name] };
  const main = { innerHTML: "", scrollTop: 0, dataset: {} };
  const elements = { main, nav: {}, ver: {}, "dark-theme": {} };
  const document = {
    documentElement: {},
    getElementById: (name) => elements[name],
    querySelector: () => hero,
    addEventListener: () => {},
    activeElement: null,
  };
  const fixture = {
    lang: "en", ip:"203.0.113.10", domainCountry:{code:"PL",name:"Poland",flag:""}, status: "frozen", statusText: "Service exit not confirmed",
    apps: [{ name: "ChatGPT", running: true, frozen: 0 }, { name: "Codex", running: true, frozen: 2 }],
    stats: { days: [] },
  };
  let state = fixture;
  const p = vm.createContext({
    document, location: { hash: "" }, window: { addEventListener() {} }, setInterval() {},
    fetch: async () => ({ ok: true, text: async () => JSON.stringify(state), json: async () => [] }),
  });
  await vm.runInContext(app, p);
  assert.match(main.innerHTML, /Codex · frozen<br>ChatGPT · running/);
  assert.match(main.innerHTML, /Poland.*From service checks/);
  assert.equal(elements["dark-theme"].media, "(prefers-color-scheme: dark)");
  const held = main.innerHTML;
  document.activeElement = { tagName: "SELECT", closest: () => main };
  state = {
    ...fixture, settings: { theme: "dark" }, status: "ok", statusText: "Protection is on",
    apps: fixture.apps.map((a) => ({ ...a, frozen: 0 })),
  };
  await vm.runInContext("refresh()", p);
  assert.equal(elements["dark-theme"].media, "all");
  assert.equal(main.innerHTML, held, "poll must not replace the focused control");
  assert.equal(details[".title"].textContent, "Protection is on");
  assert.equal(details[".sub"].innerHTML, "ChatGPT, Codex · running");
  assert.doesNotMatch(elements.nav.innerHTML, /badge frozen/);
  document.activeElement = null;
  state.settings.theme = "light";
  await vm.runInContext("refresh()", p);
  assert.equal(elements["dark-theme"].media, "not all");
  assert.match(main.innerHTML, /Protection is on/);
  assert.doesNotMatch(main.innerHTML, /Codex · frozen/);
  const error = "freeze PID 28796 (Taskmgr.exe): Access is denied.";
  state = { ...state, status: "error", statusText: "Protection error: " + error, errors: [error] };
  document.activeElement = { tagName: "SELECT", closest: () => main };
  await vm.runInContext("refresh()", p);
  assert.equal(details[".title"].textContent, "Protection error");
  assert.equal(details[".sub"].innerHTML, error);
  document.activeElement = null;
  await vm.runInContext("refresh()", p);
  assert.equal(main.innerHTML.split(error).length - 1, 1);
});
