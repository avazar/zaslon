"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const vm = require("node:vm");
const { join } = require("node:path");

const app = readFileSync(join(__dirname, "../internal/ui/panel/app.js"), "utf8");

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
});
