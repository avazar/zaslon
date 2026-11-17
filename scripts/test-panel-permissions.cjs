"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { perform } = require("../internal/ui/panel/permissions.js");

function fixture() {
  return {
    ip: "203.0.113.10", country: { code: "NL" }, ip6: "2001:db9::1", country6: { code: "RU" },
    netId: "aa:bb:cc:dd:ee:ff", apps: [{ id: "claude", name: "Claude" }],
  };
}
test("current IP/country confirmation cannot grant another family or later state", async () => {
  for (const op of ["allow_current_ip", "allow_current_country"]) {
    const state = fixture(), calls = [];
    let accept, shown;
    const pending = perform(op, {}, state, (grant) => {
      shown = grant;
      return new Promise((resolve) => { accept = resolve; });
    }, async (op, data) => { calls.push({ op, data }); return true; });
    assert.equal(calls.length, 0);
    state.ip = "192.0.2.99";
    state.country.code = "RU";
    assert.equal(shown.value, op === "allow_current_ip" ? "203.0.113.10" : "NL");
    accept(true);
    assert.equal(await pending, true);
    assert.deepEqual(calls, [{ op: op === "allow_current_ip" ? "add_ip" : "add_country", data: { value: shown.value } }]);
  }
});
test("cancelled permission never reaches the API", async () => {
  let requests = 0;
  for (const op of ["add_ip", "add_country", "set_rule", "trust_network"]) {
    assert.equal(await perform(op, { value: "NL", ips: ["203.0.113.10"] }, fixture(), async () => false,
      async () => { requests++; }), false);
  }
  assert.equal(requests, 0);
});
test("app rules are copied before confirmation", async () => {
  const data = { app: "claude", ips: ["2001:db8::1"], countries: ["NL"] };
  const calls = [];
  let accept;
  const pending = perform("set_rule", data, fixture(), () => new Promise((resolve) => { accept = resolve; }),
    async (op, value) => { calls.push({ op, value }); return true; });
  data.ips.push("2001:db9::/64"); data.countries.push("RU");
  accept(true);
  await pending;
  assert.deepEqual(calls[0], { op: "set_rule", value: { app: "claude", ips: ["2001:db8::1"], countries: ["NL"] } });
});
test("trust is bound to the displayed router rather than a later network", async () => {
  const state = fixture(), calls = [];
  let accept;
  const pending = perform("trust_network", { value: "Office" }, state,
    () => new Promise((resolve) => { accept = resolve; }), async (op, value) => { calls.push(value); return true; });
  state.netId = "11:22:33:44:55:66";
  accept(true);
  await pending;
  assert.deepEqual(calls, [{ value: "Office", app: "aa:bb:cc:dd:ee:ff" }]);
});
test("missing current evidence cannot become a permission", async () => {
  let calls = 0;
  for (const op of ["allow_current_ip", "allow_current_country", "trust_network"]) {
    assert.equal(await perform(op, {}, {}, async () => true, async () => { calls++; }), false);
  }
  assert.equal(calls, 0);
});
