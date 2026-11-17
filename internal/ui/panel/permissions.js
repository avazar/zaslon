"use strict";

// Capture the exact permission before asking. A state refresh while the dialog
// is open must never substitute a different address, country, or network.
(function (exports) {
  exports.perform = async function (op, data, state, confirm, send) {
    const request = { ...data };
    if (Array.isArray(request.ips)) request.ips = [...request.ips];
    if (Array.isArray(request.countries)) request.countries = [...request.countries];
    if (op === "allow_current_ip") { op = "add_ip"; request.value = state.ip; }
    if (op === "allow_current_country") { op = "add_country"; request.value = state.country?.code; }
    if (op === "trust_network") request.app = state.netId;
    if (!["add_ip", "add_country", "set_rule", "trust_network"].includes(op)) return send(op, request);
    const app = state.apps?.find((a) => a.id === request.app);
    const grant = {
      op, scope: app?.name || "", value: request.value || "",
      ips: request.ips || [], countries: request.countries || [],
      network: op === "trust_network" ? request.app : "",
    };
    if ((op === "add_ip" || op === "add_country") && !grant.value) return false;
    if (op === "trust_network" && !grant.network) return false;
    if (!await confirm(grant)) return false;
    return send(op, request);
  };
})(typeof module === "object" && module.exports ? module.exports : (globalThis.ZaslonPermissions = {}));
