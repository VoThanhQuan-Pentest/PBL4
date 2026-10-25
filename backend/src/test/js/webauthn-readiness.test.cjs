"use strict";
const { test } = require("node:test");
const { strict: check } = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../resources/lab/webauthn-readiness.js"), "utf8");
const endpoint = "/api/lab/action-proof/webauthn";

// Pure JS unit doubles: no browser, hardware, server, credentials, or real HTTP.
async function fixture({ remaining = 245000, started = false, fail, slowOptions = false, enrollmentOnly = false } = {}) {
  const nodes = Object.fromEntries(["status", "register", "assert"].map(id => [id, { disabled: true, textContent: "" }]));
  const calls = [];
  let creates = 0, now = 0, reloads = 0;
  const timers = [];
  const context = vm.createContext({
    document: { getElementById: id => nodes[id] },
    window: { isSecureContext: true, PublicKeyCredential: function () {} },
    location: { hostname: "localhost", reload: () => reloads++ },
    setTimeout: fn => { timers.push(fn); return timers.length; },
    performance: { now: () => now },
    atob: value => Buffer.from(value, "base64").toString("binary"),
    btoa: value => Buffer.from(value, "binary").toString("base64"),
    navigator: { credentials: { create: async () => {
      creates++;
      return { id: "AA", rawId: new ArrayBuffer(1), type: "public-key", response: {
        clientDataJSON: new ArrayBuffer(1), attestationObject: new ArrayBuffer(1), getTransports: () => ["usb"]
      }, getClientExtensionResults: () => ({}), authenticatorAttachment: "cross-platform" };
    } } },
    fetch: async (url, init) => {
      calls.push({ url, method: init.method || "GET" });
      if (url === "/lab/webauthn") return { ok: true, text: async () => '<body data-lifecycle-phase="RESTORED_ASSERTION">' };
      if (fail && creates > 0) {
        if (fail === "network") throw new TypeError("Failed to fetch");
        if (url.endsWith("/register/finish")) return { status: 400 };
      }
      let body = {};
      if (url === "/api/auth/csrf") body = { token: "synthetic-non-secret" };
      if (url === endpoint + "/status") body = { remaining_ms: remaining, registered_credentials: 0,
        successful_assertions: 0, registration_ceremony_started: started };
      if (url === endpoint + "/register/options") {
        if (slowOptions) now += 120000;
        body = { reference: "synthetic", public_key_json: JSON.stringify({ publicKey: { challenge: "AA", user: { id: "AA" } } }) };
      }
      if (url === endpoint + "/register/finish" && enrollmentOnly) body = { lifecycle_phase: "ENROLL_ONLY" };
      return { status: 200, json: async () => body };
    }
  });
  vm.runInContext(source, context);
  await new Promise(resolve => setImmediate(resolve));
  return { nodes, calls, creates: () => creates, register: () => nodes.register.onclick(), timers, reloads: () => reloads };
}

test("enrollment-only success waits for restart without fresh login or assertion", async () => {
  const f = await fixture({ enrollmentOnly: true }); await f.register();
  check.equal(f.creates(), 1); check.equal(f.nodes.assert.disabled, true);
  check.equal(f.calls.filter(c => c.url === "/api/auth/login").length, 1);
  check.equal(f.calls.filter(c => c.url.endsWith("/complete")).length, 1);
  check.match(f.nodes.status.textContent, /Chờ server khởi động lại/);
  check.equal(f.timers.length, 1);
});

test("restart watcher reloads only after assertion-only server is visible", async () => {
  const f = await fixture({ enrollmentOnly: true }); await f.register();
  await f.timers.shift()();
  check.equal(f.reloads(), 1); check.equal(f.creates(), 1);
  check.equal(f.calls.some(c => c.url.endsWith("/assert/options")), false);
});

test("network loss after device confirmation identifies the upload stage and leaves registration disabled", async () => {
  const f = await fixture({ fail: "network" });
  await f.register();
  check.equal(f.creates(), 1);
  check.equal(f.nodes.register.disabled, true);
  check.match(f.nodes.status.textContent, /gửi kết quả đăng ký về server/);
  check.match(f.nodes.status.textContent, /Failed to fetch/);
  check.match(f.nodes.status.textContent, /Khóa có thể đã được lưu.*Không đăng ký lại/);
  check.equal(f.calls.filter(c => c.url.endsWith("/register/options")).length, 1);
});

test("HTTP rejection is distinguished from a fetch failure", async () => {
  const f = await fixture({ fail: "http" });
  await f.register();
  check.match(f.nodes.status.textContent, /HTTP 400/);
  check.doesNotMatch(f.nodes.status.textContent, /Failed to fetch/);
  check.equal(f.creates(), 1);
});

test("insufficient time prevents both challenge creation and the device prompt", async () => {
  const f = await fixture({ remaining: 139999 });
  check.equal(f.nodes.register.disabled, true);
  await f.register();
  check.equal(f.creates(), 0);
  check.equal(f.calls.some(c => c.url.endsWith("/register/options")), false);
  check.match(f.nodes.status.textContent, /Không đủ thời gian lab/);
});

test("time spent receiving options is charged before opening the device prompt", async () => {
  const f = await fixture({ slowOptions: true });
  await f.register();
  check.equal(f.creates(), 0);
  check.match(f.nodes.status.textContent, /Không đủ thời gian lab/);
});

test("a started registration cannot be repeated after reload", async () => {
  const f = await fixture({ started: true });
  check.equal(f.nodes.register.disabled, true);
  await f.register();
  check.equal(f.creates(), 0);
  check.equal(f.calls.some(c => c.url.endsWith("/register/options")), false);
});

test("successful enrollment still creates a fresh session and enables assertion", async () => {
  const f = await fixture();
  await f.register();
  check.equal(f.creates(), 1);
  check.equal(f.nodes.assert.disabled, false);
  check.equal(f.calls.filter(c => c.url === "/api/auth/login").length, 2);
  check.equal(f.calls.filter(c => c.url.endsWith("/register/finish")).length, 1);
});
