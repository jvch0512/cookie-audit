import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { audit, auditHeaders, lifetime, parseSetCookie } from "../src/index.js";

const now = new Date("2026-03-01T00:00:00Z");
const rules = (h: string) => audit(parseSetCookie(h)!, now).map((i) => i.rule);

test("parses attributes case-insensitively", () => {
  const c = parseSetCookie("A=b=c; SECURE; httponly; SameSite=lax; Domain=.Example.COM; Path=/x; Max-Age=60")!;
  assert.equal(c.value, "b=c");
  assert.ok(c.secure && c.httpOnly);
  assert.equal(c.sameSite, "lax");
  assert.equal(c.domain, "example.com");
  assert.equal(c.maxAge, 60);
});

test("rejects headers without a name", () => {
  assert.equal(parseSetCookie("=novalue"), undefined);
  assert.equal(parseSetCookie("justtext"), undefined);
});

test("insecure session cookie is high severity", () => {
  const issues = audit(parseSetCookie("sessionid=1; Path=/")!, now);
  assert.ok(issues.some((i) => i.rule === "CK001" && i.severity === "high"));
  assert.ok(issues.some((i) => i.rule === "CK002"));
  assert.ok(issues.some((i) => i.rule === "CK003"));
});

test("non-sensitive cookie missing Secure is only medium and needs no HttpOnly", () => {
  const issues = audit(parseSetCookie("theme=dark; SameSite=Lax")!, now);
  assert.deepEqual(issues.map((i) => [i.rule, i.severity]), [["CK001", "medium"]]);
});

test("CSRF cookies may be readable by script", () => {
  assert.ok(!rules("csrf_token=1; Secure; SameSite=Lax").includes("CK002"));
});

test("SameSite=None needs Secure", () => {
  assert.ok(rules("x=1; SameSite=None").includes("CK004"));
  assert.ok(rules("x=1; Secure; SameSite=None").includes("CK005"));
  assert.ok(rules("x=1; SameSite=bogus").includes("CK003"));
});

test("cookie prefixes are validated", () => {
  assert.ok(rules("__Host-a=1; Secure; Domain=example.com; Path=/").includes("CK006"));
  assert.ok(rules("__Host-a=1; Secure; Path=/app").includes("CK006"));
  assert.ok(!rules("__Host-a=1; Secure; Path=/; SameSite=Lax").includes("CK006"));
  assert.ok(rules("__Secure-a=1; Path=/").includes("CK006"));
  assert.ok(rules("sid=1; Secure; HttpOnly; Path=/; SameSite=Lax").includes("CK007"));
});

test("lifetime: Max-Age wins over Expires, session cookies have none", () => {
  assert.equal(lifetime(parseSetCookie("a=1")!, now), undefined);
  assert.equal(lifetime(parseSetCookie("a=1; Max-Age=10; Expires=Wed, 01 Jan 2200 00:00:00 GMT")!, now), 10);
  assert.equal(lifetime(parseSetCookie("a=1; Expires=Sun, 01 Mar 2026 01:00:00 GMT")!, now), 3600);
});

test("long lifetimes are flagged", () => {
  assert.ok(rules("a=1; Secure; SameSite=Lax; Max-Age=40000000").includes("CK009"));
  assert.ok(rules("auth=1; Secure; HttpOnly; SameSite=Lax; Max-Age=3200000").includes("CK010"));
});

test("auditHeaders handles raw header lines, comments and garbage", () => {
  const r = auditHeaders("# c\nSet-Cookie: a=1; Secure; SameSite=Lax\n\nSET-COOKIE: b=2\nnot a cookie\n", now);
  assert.equal(r.results.length, 2);
  assert.deepEqual(r.invalid, ["not a cookie"]);
});

test("CLI exit codes follow --fail-on", () => {
  const run = (...a: string[]) => spawnSync("node", ["dist/src/cli.js", ...a], { encoding: "utf8" });
  const bad = run("samples/headers.txt");
  assert.equal(bad.status, 1);
  assert.match(bad.stdout, /sessionid/);
  assert.match(bad.stdout, /CK006/);
  assert.equal(run("samples/headers.txt", "--fail-on", "medium").status, 1);
  assert.equal(run().status, 2);
  assert.equal(run("samples/headers.txt", "--fail-on", "x").status, 2);
  assert.equal(run("missing.txt").status, 2);
  assert.ok(Array.isArray(JSON.parse(run("samples/headers.txt", "--json").stdout).results));
});
