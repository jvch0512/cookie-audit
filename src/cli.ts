#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { auditHeaders } from "./index.js";

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith("--"));
if (!file) {
  console.error("usage: cookie-audit <headers.txt | -> [--json] [--fail-on high|medium|low]");
  process.exit(2);
}
const failIdx = args.indexOf("--fail-on");
const failOn = failIdx >= 0 ? args[failIdx + 1] : "high";
const rank: Record<string, number> = { low: 1, medium: 2, high: 3 };
if (!(failOn! in rank)) { console.error("--fail-on must be high, medium or low"); process.exit(2); }
let text: string;
try { text = readFileSync(file === "-" ? 0 : file, "utf8"); } catch (e) { console.error((e as Error).message); process.exit(2); }
const { results, invalid } = auditHeaders(text);
if (args.includes("--json")) console.log(JSON.stringify({ results, invalid }, null, 2));
else {
  for (const r of results) {
    console.log(`${r.cookie.name}${r.issues.length ? "" : "  OK"}`);
    for (const i of r.issues) console.log(`  [${i.severity}] ${i.rule} ${i.message}`);
  }
  for (const l of invalid) console.log(`unparseable: ${l}`);
}
const bad = results.some((r) => r.issues.some((i) => rank[i.severity]! >= rank[failOn!]!));
process.exit(bad ? 1 : 0);
