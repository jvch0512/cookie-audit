export interface Cookie {
  name: string;
  value: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: "strict" | "lax" | "none" | "invalid";
  domain?: string;
  path?: string;
  maxAge?: number;
  expires?: Date;
  partitioned: boolean;
}

export interface Issue {
  rule: string;
  severity: "high" | "medium" | "low";
  message: string;
}

export interface Result {
  cookie: Cookie;
  issues: Issue[];
}

/** Parse one Set-Cookie header value. Returns undefined when there is no name=value pair. */
export function parseSetCookie(header: string): Cookie | undefined {
  const parts = header.split(";");
  const first = parts.shift() ?? "";
  const eq = first.indexOf("=");
  if (eq <= 0) return undefined;
  const c: Cookie = { name: first.slice(0, eq).trim(), value: first.slice(eq + 1).trim(), secure: false, httpOnly: false, partitioned: false };
  if (!c.name) return undefined;
  for (const raw of parts) {
    const i = raw.indexOf("=");
    const key = (i < 0 ? raw : raw.slice(0, i)).trim().toLowerCase();
    const val = i < 0 ? "" : raw.slice(i + 1).trim();
    switch (key) {
      case "secure": c.secure = true; break;
      case "httponly": c.httpOnly = true; break;
      case "partitioned": c.partitioned = true; break;
      case "samesite": { const v = val.toLowerCase(); c.sameSite = v === "strict" || v === "lax" || v === "none" ? v : "invalid"; break; }
      case "domain": c.domain = val.replace(/^\./, "").toLowerCase(); break;
      case "path": c.path = val; break;
      case "max-age": { const n = Number(val); if (/^-?\d+$/.test(val) && Number.isFinite(n)) c.maxAge = n; break; }
      case "expires": { const d = new Date(val); if (!Number.isNaN(d.getTime())) c.expires = d; break; }
    }
  }
  return c;
}

const SESSION_HINT = /(sess|sid|token|auth|jwt|login|csrf|xsrf|remember)/i;
const DAY = 86_400;

/** Seconds of lifetime, or undefined for a session cookie. Max-Age wins over Expires like browsers do. */
export function lifetime(c: Cookie, now: Date): number | undefined {
  if (c.maxAge !== undefined) return c.maxAge;
  if (c.expires) return Math.round((c.expires.getTime() - now.getTime()) / 1000);
  return undefined;
}

export function audit(c: Cookie, now: Date = new Date()): Issue[] {
  const out: Issue[] = [];
  const add = (rule: string, severity: Issue["severity"], message: string) => out.push({ rule, severity, message });
  const sensitive = SESSION_HINT.test(c.name);
  if (!c.secure) add("CK001", sensitive ? "high" : "medium", "missing Secure: the cookie can be sent over plain HTTP");
  if (!c.httpOnly && sensitive && !/csrf|xsrf/i.test(c.name)) add("CK002", "high", "missing HttpOnly on a session-like cookie: readable by XSS");
  if (c.sameSite === undefined) add("CK003", "medium", "no SameSite attribute: browser default applies (Lax in modern browsers, but not everywhere)");
  else if (c.sameSite === "invalid") add("CK003", "medium", "invalid SameSite value is ignored by browsers");
  else if (c.sameSite === "none") {
    if (!c.secure) add("CK004", "high", "SameSite=None requires Secure; browsers reject this cookie");
    else add("CK005", "low", "SameSite=None allows cross-site sending; make sure that is intended");
  }
  const lower = c.name.toLowerCase();
  if (lower.startsWith("__host-")) {
    if (!c.secure || c.path !== "/" || c.domain) add("CK006", "high", "__Host- prefix requires Secure, Path=/ and no Domain; browsers will reject it");
  } else if (lower.startsWith("__secure-")) {
    if (!c.secure) add("CK006", "high", "__Secure- prefix requires Secure; browsers will reject it");
  } else if (sensitive && c.secure && c.path === "/" && !c.domain) {
    add("CK007", "low", "session-like cookie could use the __Host- prefix for stronger origin binding");
  }
  if (c.domain) add("CK008", "low", `Domain=${c.domain} shares the cookie with all subdomains`);
  const life = lifetime(c, now);
  if (life !== undefined && life > 400 * DAY) add("CK009", "medium", `lifetime of ${Math.round(life / DAY)} days exceeds the 400 day cap browsers apply`);
  else if (life !== undefined && life > 30 * DAY && sensitive) add("CK010", "medium", `session-like cookie lives ${Math.round(life / DAY)} days; prefer short lifetimes with rotation`);
  if (c.value.length > 4096) add("CK011", "low", "cookie value over 4096 bytes may be dropped by browsers");
  return out;
}

/** Audit many header lines (raw "Set-Cookie: ..." lines or bare values). Unparseable lines are returned in `invalid`. */
export function auditHeaders(text: string, now: Date = new Date()): { results: Result[]; invalid: string[] } {
  const results: Result[] = [];
  const invalid: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const value = t.replace(/^set-cookie:\s*/i, "");
    const cookie = parseSetCookie(value);
    if (!cookie) { invalid.push(t); continue; }
    results.push({ cookie, issues: audit(cookie, now) });
  }
  return { results, invalid };
}
