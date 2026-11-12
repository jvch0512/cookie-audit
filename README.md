# cookie-audit

Audit `Set-Cookie` headers for the attributes that matter in web application security: `Secure`, `HttpOnly`, `SameSite`, the `__Host-` and `__Secure-` prefix rules, `Domain` scope and lifetime. Zero runtime dependencies, strict TypeScript.

> Built with AI assistance (Claude) as part of a security portfolio. Sample headers are fictional.

## Usage

```bash
npm ci && npm run build
curl -sI https://example.com | node dist/src/cli.js -
node dist/src/cli.js samples/headers.txt --fail-on medium
node dist/src/cli.js samples/headers.txt --json
```

Exit codes: 0 no issue at or above `--fail-on` (default high), 1 issues found, 2 usage or file error.

## Rules

| ID | Check |
|---|---|
| CK001 | Missing `Secure` (high for session-like names, medium otherwise) |
| CK002 | Missing `HttpOnly` on session-like cookies (CSRF tokens excluded) |
| CK003 | Missing or invalid `SameSite` |
| CK004 / CK005 | `SameSite=None` without `Secure` / cross-site sending notice |
| CK006 | `__Host-` or `__Secure-` prefix constraints violated (browsers reject the cookie) |
| CK007 | Session-like cookie that could use the `__Host-` prefix |
| CK008 | `Domain` shares the cookie with subdomains |
| CK009 / CK010 | Lifetime above the 400 day browser cap / long-lived session-like cookie |
| CK011 | Value over 4096 bytes |

`Max-Age` takes precedence over `Expires`, as in browsers. "Session-like" is a name heuristic (sess, sid, token, auth, jwt, login, remember), so review the results rather than treating them as proof.

## Tests

`npm test` covers parsing, each rule, prefix semantics, lifetime precedence and the CLI. CI runs on Node 20 and 22.

MIT licensed.
