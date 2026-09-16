# Meridian Trust — Master Implementation Plan (Complete Vulnerability Catalogue)

> **INTENTIONALLY VULNERABLE TRAINING APPLICATION — DO NOT DEPLOY TO ANY PUBLIC/PRODUCTION NETWORK.**
> Educational lab for teaching web penetration testing against the full OWASP Top 10 (2021), the OWASP
> API Security Top 10, and the broader universe of common web-app vulnerabilities. Binds to `127.0.0.1`
> only. Fake seeded data only.

**Stack:** Node.js + Express + SQLite (`better-sqlite3`), EJS server-side views, JWT for the API layer,
optional GraphQL + WebSocket modules.
**Run:** Docker Compose (`127.0.0.1:3000`).
**Mode:** Vulnerable-only. Every flaw is intentional and recorded in `docs/FINDINGS.md`.

---

## How to read this plan
- Each vulnerability has a **Finding ID** (`VB-###`) used in `FINDINGS.md` and the lab worksheet.
- Each is mapped to an **OWASP category** and the concrete **feature/endpoint** that hosts it.
- Phases order the build: legitimate app first, then vulns injected in themed batches.
- **200+ findings total.** Some advanced items are marked *(optional/advanced — needs extra infra)*.

---

## Phase 0 — Scaffolding & Infrastructure
- Repo: `/src`, `/db`, `/docs`, `/uploads`, `Dockerfile`, `docker-compose.yml`.
- Express, `better-sqlite3`, `express-session`, EJS, `multer`, `jsonwebtoken`, optional `ws` + `express-graphql`.
- Seed: customers, `admin/admin`, `support`, accounts, transactions, treasury account, fake PAN/SSN.
- Safety: localhost bind, "VULNERABLE" banner, isolated Docker network, reseed script.

## Phase 1 — Legitimate Banking Core (no planted bugs)
Auth, dashboard, accounts/balances, transfers, transaction history/search, profile, avatar upload +
avatar-by-URL, support messaging, admin panel, REST/JSON API + JWT, GraphQL endpoint, WebSocket
notifications, statement export/import, PDF generator, webhook tester, password reset, notifications.

---

# COMPLETE VULNERABILITY CATALOGUE

## Phase 2 — A01: Broken Access Control
- **VB-001** IDOR — read any account `/account/:id`.
- **VB-002** IDOR — read/replay any transaction `/transaction/:id`.
- **VB-003** IDOR — edit any profile `/profile/:id`.
- **VB-004** IDOR — download any user's statement `/statement/:id`.
- **VB-005** Missing function-level authz — `/admin/*` open to normal users.
- **VB-006** Forced browsing — hidden `/admin`, `/debug`, `/backup`, `/internal`.
- **VB-007** Vertical priv-esc — `role` settable via profile update (mass assignment).
- **VB-008** Horizontal priv-esc — transfer *from* an account you don't own.
- **VB-009** Path traversal / LFI — `/download?file=../../etc/passwd`.
- **VB-010** Directory traversal on upload retrieval `/uploads/..%2f`.
- **VB-011** Unprotected API listing — `GET /api/users` returns all users.
- **VB-012** CORS misconfig — `ACAO: *` **with** credentials.
- **VB-013** CORS reflected-origin — echoes any `Origin` back.
- **VB-014** JWT `alg:none` accepted → forge admin.
- **VB-015** HTTP method bypass — `POST`-only guard bypassed with `PUT`/`X-HTTP-Method-Override`.
- **VB-016** Referer/`X-Forwarded-For`-based access control bypass.
- **VB-017** Multi-step process step-skipping (go straight to confirm-transfer).
- **VB-018** Insecure direct object reference in GraphQL node lookup.
- **VB-019** Cookie-based role trust — `isAdmin=false` client cookie.
- **VB-020** Static secret "god mode" query param `?debug=1&admin=1`.

## Phase 3 — A03: Injection
### SQL Injection
- **VB-021** Login bypass (`' OR '1'='1' -- `).
- **VB-022** UNION-based extraction in transaction search.
- **VB-023** Boolean-blind SQLi in account lookup.
- **VB-024** Time-based blind SQLi (`... AND 1=randomblob(100000000)`).
- **VB-025** Second-order SQLi — stored username reused in a query.
- **VB-026** SQLi via HTTP header (`User-Agent`/`X-Forwarded-For` logged into DB).
- **VB-027** SQLi via cookie value.
- **VB-028** ORDER BY / column-name SQLi (non-parameterizable context).
- **VB-029** Stacked-query SQLi (INSERT/UPDATE injection).
### Cross-Site Scripting
- **VB-030** Stored XSS — transfer memo / support message.
- **VB-031** Reflected XSS — search box.
- **VB-032** DOM XSS — `location.hash` sink.
- **VB-033** Stored XSS via uploaded SVG/HTML file.
- **VB-034** XSS in error/404 page (reflected path).
- **VB-035** XSS via HTTP header reflected in page (`Referer`).
- **VB-036** Blind XSS — admin-only view renders customer input unescaped.
- **VB-037** Mutation XSS (mXSS) via innerHTML sanitizer bypass.
- **VB-038** XSS in JSON response served with `text/html`.
- **VB-039** Markdown XSS — `marked` with raw HTML enabled.
### Other injection
- **VB-040** OS command injection — admin "ping host" tool.
- **VB-041** Blind/time-based command injection.
- **VB-042** Argument injection into a CLI tool (`--` option smuggling).
- **VB-043** SSTI — display-name rendered through template engine.
- **VB-044** NoSQL/object injection — `{"$ne":null}` login handling.
- **VB-045** CRLF / HTTP response-header injection.
- **VB-046** Log injection / forged log entries.
- **VB-047** XPath injection (XML-backed lookup).
- **VB-048** LDAP injection (directory search demo).
- **VB-049** Server-Side Includes (SSI) injection.
- **VB-050** Email/SMTP header injection in "contact us".
- **VB-051** GraphQL injection via unsanitized filter argument.
- **VB-052** Prototype-pollution-based injection via query parser.
- **VB-053** ReDoS via user-supplied regex / catastrophic backtracking.
- **VB-054** Formula/CSV injection into stored fields (fires on export).

## Phase 4 — A02: Cryptographic Failures
- **VB-055** Plaintext password storage.
- **VB-056** Unsalted MD5/SHA1 password hashes.
- **VB-057** Fast unsalted hash + provided rainbow-table exercise.
- **VB-058** PAN/card + SSN returned in API/JSON (sensitive data exposure).
- **VB-059** Weak/hardcoded JWT secret (crackable with `hashcat`).
- **VB-060** JWT `kid` SQL/path injection.
- **VB-061** JWT `jku`/`x5u` header points to attacker key.
- **VB-062** JWT algorithm confusion (RS256 → HS256 with public key).
- **VB-063** Cookies missing `Secure`/`HttpOnly`/`SameSite`.
- **VB-064** Sensitive data & tokens in URL query string.
- **VB-065** Predictable/sequential password-reset token.
- **VB-066** Weak randomness — `Math.random()` for tokens/OTP.
- **VB-067** Hardcoded secrets/keys in source; committed `.env`.
- **VB-068** AES-ECB mode — pattern leakage in encrypted cookie.
- **VB-069** Static/zero IV reuse in CBC.
- **VB-070** Padding-oracle-style decryption error differences.
- **VB-071** Hash length-extension on a naive `secret||data` MAC.
- **VB-072** Reversible "encryption" (Base64/XOR) treated as secure.
- **VB-073** Cleartext transport (no TLS) for the whole app.
- **VB-074** Sensitive data cached (missing `Cache-Control: no-store`).

## Phase 5 — A04: Insecure Design (Business Logic)
- **VB-075** Negative-amount transfer → steal funds.
- **VB-076** Integer overflow/underflow to inflate balance.
- **VB-077** Race condition (TOCTOU) on transfer → double-spend.
- **VB-078** Race condition on coupon/promo redemption.
- **VB-079** No transaction/amount limits.
- **VB-080** Currency rounding abuse (fractional-cent skimming).
- **VB-081** Password reset without identity verification.
- **VB-082** Promo/loan approval applied repeatedly.
- **VB-083** Insufficient anti-automation on money movement (no CAPTCHA/limit).
- **VB-084** Workflow bypass — skip OTP/confirmation step.
- **VB-085** Trusting client-side price/balance value in request body.
- **VB-086** Unlimited-attempt gift-card/voucher validation (enumeration).

## Phase 6 — A07: Identification & Authentication Failures
- **VB-087** No account lockout / no rate limit (brute force).
- **VB-088** Credential stuffing (no protection, no MFA).
- **VB-089** Password spraying viable (weak lockout).
- **VB-090** Weak password policy (allows `123`).
- **VB-091** Username enumeration via differing error messages.
- **VB-092** Username enumeration via response timing.
- **VB-093** Session fixation — ID not rotated on login.
- **VB-094** Predictable session identifiers.
- **VB-095** Predictable "remember-me" token.
- **VB-096** Session never expires; logout doesn't invalidate server-side.
- **VB-097** Concurrent sessions unlimited; no re-auth for sensitive ops.
- **VB-098** OTP/MFA validated client-side (bypassable).
- **VB-099** OTP brute-forceable (no attempt limit, short code).
- **VB-100** OTP reuse / not invalidated after use.
- **VB-101** Auth via trusting `X-User-Id`/`X-Role` header.
- **VB-102** OAuth `state` missing → login CSRF.
- **VB-103** OAuth `redirect_uri` not validated → token theft.
- **VB-104** Password change without current-password check.

## Phase 7 — A05: Security Misconfiguration
- **VB-105** Verbose stack traces to the browser.
- **VB-106** Debug mode / `/debug` exposes env & config.
- **VB-107** Default credentials `admin/admin`.
- **VB-108** Directory listing on `/uploads`, `/backup`.
- **VB-109** Missing security headers (CSP/HSTS/X-Frame/X-Content-Type).
- **VB-110** Clickjacking — no frame protection on transfer page.
- **VB-111** Exposed `.git/`, `backup.zip`, `db.sqlite`.
- **VB-112** Dangerous HTTP methods enabled (TRACE/PUT/DELETE).
- **VB-113** Verbose `Server`/`X-Powered-By` version banners.
- **VB-114** Overly permissive file upload → web shell (RCE).
- **VB-115** Unrestricted upload path → overwrite app files.
- **VB-116** Admin interface exposed on same origin without extra control.
- **VB-117** Sample/test endpoints left enabled (`/test`, `/phpinfo`-style).
- **VB-118** Permissive CSP (`unsafe-inline`, `*`).
- **VB-119** Misconfigured `Access-Control-Allow-Headers`/`-Methods`.
- **VB-120** Secrets in client-side JS / source maps shipped to prod.

## Phase 8 — A06: Vulnerable & Outdated Components
- **VB-121** Pinned known-CVE `jsonwebtoken` (documented CVE).
- **VB-122** Pinned known-CVE `lodash` (prototype pollution CVE).
- **VB-123** Pinned known-CVE `marked` (XSS/ReDoS CVE).
- **VB-124** Prototype pollution via unsafe recursive merge.
- **VB-125** Vulnerable client lib from CDN without SRI.
- **VB-126** `/version` endpoint discloses component versions.
- **VB-127** Outdated Express/middleware with known advisory.
- **VB-128** Vulnerable image/XML parser (ties to XXE/ImageTragick).
- **VB-129** Dependency confusion note — internal package name public *(advisory/optional)*.

## Phase 9 — A08: Software & Data Integrity Failures
- **VB-130** Insecure deserialization (serialized object in cookie/import → RCE).
- **VB-131** `node-serialize`/eval-style deserialization gadget.
- **VB-132** Unsigned "import transactions" JSON trusted blindly.
- **VB-133** Third-party script without Subresource Integrity.
- **VB-134** Auto-update/plugin from unauthenticated source.
- **VB-135** CSV/formula injection in exported statements.
- **VB-136** Unverified webhook signatures (spoofable callbacks).
- **VB-137** Client-side integrity trust — signature check done in JS.

## Phase 10 — A10: Server-Side Request Forgery (SSRF)
- **VB-138** SSRF — avatar-by-URL fetches arbitrary URL.
- **VB-139** SSRF to cloud metadata `169.254.169.254`.
- **VB-140** SSRF — webhook tester posts to internal URL.
- **VB-141** Blind SSRF via PDF/statement generator.
- **VB-142** SSRF filter bypass (`localhost`, `0.0.0.0`, decimal/hex IP).
- **VB-143** SSRF via redirect (open redirect chained to internal).
- **VB-144** SSRF via DNS rebinding *(advanced/optional)*.
- **VB-145** SSRF to non-HTTP scheme (`file://`, `gopher://`) *(advanced)*.

## Phase 11 — A09: Security Logging & Monitoring Failures
- **VB-146** No logging of auth events.
- **VB-147** No logging of transfers/admin actions.
- **VB-148** No alerting during brute force / fund theft.
- **VB-149** Logs leak secrets (passwords/tokens).
- **VB-150** World-readable logs; no access control.
- **VB-151** No tamper protection (pairs with log injection VB-046).
- **VB-152** No audit trail for privilege changes.

## Phase 12 — Client-Side & Cross-Cutting Web Vulns
- **VB-153** CSRF — state-changing transfer, no anti-CSRF token.
- **VB-154** CSRF via `GET` money movement.
- **VB-155** JSON CSRF (no content-type enforcement).
- **VB-156** Open redirect — `/redirect?url=`.
- **VB-157** Reverse tabnabbing (`target=_blank` no `noopener`).
- **VB-158** Host header injection — reset links from `Host`.
- **VB-159** Web cache poisoning via unkeyed header.
- **VB-160** Web cache deception (`/account/profile.css`).
- **VB-161** XXE — XML import with external entities.
- **VB-162** Blind XXE / OOB data exfiltration.
- **VB-163** XXE billion-laughs DoS.
- **VB-164** SVG/HTML upload stored XSS (content sniffing).
- **VB-165** Content-type sniffing (`X-Content-Type-Options` missing).
- **VB-166** `postMessage` origin not validated (client-side).
- **VB-167** DOM clobbering.
- **VB-168** CSP bypass via JSONP/allowed CDN.
- **VB-169** Secrets stored in `localStorage`/`sessionStorage`.
- **VB-170** Sensitive data in browser cache/history (GET params).
- **VB-171** Insecure `window.name` data passing.
- **VB-172** HTTP Parameter Pollution (`?amount=1&amount=1000000`).
- **VB-173** Cross-Site WebSocket Hijacking (no origin check on `ws`).
- **VB-174** WebSocket message injection / missing authz.
- **VB-175** GraphQL introspection enabled (schema leak).
- **VB-176** GraphQL batching/aliasing brute force (bypass rate limit).
- **VB-177** GraphQL deeply-nested query DoS.
- **VB-178** GraphQL field-level authz missing (BFLA).

## Phase 13 — API Security (OWASP API Top 10 alignment)
- **VB-179** BOLA/IDOR at object level `/api/accounts/:id` (API1).
- **VB-180** Broken authentication on API tokens (API2).
- **VB-181** Broken object-property-level authz — mass assignment (API3).
- **VB-182** Excessive data exposure — API returns full object incl. secrets (API3).
- **VB-183** Unrestricted resource consumption — no rate limit/pagination (API4).
- **VB-184** Broken function-level authz — admin API callable by users (API5).
- **VB-185** Unrestricted access to sensitive business flow — bulk transfer (API6).
- **VB-186** SSRF via API URL parameter (API7, ties to Phase 10).
- **VB-187** Security misconfiguration on API (verbose errors, no headers) (API8).
- **VB-188** Improper inventory — old `/api/v1` unpatched alongside `/api/v2` (API9).
- **VB-189** Unsafe consumption of 3rd-party API data (API10).

## Phase 14 — Denial of Service & Resource Abuse
- **VB-190** ReDoS on login/search regex (ties to VB-053).
- **VB-191** Zip bomb / decompression bomb on import.
- **VB-192** Unbounded file upload size → disk exhaustion.
- **VB-193** Unbounded JSON body / array → memory exhaustion.
- **VB-194** Expensive query without pagination → CPU/DB exhaustion.
- **VB-195** Account-lockout abuse as DoS (lock victims out).

## Phase 15 — File Handling & Upload Attacks
- **VB-196** Zip Slip — path traversal on archive extraction.
- **VB-197** Image parsing exploit surface (ImageTragick-style) *(advanced)*.
- **VB-198** EXIF/metadata leak in uploaded images.
- **VB-199** Polyglot file (valid image + script) upload.
- **VB-200** Double-extension / null-byte upload bypass (`shell.php%00.jpg`).
- **VB-201** MIME-type spoof upload bypass.
- **VB-202** Arbitrary file read via filename in download endpoint (ties to VB-009).

## Phase 16 — Teaching Materials & Wrap-up
- Complete `docs/FINDINGS.md` — every VB-### with OWASP mapping, location (`file:line`), payload,
  step-by-step exploit, expected result, and remediation note.
- `docs/LAB-MANUAL.md` — per-category walkthroughs + blank student checklist/worksheet.
- `docs/SETUP.md` — run + safety instructions; `reseed` script for clean restarts.
- Smoke tests confirming each planted vuln fires.

---

## OWASP Top 10 (2021) → Finding coverage matrix
| OWASP | Findings |
|---|---|
| A01 Broken Access Control | VB-001…020, 153…155, 172, 179, 184 |
| A02 Cryptographic Failures | VB-055…074 |
| A03 Injection | VB-021…054, 161…163, 175…178 |
| A04 Insecure Design | VB-075…086 |
| A05 Security Misconfiguration | VB-105…120, 187 |
| A06 Vulnerable & Outdated Components | VB-121…129 |
| A07 Auth Failures | VB-087…104, 180 |
| A08 Integrity Failures | VB-130…137 |
| A09 Logging & Monitoring Failures | VB-146…152 |
| A10 SSRF | VB-138…145, 186 |

**Total: 200+ intentional, documented findings** covering every OWASP Top 10 (2021) category, the OWASP
API Security Top 10, plus CSRF, SSTI, XXE, open redirect, clickjacking, path traversal/LFI, file-upload
RCE, prototype pollution, host-header injection, CRLF, CSV/formula injection, insecure deserialization,
CORS abuse, full JWT attack suite, ReDoS/DoS, WebSocket & GraphQL flaws, and file-upload attack chains.
