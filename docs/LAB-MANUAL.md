# Meridian Trust — Instructor Lab Manual & Student Checklist

A suggested teaching flow mapped to the OWASP Top 10 (2021). Full exploit steps with proxy-tool
instructions are in [FINDINGS.md](FINDINGS.md).

## Suggested session order (2–4 lab sessions)
1. **Recon & proxy setup** — configure Burp/ZAP, map the app, read `/robots.txt`, `/version`.
2. **A01 Access Control** — IDOR, mass assignment, admin panel, path traversal.
3. **A03 Injection** — SQLi, XSS, command injection, SSTI, XXE.
4. **A02 & A07 Crypto/Auth** — JWT attacks, plaintext creds, brute force, session flaws.
5. **A04/A05/A06** — business logic, misconfig, vulnerable components.
6. **A08/A09/A10** — integrity, logging gaps, SSRF.

## Student worksheet (fill in as you go)
For each finding: record the **request** (from proxy history), the **payload**, the **evidence**
(response snippet/screenshot), the **impact**, and the **remediation**.

| # | OWASP | Vulnerability | Endpoint | Payload used | Evidence | Impact | Fix |
|---|-------|---------------|----------|--------------|----------|--------|-----|
| VB-001 | A01 | IDOR – account | `/account/:id` | | | | |
| VB-007 | A01 | Mass assignment | `POST /profile/:id` | | | | |
| VB-005 | A01 | Missing func-level authz | `/admin` | | | | |
| VB-009 | A01 | Path traversal | `/download?file=` | | | | |
| VB-021 | A03 | SQLi login bypass | `POST /login` | | | | |
| VB-022 | A03 | UNION SQLi | `/search?q=` | | | | |
| VB-030 | A03 | Stored XSS | `POST /transfer` memo | | | | |
| VB-040 | A03 | Command injection | `POST /admin/ping` | | | | |
| VB-043 | A03 | SSTI | `/greet` | | | | |
| VB-161 | A03 | XXE | `POST /import/xml` | | | | |
| VB-055 | A02 | Plaintext passwords | `/api/v1/users` | | | | |
| VB-059 | A02 | Weak JWT secret | `POST /api/login` | | | | |
| VB-014 | A02 | JWT alg:none | `/api/users` | | | | |
| VB-065 | A02 | Predictable reset token | `POST /reset` | | | | |
| VB-075 | A04 | Negative transfer | `POST /transfer` | | | | |
| VB-077 | A04 | Race condition | `POST /transfer` | | | | |
| VB-106 | A05 | Debug/env exposure | `/debug` | | | | |
| VB-114 | A05 | Unrestricted upload | `POST /upload` | | | | |
| VB-124 | A06 | Prototype pollution | `POST /profile/:id` | | | | |
| VB-087 | A07 | Brute force / no lockout | `POST /login` | | | | |
| VB-101 | A07 | Header-trust auth | any + `X-User-Id` | | | | |
| VB-138 | A10 | SSRF avatar-by-URL | `/avatar/fetch?url=` | | | | |
| VB-140 | A10 | SSRF webhook | `POST /webhook` | | | | |
| VB-044 | A03 | NoSQL/object injection | `POST /nosql-login` | | | | |
| VB-023 | A03 | Blind/time SQLi | `/blind?id=` | | | | |
| VB-025 | A03 | Second-order SQLi | `/so/set-nick`,`/so/lookup` | | | | |
| VB-026 | A03 | Header SQLi | `/track` (User-Agent) | | | | |
| VB-053 | A03 | ReDoS | `/validate?email=` | | | | |
| VB-062 | A02 | JWT alg confusion | `/jwt/rs256/whoami` | | | | |
| VB-060 | A02 | JWT kid injection | `/jwt/kid/whoami` | | | | |
| VB-175 | A03 | GraphQL introspection/BOLA | `/graphql` | | | | |
| VB-130 | A08 | Insecure deserialization | `/integrity/prefs/load` | | | | |
| VB-196 | A08 | Zip Slip | `POST /integrity/import-zip` | | | | |
| VB-135 | A08 | CSV formula injection | `/integrity/export.csv` | | | | |
| VB-068 | A02 | AES-ECB leakage | `/crypto/ecb` | | | | |
| VB-072 | A02 | Reversible token | `/crypto/whoami` | | | | |
| VB-098 | A07 | OTP bypass/brute | `/otp/mfa/*` | | | | |
| VB-173 | A01 | WebSocket hijacking | `ws:///ws` | | | | |
| VB-049 | A03 | SSI injection | `/ssi?tpl=` | | | | |
| VB-048 | A03 | LDAP injection | `/ldap?user=` | | | | |
| VB-029 | A03 | Stacked-query SQLi | `/note?data=` | | | | |
| VB-028 | A03 | ORDER BY SQLi | `/sortusers?order=` | | | | |
| VB-042 | A03 | Argument injection | `/archive?path=` | | | | |
| VB-172 | A04 | HTTP Parameter Pollution | `/pay?amount=` | | | | |
| VB-104 | A04 | Password change no current | `POST /account/password` | | | | |
| VB-085 | A04 | Client-trusted price | `POST /shop/buy` | | | | |
| VB-086 | A04 | Voucher enumeration | `/voucher?code=` | | | | |
| VB-080 | A04 | Currency rounding abuse | `/fx?amount=` | | | | |
| VB-136 | A08 | Unverified webhook sig | `POST /integrity/webhook/receive` | | | | |
| VB-071 | A02 | Hash length-extension | `/crypto/sign`,`/crypto/verify` | | | | |
| VB-103 | A01 | OAuth redirect_uri/state | `/oauth/authorize` | | | | |
| VB-159 | A05 | Cache poisoning | `/home-banner` (X-Forwarded-Host) | | | | |
| VB-160 | A05 | Cache deception | `/account-info/*.css` | | | | |
| VB-165 | A05 | Content-type sniffing | `/raw?body=` | | | | |
| VB-032 | A03 | DOM XSS | `/client#...` | | | | |
| VB-157 | A05 | Reverse tabnabbing | `/client` | | | | |
| VB-166 | A05 | postMessage no origin | `/client` | | | | |
| VB-167 | A05 | DOM clobbering | `/client` | | | | |
| VB-169 | A02 | Secrets in localStorage | `/client` | | | | |
| VB-070 | A02 | Padding oracle | `/crypto/po/*` | | | | |
| VB-046 | A09 | Log injection | `/track-event`,`/logs` | | | | |
| VB-050 | A03 | SMTP header injection | `/contact` | | | | |
| VB-047 | A03 | XPath injection | `/xpath?user=` | | | | |
| VB-194 | A04 | Expensive-query DoS | `/report?n=` | | | | |
| VB-145 | A10 | SSRF file:// + bypass | `/proxy?url=` | | | | |
| VB-034 | A03 | 404 reflected XSS | `/<payload>` | | | | |
| VB-035 | A03 | Referer XSS | `/welcome` | | | | |
| VB-038 | A03 | JSON-as-HTML XSS | `/api-echo?q=` | | | | |
| VB-154 | A01 | CSRF via GET | `/quick-transfer` | | | | |
| VB-092 | A07 | Timing user enum | `/user-check?u=` | | | | |
| VB-198 | A05 | EXIF not stripped | `/exif?file=` | | | | |
| VB-206 | A01 | GraphQL mutation no authz | `POST /graphql` | | | | |
| VB-208 | A01 | No-auth PUT mass assign | `PUT /user/:id` | | | | |
| VB-209 | A01 | IDOR by account number | `/api/acct?num=` | | | | |
| VB-210 | A05 | Reflected File Download | `/statement/export?name=` | | | | |
| VB-211 | A03 | Stored XSS via username | `/admin/recent` | | | | |
| VB-212 | A06 | Proto-pollution privesc | `/profile` → `/feature/flags` | | | | |
| VB-213 | A03 | Billion-laughs XML bomb | `POST /import/xml2` | | | | |
| VB-214 | A07 | Forgeable remember-me | `/remember?user=` | | | | |

## Grading rubric (suggested)
- **Discovery** (found it via proxy): 40%
- **Exploitation** (working PoC): 40%
- **Remediation** (correct fix described): 20%
