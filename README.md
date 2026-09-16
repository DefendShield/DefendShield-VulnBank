# 🏦 Meridian Trust — Deliberately Vulnerable Banking App (Training Lab)

An **intentionally vulnerable** web application for teaching web penetration testing and the
**OWASP Top 10 (2021)**. Built for classroom use (DVWA/WebGoat-style).

> ⚠ **DO NOT DEPLOY.** Localhost teaching lab only. Contains real, exploitable vulnerabilities and
> fake seeded data. See safety rails in [docs/SETUP.md](docs/SETUP.md).

## Quick start
```bash
docker compose up --build      # http://127.0.0.1:3000
# or:  npm install && npm start
npm test                       # run the API/vulnerability test harness (101/101 on a clean run)
```

## Documentation
- **[docs/IMPLEMENTATION-PLAN.md](docs/IMPLEMENTATION-PLAN.md)** — full 200+ vulnerability catalogue, phased, mapped to OWASP.
- **[docs/FINDINGS.md](docs/FINDINGS.md)** — exploitation writeup with **Burp Suite / OWASP ZAP** step-by-step for every verified finding.
- **[docs/Meridian-Trust-FINDINGS.pdf](docs/Meridian-Trust-FINDINGS.pdf)** — printable PDF of the findings writeup (regenerate with `python3 scripts/make_pdf.py`).
- **[docs/Meridian-Trust-Lab-Handbook.pdf](docs/Meridian-Trust-Lab-Handbook.pdf)** — combined instructor handout: setup + catalogue + findings + lab manual (regenerate with `python3 scripts/make_combined_pdf.py`).
- **[docs/Meridian-Trust-Lab-Handbook-STUDENT.pdf](docs/Meridian-Trust-Lab-Handbook-STUDENT.pdf)** — student edition: setup + methodology + challenge objectives + worksheet, with payloads/steps/fixes redacted (regenerate with `python3 scripts/make_student_pdf.py`).
- **[docs/LAB-MANUAL.md](docs/LAB-MANUAL.md)** — instructor flow + student worksheet/checklist + grading rubric.
- **[docs/SETUP.md](docs/SETUP.md)** — install, run, reset, safety.

## OWASP Top 10 coverage (implemented & verified)
| OWASP | Examples in this app |
|-------|----------------------|
| A01 Broken Access Control | IDOR, mass assignment, admin bypass, path traversal, CORS |
| A02 Cryptographic Failures | plaintext creds, weak JWT secret, alg:none, predictable reset token |
| A03 Injection | SQLi, XSS (stored/reflected), command injection, SSTI, XXE |
| A04 Insecure Design | negative-amount transfer, race condition, foreign-account transfer |
| A05 Security Misconfiguration | debug/env leak, directory listing, missing headers, unrestricted upload |
| A06 Vulnerable Components | pinned CVE deps, prototype pollution |
| A07 Auth Failures | no lockout, user enumeration, session fixation, header-trust auth |
| A08 Integrity Failures | unsigned import, missing SRI, CSV injection |
| A09 Logging Failures | no auth/transfer/admin logging |
| A10 SSRF | avatar-by-URL, webhook tester, cloud-metadata reach |
