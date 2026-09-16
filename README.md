# 🏦 Meridian Trust — Deliberately Vulnerable Banking App (Training Lab)

An **intentionally vulnerable** web application for teaching web penetration testing and the
**OWASP Top 10 (2021)**. Built for classroom use (DVWA/WebGoat-style).

> ⚠ **DO NOT DEPLOY.** Localhost teaching lab only. Contains real, exploitable vulnerabilities and
> fake seeded data. See safety rails in [docs/SETUP.md](docs/SETUP.md).

## Running steps

**Requirements:** Node.js 20+ (and npm), or Docker + Docker Compose. Runs on `127.0.0.1` only.

### 1. Get the code
```bash
git clone https://github.com/DefendShield/DefendShield-VulnBank
cd DefendShield-VulnBank
```

### 2. Run it — pick one

**Option A — Docker (recommended):**
```bash
docker compose up --build
```

**Option B — Node directly:**
```bash
npm install
npm start                 # default port 3000
# PORT=3001 npm start     # use another port if 3000 is busy
```

### 3. Open the app
Browse to **http://127.0.0.1:3000** (or `:3001` if you set `PORT`).

Sample logins (simulated data — intentionally weak):

| Username | Password | Role |
|----------|----------|------|
| admin    | admin      | admin |
| alice    | password1  | customer |
| bob      | hunter2    | customer |

### 4. (Optional) Run the test harness
```bash
npm run reseed            # reset to a clean state first
npm test                  # 101/101 automated checks (14 manual/client-side skips)
```

### 5. Reset between sessions
```bash
npm run reseed            # wipe & re-seed fake data for a clean lab
```

> **Docker on Kali/Linux:** if `docker compose build` fails with a `docker-credential-desktop` error,
> run `sed -i '/"credsStore": "desktop"/d' ~/.docker/config.json` and retry. See [docs/SETUP.md](docs/SETUP.md).

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

## License & disclaimer

Licensed under the [MIT License](LICENSE).

> **Training-lab disclaimer.** This software is **intentionally vulnerable** and is provided solely for
> authorized security education, teaching, and research in an **isolated environment**. Do **not** deploy it
> to any public, shared, or production network. Only use it against systems you own or are explicitly
> authorized to test. The authors accept no liability for misuse or for any damage resulting from
> deployment outside a controlled lab.
