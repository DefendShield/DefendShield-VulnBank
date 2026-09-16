# Meridian Trust — Setup & Safety

> ⚠ **INTENTIONALLY VULNERABLE.** Never deploy to a public network, shared host, or the internet.
> Run only on an isolated lab machine / VM bound to localhost.

## Run with Docker (recommended)
```bash
cd DefendShield-VulnBank
docker compose up --build
# App: http://127.0.0.1:3000   (bound to 127.0.0.1 only)
```

### Docker gotcha on Kali/Linux (`docker-credential-desktop` error)
If `docker compose build` fails with
`error getting credentials ... docker-credential-desktop ... not found`, your `~/.docker/config.json`
references the Docker Desktop credential helper. Fix by removing the `credsStore` line:
```bash
# edit ~/.docker/config.json and delete the line:   "credsStore": "desktop",
# (or, quick one-liner:)
sed -i '/"credsStore": "desktop"/d' ~/.docker/config.json
docker compose up --build
```

## Run with Node directly
```bash
cd DefendShield-VulnBank
npm install
npm start                 # http://127.0.0.1:3000
PORT=3001 npm start       # use another port if 3000 is busy
```

## Verify the lab (API test harness)
An automated harness exercises each planted vulnerability over HTTP and reports PASS/FAIL — useful for
regression testing after changes and as API-testing examples for students.
```bash
npm test                                  # tests http://127.0.0.1:3001 by default
BASE=http://127.0.0.1:3000 npm test       # target a different port
```
Run `npm run reseed` and restart first for a clean, repeatable run (some tests mutate data & pollute the
process). A clean run reports `101/101 automated passed, 0 failed, 14 manual/skipped`. The 14 skips are
client-side (DOM XSS, tabnabbing, postMessage, DOM clobbering, localStorage), browser-CSRF, or DoS/timing
checks (ReDoS, race condition, unbounded body, time-based SQLi) that must be verified by hand — the harness
lists each with a reason.

## Reset the lab between students
```bash
npm run reseed            # wipes db/vulnbank.sqlite and re-seeds fake data
```

## Seed accounts
| Username | Password   | Role   |
|----------|------------|--------|
| admin    | admin      | admin  |
| support  | support123 | support|
| alice    | password1  | user   |
| bob      | hunter2    | user   |
| carol    | letmein    | user   |

## Proxy tooling
Configure Burp Suite or OWASP ZAP as an HTTP proxy on `127.0.0.1:8080` and point your browser at it.
Full step-by-step exploitation is in [FINDINGS.md](FINDINGS.md). Recommended Burp extensions:
**JWT Editor**, **Turbo Intruder**, **Logger++**.

## Safety rails built in
- Binds to `127.0.0.1` in `docker-compose.yml`.
- Loud red "VULNERABLE" banner on every page.
- Only fake, seeded data — no real PII.
- `reseed` script for a clean, repeatable classroom state.
