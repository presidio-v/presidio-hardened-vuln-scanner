# Presidio-Hardened Vuln Scanner — Requirements

## Overview

`presidio-hardened-vuln-scanner` provides a complete lab environment for
Experiment 3 of PRES-EDU-SEC-101 (Computer Security). It ships:

1. A deliberately vulnerable Flask application (`vulnerable_app/`) containing
   known OWASP Top 10 flaws for scanning and exploitation exercises.
2. A fixed Flask application (`fixed_app/`) with all flaws remediated.
3. A Python scanner (`scanner.py`) that probes HTTP endpoints for SQLi, XSS,
   CSRF, authentication, and missing security headers.
4. An exploit confirmation script (`exploit.py`) that demonstrates SQLi and XSS.
5. A report generator (`report.py`) for static, dynamic, and comparison output.

## Mandatory Presidio Security Extensions

- Scanner input validation: target URL validated before requests are sent
- No execution of user-supplied code or shell commands in the scanner
- Security event logging for all scan and exploit operations
- Fixed app uses: Flask-Talisman (security headers), Flask-WTF CSRF, Argon2id password hashing, parameterized SQL
- Full GitHub security files: SECURITY.md, .github/dependabot.yml, .github/workflows/codeql.yml

## Technical Requirements

- Python 3.10+
- `requests`, `beautifulsoup4` as runtime deps
- `src/presidio_vuln_scanner/` layout with `checks/` subpackage
- pytest ≥80% coverage
- ruff lint + format enforced
- MIT License, version 0.1.2

## Intentional Vulnerabilities in vulnerable_app/

| Flaw | Location | bandit rule | OWASP 2021 |
|---|---|---|---|
| Hardcoded secret key | `app.secret_key` | B105 | A02 |
| `eval()` usage | `/debug` route | B307 | A03 |
| `subprocess(shell=True)` | `/admin` route | B602 | A03 |
| MD5 password hashing | `/register` route | B324 | A02 |
| SQL injection | `/search` route | B608 | A03 |
| Reflected XSS | `/profile` route | B701 | A03 |
| Missing CSRF token | `/transfer` route | — | A01 |
| Missing security headers | all routes | — | A05 |

## Version Deliberation Log

### v0.1.0 — Initial release

**Scope decision:** The scanner is a simple HTTP fuzzer, not a full-featured
tool like ZAP or Burp. It is designed to be readable and debuggable by students
in one session. The educational value is in understanding *how* detection works,
not in having an exhaustive scanner.

**Scope decision:** The vulnerable app uses SQLite in-memory to avoid any
external database dependency. This means the app resets its state on each
restart, which is fine for the exercise.
### v0.1.1 — fixed_app database lifecycle (release/0.1.x)

**Fix:** `fixed_app` now initialises its database at import (the lab starts it with
`from fixed_app.app import app`), seeds the `vulnerable_app` demo users so a benign search is
a positive control, and no route closes the shared connection. Before, every `/search` on the
fixed app returned 500, and a scan reported it SQLi-clean for the wrong reason. Output escaping
is deliberately unchanged on this line: the course's adversarial step teaches those sinks.

### v0.1.2 — main after v0.1.1

**Version decision:** `main` carries the same database fix plus output escaping on every
`fixed_app` response. It is versioned above the 0.1.1 already on PyPI; the packaged scanner
(`src/`) is unchanged since 0.1.0.

<!-- Deliver the complete working project ready for GitHub publish. -->

## SDLC

These requirements are delivered under the family-wide Presidio SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
