# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes    |

## Reporting a Vulnerability

Please report security vulnerabilities by opening a private GitHub Security Advisory
(via the "Security" tab → "Report a vulnerability") rather than a public issue.

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgement within 5 business days. We aim to release a patch
within 30 days of a confirmed vulnerability.

## Important Notice

`vulnerable_app/` contains **intentional security vulnerabilities** for educational
use. It must never be deployed to a network-accessible server.

## Security Features (scanner and fixed app)

| Feature | Description |
|---|---|
| **Input validation** | Target URL validated before any HTTP request |
| **No shell execution** | Scanner never invokes shell commands |
| **Flask-Talisman** | CSP, HSTS, X-Frame-Options on fixed app |
| **Flask-WTF CSRF** | CSRF tokens on all state-changing endpoints in fixed app |
| **Argon2id** | Password hashing in fixed app |
| **Parameterized SQL** | All queries use `?` placeholders in fixed app |
| **Security logging** | Structured events for scan and exploit operations |

## Software Development Lifecycle

This repository is developed under the Presidio hardened-family SDLC. The public report
— scope, standards mapping, threat-model gates, and supply-chain controls — is at
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
