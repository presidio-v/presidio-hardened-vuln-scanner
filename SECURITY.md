# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes    |

## Reporting a Vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Email **security@presidio-group.eu** with description, reproduction steps, and impact.
Acknowledgement within 48 hours; resolution within 7 days.

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
