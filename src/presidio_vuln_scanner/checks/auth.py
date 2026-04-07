"""Authentication checks: missing lockout, response differentiation."""

from __future__ import annotations

import requests

_LOGIN_PATHS = ["/login", "/auth", "/signin"]
_ATTEMPTS = 6


def check(target: str) -> list[dict]:
    findings = []
    base = target.rstrip("/")

    for path in _LOGIN_PATHS:
        url = base + path
        try:
            resp = requests.post(
                url,
                data={"username": "admin", "password": "wrongpassword"},
                timeout=3,
            )
            if resp.status_code not in (404, 405):
                statuses = []
                for _ in range(_ATTEMPTS):
                    r = requests.post(
                        url,
                        data={"username": "admin", "password": "wrongpassword"},
                        timeout=3,
                    )
                    statuses.append(r.status_code)

                if 429 not in statuses:
                    findings.append(
                        {
                            "check": "auth",
                            "severity": "MEDIUM",
                            "url": url,
                            "param": None,
                            "payload": None,
                            "evidence": f"6 rapid login attempts; statuses={statuses}",
                            "description": (
                                "No rate limiting on login endpoint — brute force possible"
                            ),
                        }
                    )
                break
        except requests.RequestException:
            pass
    return findings
