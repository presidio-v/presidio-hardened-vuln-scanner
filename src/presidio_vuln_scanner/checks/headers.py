"""HTTP security header checks."""

from __future__ import annotations

import requests

_REQUIRED_HEADERS = {
    "Content-Security-Policy": "HIGH",
    "X-Frame-Options": "MEDIUM",
    "X-Content-Type-Options": "MEDIUM",
    "Strict-Transport-Security": "MEDIUM",
    "Referrer-Policy": "LOW",
}


def check(target: str) -> list[dict]:
    findings = []
    try:
        resp = requests.get(target.rstrip("/") + "/", timeout=5)
        for header, severity in _REQUIRED_HEADERS.items():
            if header not in resp.headers:
                findings.append(
                    {
                        "check": "headers",
                        "severity": severity,
                        "url": target,
                        "param": header,
                        "payload": None,
                        "evidence": f"Header '{header}' absent from response",
                        "description": f"Missing security header: {header}",
                    }
                )
    except requests.RequestException:
        pass
    return findings
