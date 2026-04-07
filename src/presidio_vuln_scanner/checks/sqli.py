"""SQL injection probes."""

from __future__ import annotations

import requests

_PAYLOADS = [
    ("' OR '1'='1", "username"),
    ("' OR 1=1--", "username"),
    ("'; SELECT 1--", "username"),
]
_ERROR_SIGNATURES = [
    "syntax error",
    "sqlite3.operationalerror",
    "unclosed",
    "sqlite",
]


def check(target: str) -> list[dict]:
    findings = []
    endpoint = target.rstrip("/") + "/search"
    for payload, param in _PAYLOADS:
        try:
            resp = requests.get(endpoint, params={"q": payload}, timeout=5)
            body = resp.text.lower()
            is_error = any(sig in body for sig in _ERROR_SIGNATURES)
            is_data_leak = "<li>" in resp.text and resp.status_code == 200
            if is_error or is_data_leak:
                findings.append(
                    {
                        "check": "sqli",
                        "severity": "HIGH",
                        "url": endpoint,
                        "param": param,
                        "payload": payload,
                        "evidence": resp.text[:200],
                        "description": (
                            "SQL injection: application returned data or error"
                            " for injected payload"
                        ),
                    }
                )
                break
        except requests.RequestException:
            pass
    return findings
