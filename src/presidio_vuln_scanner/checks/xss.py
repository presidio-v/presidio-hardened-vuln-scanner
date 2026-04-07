"""Reflected XSS probes."""

from __future__ import annotations

import requests

_PAYLOADS = [
    "<script>alert('XSS')</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
]


def check(target: str) -> list[dict]:
    findings = []
    endpoint = target.rstrip("/") + "/profile"
    for payload in _PAYLOADS:
        try:
            resp = requests.get(endpoint, params={"name": payload}, timeout=5)
            if payload in resp.text:
                findings.append(
                    {
                        "check": "xss",
                        "severity": "HIGH",
                        "url": endpoint,
                        "param": "name",
                        "payload": payload,
                        "evidence": resp.text[:200],
                        "description": "Reflected XSS: payload echoed unsanitized in response",
                    }
                )
                break
        except requests.RequestException:
            pass
    return findings
