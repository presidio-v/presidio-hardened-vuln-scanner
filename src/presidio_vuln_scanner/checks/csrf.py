"""CSRF protection checks."""

from __future__ import annotations

import requests
from bs4 import BeautifulSoup


def check(target: str) -> list[dict]:
    findings = []
    endpoints = [
        (target.rstrip("/") + "/transfer", "POST"),
        (target.rstrip("/") + "/register", "POST"),
    ]
    for url, method in endpoints:
        try:
            if method == "POST":
                resp = requests.post(url, data={"amount": "1", "to": "test"}, timeout=5)
            else:
                resp = requests.get(url, timeout=5)

            soup = BeautifulSoup(resp.text, "html.parser")
            csrf_inputs = soup.find_all(
                "input",
                attrs={"name": lambda n: n and "csrf" in n.lower()},
            )
            has_403 = resp.status_code == 403

            if not csrf_inputs and not has_403 and resp.status_code < 500:
                findings.append(
                    {
                        "check": "csrf",
                        "severity": "MEDIUM",
                        "url": url,
                        "param": method,
                        "payload": None,
                        "evidence": f"POST accepted without CSRF token, status={resp.status_code}",
                        "description": (
                            "Missing CSRF protection: state-changing endpoint"
                            " accepts requests without token"
                        ),
                    }
                )
        except requests.RequestException:
            pass
    return findings
