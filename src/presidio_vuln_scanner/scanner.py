"""Scanner orchestrator: runs enabled checks and produces a JSON report."""

from __future__ import annotations

import enum
import json
import pathlib
from collections.abc import Sequence
from dataclasses import asdict, dataclass

from .checks import auth, csrf, headers, sqli, xss
from .security import log_security_event

_CHECK_MAP = {
    "sqli": sqli.check,
    "xss": xss.check,
    "csrf": csrf.check,
    "auth": auth.check,
    "headers": headers.check,
}


class Severity(str, enum.Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    check: str
    severity: str
    url: str
    param: str | None
    payload: str | None
    evidence: str
    description: str


def run_scan(
    target: str,
    checks: Sequence[str] | None = None,
    output: str | None = None,
) -> list[Finding]:
    if checks is None:
        checks = list(_CHECK_MAP.keys())

    all_findings: list[Finding] = []
    for name in checks:
        fn = _CHECK_MAP.get(name)
        if fn is None:
            continue
        raw = fn(target)
        for r in raw:
            all_findings.append(Finding(**r))

    log_security_event(
        "scan_complete",
        target=target,
        checks=",".join(checks),
        findings=len(all_findings),
    )

    if output:
        pathlib.Path(output).parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w") as f:
            json.dump([asdict(f_) for f_ in all_findings], f, indent=2)

    return all_findings
