"""Report renderer for static, dynamic, and comparison phases."""

from __future__ import annotations

import json
import pathlib


def _load_json(path: str) -> list:
    p = pathlib.Path(path)
    if not p.exists():
        return []
    with open(p) as f:
        return json.load(f)


def _severity_counts(findings: list) -> dict:
    counts: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _print_findings(findings: list) -> None:
    if not findings:
        print("  No findings.")
        return
    for f in findings:
        print(f"  [{f.get('severity', '?')}] {f.get('check', '?')} — {f.get('description', '')}")
        if f.get("url"):
            print(f"         URL: {f['url']}")
        if f.get("payload"):
            print(f"         Payload: {f['payload']}")


def report_static(bandit_path: str = "reports/bandit_report.json") -> None:
    print("\n========================================")
    print("  Phase A — Static Analysis (bandit)")
    print("========================================\n")
    data = _load_json(bandit_path)
    if not data:
        print("  No bandit report found. Run bandit first.")
        return
    results = data.get("results", data) if isinstance(data, dict) else data
    by_severity: dict[str, list] = {}
    for issue in results:
        sev = issue.get("issue_severity", "UNDEFINED")
        by_severity.setdefault(sev, []).append(issue)

    for sev in ("HIGH", "MEDIUM", "LOW"):
        issues = by_severity.get(sev, [])
        print(f"  {sev}: {len(issues)} issue(s)")
        for i in issues:
            tid = i.get("test_id", "")
            text = i.get("issue_text", "")
            fname = i.get("filename", "")
            lineno = i.get("line_number", "")
            print(f"    [{tid}] {text} — {fname}:{lineno}")
    print()


def report_dynamic(dynamic_path: str = "reports/dynamic_report.json") -> None:
    print("\n========================================")
    print("  Phase B — Dynamic Scan")
    print("========================================\n")
    findings = _load_json(dynamic_path)
    counts = _severity_counts(findings)
    print(f"  Total findings: {len(findings)}")
    for sev, cnt in counts.items():
        print(f"    {sev}: {cnt}")
    print()
    _print_findings(findings)
    print()


def report_compare(name_a: str, name_b: str) -> None:
    path_a = "reports/dynamic_report.json"
    path_b = "reports/dynamic_report_fixed.json"
    print("\n========================================")
    print(f"  Comparison: {name_a}  vs  {name_b}")
    print("========================================\n")

    fa = _load_json(path_a)
    fb = _load_json(path_b)
    ca = _severity_counts(fa)
    cb = _severity_counts(fb)

    print(f"  {'Severity':<10} {'Before':>8} {'After':>8} {'Delta':>8}")
    print(f"  {'-' * 38}")
    for sev in ("HIGH", "MEDIUM", "LOW"):
        delta = cb.get(sev, 0) - ca.get(sev, 0)
        print(f"  {sev:<10} {ca.get(sev, 0):>8} {cb.get(sev, 0):>8} {delta:>+8}")
    print()
    if cb.get("HIGH", 0) == 0:
        print("  Result: PASS — zero HIGH findings in fixed app.")
    else:
        print("  Result: FAIL — HIGH findings remain in fixed app.")
    print()
