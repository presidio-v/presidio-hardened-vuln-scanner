"""Root scanner script for Experiment 3."""

from __future__ import annotations

import argparse

from presidio_vuln_scanner.scanner import run_scan


def main() -> None:
    parser = argparse.ArgumentParser(description="OWASP vulnerability scanner")
    parser.add_argument("--target", required=True)
    parser.add_argument(
        "--checks",
        nargs="+",
        choices=["sqli", "xss", "csrf", "auth", "headers"],
        default=["sqli", "xss", "csrf", "auth", "headers"],
    )
    parser.add_argument("--output", default="reports/dynamic_report.json")
    args = parser.parse_args()

    print(f"Scanning {args.target} ...")
    findings = run_scan(args.target, checks=args.checks, output=args.output)
    print(f"Found {len(findings)} issue(s). Report saved to {args.output}")
    for f in findings:
        print(f"  [{f.severity}] {f.check}: {f.description}")


if __name__ == "__main__":
    main()
