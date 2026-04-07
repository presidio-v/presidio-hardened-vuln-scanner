"""Root report script for Experiment 3."""

from __future__ import annotations

import argparse

from presidio_vuln_scanner.report import report_compare, report_dynamic, report_static


def main() -> None:
    parser = argparse.ArgumentParser(description="Experiment 3 report generator")
    parser.add_argument("--phase", choices=["static", "dynamic"])
    parser.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"))
    args = parser.parse_args()

    if args.phase == "static":
        report_static()
    elif args.phase == "dynamic":
        report_dynamic()
    elif args.compare:
        report_compare(args.compare[0], args.compare[1])
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
