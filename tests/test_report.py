"""Tests for the report module."""

from __future__ import annotations

import json
import pathlib

import pytest

from presidio_vuln_scanner.report import (
    _load_json,
    _print_findings,
    _severity_counts,
    report_compare,
    report_dynamic,
    report_static,
)


@pytest.fixture(autouse=True)
def tmp_reports(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "reports").mkdir()
    return tmp_path


def _write_json(path: pathlib.Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f)


def test_load_json_missing_returns_empty(tmp_path):
    result = _load_json("reports/nonexistent.json")
    assert result == []


def test_severity_counts():
    findings = [
        {"severity": "HIGH"},
        {"severity": "HIGH"},
        {"severity": "MEDIUM"},
    ]
    counts = _severity_counts(findings)
    assert counts["HIGH"] == 2
    assert counts["MEDIUM"] == 1
    assert counts["LOW"] == 0


def test_print_findings_empty(capsys):
    _print_findings([])
    out = capsys.readouterr().out
    assert "No findings" in out


def test_print_findings_with_data(capsys):
    findings = [
        {
            "severity": "HIGH",
            "check": "sqli",
            "description": "SQL injection found",
            "url": "http://localhost/search",
            "payload": "' OR '1'='1",
        }
    ]
    _print_findings(findings)
    out = capsys.readouterr().out
    assert "sqli" in out
    assert "SQL injection" in out


def test_report_static_no_file(capsys):
    report_static("reports/missing.json")
    out = capsys.readouterr().out
    assert "No bandit report" in out


def test_report_static_with_results(capsys, tmp_path):
    data = {
        "results": [
            {
                "test_id": "B105",
                "issue_text": "Hardcoded secret",
                "issue_severity": "HIGH",
                "filename": "app.py",
                "line_number": 5,
            }
        ]
    }
    _write_json(tmp_path / "reports" / "bandit_report.json", data)
    report_static("reports/bandit_report.json")
    out = capsys.readouterr().out
    assert "B105" in out or "HIGH" in out


def test_report_dynamic_no_file(capsys):
    report_dynamic("reports/missing.json")
    out = capsys.readouterr().out
    assert "No findings" in out


def test_report_dynamic_with_findings(capsys, tmp_path):
    findings = [
        {"severity": "HIGH", "check": "sqli", "description": "SQL injection", "url": "http://x"},
        {"severity": "MEDIUM", "check": "csrf", "description": "CSRF", "url": "http://x"},
    ]
    _write_json(tmp_path / "reports" / "dynamic_report.json", findings)
    report_dynamic("reports/dynamic_report.json")
    out = capsys.readouterr().out
    assert "2" in out


def test_report_compare_pass(capsys, tmp_path):
    before = [
        {
            "severity": "HIGH",
            "check": "sqli",
            "description": "SQLi",
            "url": "http://x",
            "payload": None,
            "evidence": "",
        },
        {
            "severity": "MEDIUM",
            "check": "headers",
            "description": "Headers",
            "url": "http://x",
            "payload": None,
            "evidence": "",
        },
    ]
    after: list = []
    _write_json(tmp_path / "reports" / "dynamic_report.json", before)
    _write_json(tmp_path / "reports" / "dynamic_report_fixed.json", after)
    report_compare("vulnerable", "fixed")
    out = capsys.readouterr().out
    assert "PASS" in out


def test_report_compare_fail(capsys, tmp_path):
    before = [
        {
            "severity": "HIGH",
            "check": "sqli",
            "description": "SQLi",
            "url": "http://x",
            "payload": None,
            "evidence": "",
        }
    ]
    after = [
        {
            "severity": "HIGH",
            "check": "sqli",
            "description": "SQLi still",
            "url": "http://x",
            "payload": None,
            "evidence": "",
        }
    ]
    _write_json(tmp_path / "reports" / "dynamic_report.json", before)
    _write_json(tmp_path / "reports" / "dynamic_report_fixed.json", after)
    report_compare("vulnerable", "fixed")
    out = capsys.readouterr().out
    assert "FAIL" in out
