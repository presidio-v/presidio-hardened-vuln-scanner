"""Unit tests for scanner modules using mocked HTTP responses."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from presidio_vuln_scanner.checks import headers, sqli, xss
from presidio_vuln_scanner.exploit import run_exploit
from presidio_vuln_scanner.scanner import Finding, run_scan


def _mock_response(text: str, status_code: int = 200, resp_headers: dict | None = None):
    mock = MagicMock()
    mock.text = text
    mock.status_code = status_code
    mock.headers = resp_headers or {}
    return mock


class TestSqliCheck:
    def test_detects_data_leak(self):
        mock_resp = _mock_response("<ul><li>alice: $100</li></ul>")
        with patch("presidio_vuln_scanner.checks.sqli.requests.get", return_value=mock_resp):
            findings = sqli.check("http://localhost:5000")
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"

    def test_no_finding_on_empty_response(self):
        mock_resp = _mock_response("<p>No results</p>")
        with patch("presidio_vuln_scanner.checks.sqli.requests.get", return_value=mock_resp):
            findings = sqli.check("http://localhost:5000")
        assert findings == []


class TestXssCheck:
    def test_detects_reflection(self):
        payload = "<script>alert('XSS')</script>"
        mock_resp = _mock_response(f"<h1>Hello, {payload}!</h1>")
        with patch("presidio_vuln_scanner.checks.xss.requests.get", return_value=mock_resp):
            findings = xss.check("http://localhost:5000")
        assert len(findings) == 1
        assert findings[0]["check"] == "xss"

    def test_no_finding_when_escaped(self):
        mock_resp = _mock_response("<h1>Hello, &lt;script&gt;!</h1>")
        with patch("presidio_vuln_scanner.checks.xss.requests.get", return_value=mock_resp):
            findings = xss.check("http://localhost:5000")
        assert findings == []


class TestHeadersCheck:
    def test_missing_headers_flagged(self):
        mock_resp = _mock_response("<h1>App</h1>", resp_headers={})
        with patch("presidio_vuln_scanner.checks.headers.requests.get", return_value=mock_resp):
            findings = headers.check("http://localhost:5000")
        assert any(f["param"] == "Content-Security-Policy" for f in findings)

    def test_present_headers_not_flagged(self):
        all_headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000",
            "Referrer-Policy": "no-referrer",
        }
        mock_resp = _mock_response("<h1>App</h1>", resp_headers=all_headers)
        with patch("presidio_vuln_scanner.checks.headers.requests.get", return_value=mock_resp):
            findings = headers.check("http://localhost:5000")
        assert findings == []


class TestRunScan:
    def test_run_scan_returns_findings(self):
        with (
            patch(
                "presidio_vuln_scanner.checks.sqli.requests.get",
                return_value=_mock_response("<li>admin</li>"),
            ),
            patch(
                "presidio_vuln_scanner.checks.xss.requests.get",
                return_value=_mock_response("<script>alert('XSS')</script>"),
            ),
            patch(
                "presidio_vuln_scanner.checks.csrf.requests.post",
                return_value=_mock_response("Transferred", resp_headers={}),
            ),
            patch(
                "presidio_vuln_scanner.checks.auth.requests.post",
                return_value=_mock_response("invalid", status_code=200),
            ),
            patch(
                "presidio_vuln_scanner.checks.headers.requests.get",
                return_value=_mock_response("<h1>App</h1>", resp_headers={}),
            ),
        ):
            findings = run_scan("http://localhost:5000", checks=["sqli", "xss", "headers"])
        assert all(isinstance(f, Finding) for f in findings)

    def test_run_scan_unknown_check_skipped(self):
        findings = run_scan("http://localhost:5000", checks=["unknown_check"])
        assert findings == []


class TestExploit:
    def test_sqli_exploit(self):
        mock_resp = _mock_response("<li>alice</li>")
        with patch("presidio_vuln_scanner.exploit.requests.get", return_value=mock_resp):
            result = run_exploit("sqli", "http://localhost:5000", "' OR '1'='1")
        assert result["success"] is True

    def test_xss_exploit(self):
        payload = "<script>alert('XSS')</script>"
        mock_resp = _mock_response(payload)
        with patch("presidio_vuln_scanner.exploit.requests.get", return_value=mock_resp):
            result = run_exploit("xss", "http://localhost:5000", payload)
        assert result["reflected"] is True

    def test_unknown_vuln_raises(self):
        import pytest

        with pytest.raises(ValueError):
            run_exploit("unknown", "http://localhost:5000", "payload")
