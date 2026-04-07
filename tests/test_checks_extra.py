"""Additional coverage for auth and csrf checks via mocking."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from presidio_vuln_scanner.checks import auth, csrf


def _resp(text: str = "", status_code: int = 200, headers: dict | None = None):
    m = MagicMock()
    m.text = text
    m.status_code = status_code
    m.headers = headers or {}
    return m


class TestCsrfCheck:
    def test_detects_missing_csrf(self):
        mock_post = _resp("Transferred", status_code=200)
        with patch("presidio_vuln_scanner.checks.csrf.requests.post", return_value=mock_post):
            findings = csrf.check("http://localhost:5000")
        assert any(f["check"] == "csrf" for f in findings)

    def test_no_finding_when_403(self):
        mock_post = _resp("Forbidden", status_code=403)
        with patch("presidio_vuln_scanner.checks.csrf.requests.post", return_value=mock_post):
            findings = csrf.check("http://localhost:5000")
        assert findings == []

    def test_no_finding_when_csrf_token_present(self):
        html = '<input type="hidden" name="csrf_token" value="abc123">'
        mock_post = _resp(html, status_code=200)
        with patch("presidio_vuln_scanner.checks.csrf.requests.post", return_value=mock_post):
            findings = csrf.check("http://localhost:5000")
        assert findings == []

    def test_request_error_silenced(self):
        import requests as req_lib

        with patch(
            "presidio_vuln_scanner.checks.csrf.requests.post",
            side_effect=req_lib.RequestException("timeout"),
        ):
            findings = csrf.check("http://localhost:5000")
        assert findings == []


class TestAuthCheck:
    def test_no_login_endpoint_returns_empty(self):
        mock_404 = _resp("Not found", status_code=404)
        with patch("presidio_vuln_scanner.checks.auth.requests.post", return_value=mock_404):
            findings = auth.check("http://localhost:5000")
        assert findings == []

    def test_detects_missing_rate_limit(self):
        mock_200 = _resp("invalid credentials", status_code=200)
        with patch("presidio_vuln_scanner.checks.auth.requests.post", return_value=mock_200):
            findings = auth.check("http://localhost:5000")
        assert any(f["check"] == "auth" for f in findings)

    def test_no_finding_when_429_returned(self):
        responses = [_resp("invalid", 200)] + [_resp("rate limited", 429)] * 6
        with patch("presidio_vuln_scanner.checks.auth.requests.post", side_effect=responses):
            findings = auth.check("http://localhost:5000")
        assert findings == []
