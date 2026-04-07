"""Tests confirming the vulnerable app has the expected vulnerabilities."""


def test_sqli_returns_all_users(vuln_client):
    resp = vuln_client.get("/search?q=' OR '1'='1")
    assert resp.status_code == 200
    assert b"<li>" in resp.data


def test_xss_reflects_payload(vuln_client):
    payload = "<script>alert('XSS')</script>"
    resp = vuln_client.get(f"/profile?name={payload}")
    assert resp.status_code == 200
    assert payload.encode() in resp.data


def test_transfer_accepts_without_csrf(vuln_client):
    resp = vuln_client.post("/transfer", data={"amount": "10", "to": "eve"})
    assert resp.status_code == 200
    assert b"Transferred" in resp.data


def test_debug_eval_executes(vuln_client):
    resp = vuln_client.get("/debug?expr=2*2")
    assert resp.status_code == 200
    assert b"4" in resp.data
