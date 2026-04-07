# presidio-hardened-vuln-scanner

Web application vulnerability scanner with a deliberately vulnerable Flask app
and its hardened counterpart. Used in Experiment 3 of PRES-EDU-SEC-101.

> **Warning:** `vulnerable_app/` contains intentional security flaws.
> Never deploy it outside a local development environment.

## Setup

```bash
git clone https://github.com/presidio-v/presidio-hardened-vuln-scanner.git
cd presidio-hardened-vuln-scanner
pip install -r requirements.txt
```

## Phase A — Static Analysis

```bash
bandit -r vulnerable_app/ -f json -o reports/bandit_report.json -ll
bandit -r vulnerable_app/ -f txt
pip-audit --requirement vulnerable_app/requirements.txt \
          --output reports/pip_audit.json --format json
python report.py --phase static
```

Expected findings: hardcoded secret key, `eval`, insecure `subprocess`, MD5 hashing.

## Phase B — Dynamic Scanning

```bash
cd vulnerable_app && python app.py &
cd ..
python scanner.py --target http://localhost:5000 \
                  --checks sqli xss csrf auth headers \
                  --output reports/dynamic_report.json
python report.py --phase dynamic
```

Expected findings: SQL injection, reflected XSS, missing CSRF token, missing headers.

## Phase C — Manual Exploitation

```bash
python exploit.py --vuln sqli \
                  --payload "' OR '1'='1" \
                  --target http://localhost:5000

python exploit.py --vuln xss \
                  --payload "<script>alert('XSS')</script>" \
                  --target http://localhost:5000
```

## Phase D — Fix and Verify

```bash
kill %1
cd fixed_app && python app.py --port 5001 2>/dev/null || python app.py &
cd ..
bandit -r fixed_app/ -f txt
python scanner.py --target http://localhost:5001 \
                  --checks sqli xss csrf auth headers \
                  --output reports/dynamic_report_fixed.json
python report.py --compare vulnerable fixed
```

## What to Measure

- Findings before fix: count by severity (HIGH / MEDIUM / LOW)
- Findings after fix: should be zero HIGH
- Takeaway: static + dynamic analysis find different vulnerability classes

## License

MIT
