"""presidio-hardened-vuln-scanner: OWASP-focused web application vulnerability scanner."""

from .scanner import Finding, Severity, run_scan
from .security import log_security_event, setup_logging

__version__ = "0.1.0"
__all__ = ["Finding", "Severity", "run_scan", "setup_logging", "log_security_event"]

setup_logging()
