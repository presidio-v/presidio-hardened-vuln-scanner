"""Security utilities: structured logging."""

from __future__ import annotations

import logging
import sys

logger = logging.getLogger("presidio_vuln_scanner")


def setup_logging(level: int = logging.INFO) -> None:
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        logger.addHandler(handler)
    logger.setLevel(level)


def log_security_event(event: str, **kwargs: object) -> None:
    parts = " ".join(f"{k}={v}" for k, v in kwargs.items())
    logger.info("SECURITY_EVENT event=%s %s", event, parts)
