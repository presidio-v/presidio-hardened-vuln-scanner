"""Shared fixtures for vuln-scanner tests."""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))


@pytest.fixture(scope="session")
def vuln_client():
    import vulnerable_app.app as vapp  # type: ignore[import]

    # Reset module-level connection so init_db starts fresh
    vapp._DB_CONN = None
    vapp.app.config["TESTING"] = True
    vapp.init_db()
    with vapp.app.test_client() as client:
        yield client
