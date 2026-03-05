import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "docker: marks tests that require a running Docker daemon (skip with -m 'not docker')",
    )
