"""Shared pytest fixtures for rom-analyzer tests."""
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def golden_dir() -> Path:
    return Path(__file__).parent / "golden"


@pytest.fixture(scope="session")
def reference_dir() -> Path:
    return Path(__file__).parent.parent / "reference"
