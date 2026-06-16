"""Unit tests for GhidraSession lifecycle (pyghidra mocked out)."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from rom_analyzer.ghidra.session import GhidraSession


def _make_session() -> GhidraSession:
    mock_project = MagicMock()
    return GhidraSession(project=mock_project, project_name="test-proj")


def test_prog_name_for_is_deterministic(tmp_path):
    rom = tmp_path / "test.bin"
    rom.write_bytes(b"\x00" * 16)
    session = _make_session()
    name1 = session.prog_name_for(rom)
    name2 = session.prog_name_for(rom)
    assert name1 == name2
    assert "test.bin" in name1


def test_prog_name_for_includes_sha1_prefix(tmp_path):
    rom = tmp_path / "rom.bin"
    rom.write_bytes(b"\xAB\xCD" * 8)
    session = _make_session()
    name = session.prog_name_for(rom)
    # name is "<filename>-<6-char sha1>"
    parts = name.rsplit("-", 1)
    assert len(parts) == 2
    assert len(parts[1]) == 6


def test_context_manager_calls_close():
    mock_project = MagicMock()
    session = GhidraSession(project=mock_project, project_name="p")
    with session:
        pass
    mock_project.close.assert_called_once()


def test_context_manager_calls_close_on_exception():
    mock_project = MagicMock()
    session = GhidraSession(project=mock_project, project_name="p")
    with pytest.raises(ValueError):
        with session:
            raise ValueError("boom")
    mock_project.close.assert_called_once()
