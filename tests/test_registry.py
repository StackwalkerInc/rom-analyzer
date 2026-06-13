from pathlib import Path

import pytest

from rom_analyzer.registry import (
    ReferenceEntry, load_registry, select_references, partition_available,
)


def _write_registry(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "registry.toml"
    p.write_text(body)
    return p


def test_load_registry_parses_entry(tmp_path):
    (tmp_path / "33520003.json").write_text("{}")
    reg = _write_registry(tmp_path, """
[[reference]]
id = "33520003"
json = "33520003.json"
rom = "z27ag.bin"
family = "z27ag"
variant = "fp8000"
priority = 100
features = ["obd", "mut"]
notes = "primary"
""")
    entries = load_registry(reg)
    assert len(entries) == 1
    e = entries[0]
    assert e.id == "33520003"
    assert e.json_path == tmp_path / "33520003.json"
    assert e.rom_path == tmp_path.parent / "roms" / "z27ag.bin"
    assert e.family == "z27ag"
    assert e.variant == "fp8000"
    assert e.priority == 100
    assert e.features == ["obd", "mut"]


def test_load_registry_missing_json_is_error(tmp_path):
    reg = _write_registry(tmp_path, """
[[reference]]
id = "x"
json = "nope.json"
rom = "x.bin"
family = "f"
variant = "fp8000"
priority = 1
""")
    with pytest.raises(FileNotFoundError):
        load_registry(reg)


def test_load_registry_defaults_optional_fields(tmp_path):
    (tmp_path / "a.json").write_text("{}")
    reg = _write_registry(tmp_path, """
[[reference]]
id = "a"
json = "a.json"
rom = "a.bin"
family = "f"
variant = "fp8000"
""")
    e = load_registry(reg)[0]
    assert e.priority == 0
    assert e.features == []
    assert e.notes == ""


def _entry(id, variant="fp8000", priority=0):
    return ReferenceEntry(id=id, json_path=Path(f"{id}.json"),
                          rom_path=Path(f"{id}.bin"), family="f",
                          variant=variant, priority=priority, features=[], notes="")


def test_select_filters_by_variant():
    entries = [_entry("a", "fp8000"), _entry("b", "fpc000")]
    got = select_references(entries, variant="fp8000", include_ids=[], exclude_ids=[])
    assert [e.id for e in got] == ["a"]


def test_select_include_ids_restricts():
    entries = [_entry("a"), _entry("b"), _entry("c")]
    got = select_references(entries, variant="fp8000", include_ids=["b", "c"], exclude_ids=[])
    assert {e.id for e in got} == {"b", "c"}


def test_select_exclude_ids_drops():
    entries = [_entry("a"), _entry("b")]
    got = select_references(entries, variant="fp8000", include_ids=[], exclude_ids=["a"])
    assert [e.id for e in got] == ["b"]


def test_select_sorted_by_priority_desc():
    entries = [_entry("a", priority=10), _entry("b", priority=50), _entry("c", priority=30)]
    got = select_references(entries, variant="fp8000", include_ids=[], exclude_ids=[])
    assert [e.id for e in got] == ["b", "c", "a"]


def test_partition_available_splits_on_rom_existence(tmp_path):
    present = tmp_path / "present.bin"
    present.write_bytes(b"\x00")
    e_present = ReferenceEntry("p", tmp_path / "p.json", present, "f", "fp8000", 0, [], "")
    e_missing = ReferenceEntry("m", tmp_path / "m.json", tmp_path / "missing.bin",
                               "f", "fp8000", 0, [], "")
    avail, missing = partition_available([e_present, e_missing])
    assert [e.id for e in avail] == ["p"]
    assert [e.id for e in missing] == ["m"]
