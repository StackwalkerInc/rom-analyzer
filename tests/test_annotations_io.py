import json
from pathlib import Path

import pytest

from rom_analyzer.annotations_io import (
    AnnotationComment,
    AnnotationFunction,
    AnnotationParam,
    AnnotationStore,
    AnnotationSymbol,
    load_annotations,
    save_annotations,
)


def test_load_symbols(fixtures_dir):
    store = load_annotations(fixtures_dir / "tiny_annotations.json")
    by_name = {s.name: s for s in store.symbols}
    assert by_name["flash_fuel_map_rpm_axis"].address == 0xB2FA
    assert by_name["flash_fuel_map_rpm_axis"].category == "data"
    assert by_name["flash_fuel_map_rpm_axis"].confidence == "high"
    assert by_name["engine_rpm"].address == 0x804E5C
    assert by_name["engine_rpm"].category == "ram_global"
    assert by_name["engine_rpm"].confidence == "verified"
    assert by_name["engine_rpm"].verified_by == "amarkelov"


def test_load_functions(fixtures_dir):
    store = load_annotations(fixtures_dir / "tiny_annotations.json")
    by_name = {f.name: f for f in store.functions}
    assert by_name["adc_run"].entry_point == 0x1533C
    assert by_name["adc_run"].return_type == "void"
    assert len(by_name["adc_run"].params) == 1
    assert by_name["adc_run"].params[0].name == "ch"
    assert by_name["adc_run"].params[0].storage == "R0"
    assert by_name["adc_run"].params[0].type == "int"


def test_load_function_defaults(tmp_path):
    data = {
        "schema_version": 1, "rom_id": "x", "rom_sha256": "",
        "symbols": [], "struct_definitions": [], "comments": [],
        "functions": [{"name": "f", "entry_point": "0x100"}],
    }
    p = tmp_path / "a.json"
    p.write_text(json.dumps(data))
    store = load_annotations(p)
    assert store.functions[0].return_type is None
    assert store.functions[0].params == []


def test_load_comments(fixtures_dir):
    store = load_annotations(fixtures_dir / "tiny_annotations.json")
    assert len(store.comments) == 1
    assert store.comments[0].address == 0x804EF4
    assert store.comments[0].type == "end-of-line"
    assert store.comments[0].text == "2kph per discrete"


def test_save_round_trips(tmp_path):
    store = AnnotationStore(
        schema_version=1, rom_id="test", rom_sha256="",
        symbols=[AnnotationSymbol("foo", 0x100, "data", confidence="high", source="xml")],
        functions=[AnnotationFunction("bar", 0x200, return_type="void")],
    )
    p = tmp_path / "out.json"
    save_annotations(p, store)
    loaded = load_annotations(p)
    assert loaded.symbols[0].name == "foo"
    assert loaded.symbols[0].address == 0x100
    assert loaded.functions[0].name == "bar"
    assert loaded.functions[0].entry_point == 0x200
    assert loaded.functions[0].return_type == "void"


def test_save_sorts_by_address(tmp_path):
    store = AnnotationStore(
        schema_version=1, rom_id="test", rom_sha256="",
        symbols=[
            AnnotationSymbol("z", 0x300, "data"),
            AnnotationSymbol("a", 0x100, "data"),
        ],
    )
    p = tmp_path / "out.json"
    save_annotations(p, store)
    data = json.loads(p.read_text())
    addrs = [int(s["address"], 16) for s in data["symbols"]]
    assert addrs == sorted(addrs)


def test_save_address_as_hex(tmp_path):
    store = AnnotationStore(
        schema_version=1, rom_id="test", rom_sha256="",
        symbols=[AnnotationSymbol("foo", 0xB2FA, "data")],
    )
    p = tmp_path / "out.json"
    save_annotations(p, store)
    data = json.loads(p.read_text())
    assert data["symbols"][0]["address"] == "0xb2fa"


def test_save_omits_none_data_type(tmp_path):
    store = AnnotationStore(
        schema_version=1, rom_id="test", rom_sha256="",
        symbols=[AnnotationSymbol("foo", 0x100, "data", data_type=None)],
    )
    p = tmp_path / "out.json"
    save_annotations(p, store)
    data = json.loads(p.read_text())
    assert "data_type" not in data["symbols"][0]


def test_save_omits_empty_params(tmp_path):
    store = AnnotationStore(
        schema_version=1, rom_id="test", rom_sha256="",
        functions=[AnnotationFunction("f", 0x100)],
    )
    p = tmp_path / "out.json"
    save_annotations(p, store)
    data = json.loads(p.read_text())
    assert "params" not in data["functions"][0]


def test_save_omits_none_verified_by(tmp_path):
    store = AnnotationStore(
        schema_version=1, rom_id="test", rom_sha256="",
        symbols=[AnnotationSymbol("foo", 0x100, "data", verified_by=None)],
    )
    p = tmp_path / "out.json"
    save_annotations(p, store)
    data = json.loads(p.read_text())
    assert "verified_by" not in data["symbols"][0]


def test_save_writes_atomically(tmp_path):
    store = AnnotationStore(schema_version=1, rom_id="x", rom_sha256="")
    p = tmp_path / "out.json"
    save_annotations(p, store)
    assert p.exists()
    assert not (tmp_path / "out.json.tmp").exists()
