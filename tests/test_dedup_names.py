"""Tests for global symbol-name de-duplication."""

from rom_analyzer.annotations_io import (
    AnnotationFunction, AnnotationStore, AnnotationSymbol,
)
from rom_analyzer.scripts.build_reference_from_txt import dedup_symbol_names


def _store(functions=(), symbols=()):
    return AnnotationStore(schema_version=1, rom_id="t", rom_sha256="",
                           symbols=list(symbols), functions=list(functions))


def test_lowest_address_keeps_canonical_name():
    st = _store(functions=[
        AnnotationFunction(name="can0_slot11_rx_update", entry_point=0x49ef0),
        AnnotationFunction(name="can0_slot11_rx_update", entry_point=0x48ef0),
    ])
    n = dedup_symbol_names(st)
    by_addr = {f.entry_point: f.name for f in st.functions}
    assert by_addr[0x48ef0] == "can0_slot11_rx_update"      # lowest keeps it
    assert by_addr[0x49ef0] == "can0_slot11_rx_update_49ef0"  # suffixed
    assert n == 1


def test_dedup_across_functions_and_data():
    st = _store(
        functions=[AnnotationFunction(name="foo", entry_point=0x2000)],
        symbols=[AnnotationSymbol(name="foo", address=0x1000, category="data")],
    )
    dedup_symbol_names(st)
    # data at 0x1000 is lower -> keeps "foo"; function at 0x2000 suffixed
    assert st.symbols[0].name == "foo"
    assert st.functions[0].name == "foo_2000"


def test_all_names_unique_after_dedup():
    st = _store(
        functions=[
            AnnotationFunction(name="x", entry_point=0x10),
            AnnotationFunction(name="x", entry_point=0x20),
            AnnotationFunction(name="x", entry_point=0x30),
        ],
        symbols=[AnnotationSymbol(name="y", address=0x40, category="ram_global")],
    )
    dedup_symbol_names(st)
    names = [f.name for f in st.functions] + [s.name for s in st.symbols]
    assert len(names) == len(set(names))


def test_no_change_when_already_unique():
    st = _store(functions=[
        AnnotationFunction(name="a", entry_point=0x10),
        AnnotationFunction(name="b", entry_point=0x20),
    ])
    assert dedup_symbol_names(st) == 0


def test_drop_imprecise_s_duplicates_removes_rounded_artifact():
    from rom_analyzer.scripts.build_reference_from_txt import drop_imprecise_s_duplicates
    st = _store(symbols=[
        AnnotationSymbol(name="flash_x", address=0x2d72, category="data", source="colt_flash"),
        AnnotationSymbol(name="flash_x", address=0x2d74, category="data", source="z27ag_s"),
    ])
    n = drop_imprecise_s_duplicates(st)
    assert n == 1
    assert [(s.name, s.address, s.source) for s in st.symbols] == [("flash_x", 0x2d72, "colt_flash")]


def test_drop_keeps_far_apart_same_name():
    from rom_analyzer.scripts.build_reference_from_txt import drop_imprecise_s_duplicates
    st = _store(functions=[
        AnnotationFunction(name="h", entry_point=0x48ef0, source="z27ag_s"),
        AnnotationFunction(name="h", entry_point=0x49ef0, source="colt_flash"),  # 0x1000 apart
    ])
    assert drop_imprecise_s_duplicates(st) == 0  # genuine, not an artifact
