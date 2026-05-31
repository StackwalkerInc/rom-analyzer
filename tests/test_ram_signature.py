import pytest

from rom_analyzer.data_refs import DataRef, DataRefType
from rom_analyzer.ram_signature import build_ram_signatures, match_by_ram_signature
from rom_analyzer.types import MatchedFunction, ReferenceSymbol


def _ref(offset: int, addr: int) -> DataRef:
    return DataRef(instruction_offset=offset, referenced_address=addr,
                   ref_type=DataRefType.READ)


def _match(ref_addr: int, new_addr: int, sim: float = 0.97) -> MatchedFunction:
    return MatchedFunction("f", ref_addr, new_addr, sim, "vt_diff")


def _sym(name: str, addr: int) -> ReferenceSymbol:
    return ReferenceSymbol(name, addr, "ram_global")


# --- build_ram_signatures ---

def test_build_signatures_basic():
    refs = {
        0x1000: [_ref(0, 0x804010), _ref(4, 0x804020), _ref(8, 0x804030)],
        0x2000: [_ref(0, 0x804040), _ref(4, 0x804050)],
    }
    label_map = {
        0x804010: "rpm", 0x804020: "load", 0x804030: "tps",
        0x804040: "iat", 0x804050: "ect",
    }
    result = build_ram_signatures(refs, label_map)
    assert result[0x1000] == frozenset({"rpm", "load", "tps"})
    assert result[0x2000] == frozenset({"iat", "ect"})


def test_build_signatures_unlabeled_excluded():
    refs = {0x1000: [_ref(0, 0x804010), _ref(4, 0x804099)]}
    label_map = {0x804010: "rpm"}  # 0x804099 absent
    result = build_ram_signatures(refs, label_map)
    assert result[0x1000] == frozenset({"rpm"})


def test_build_signatures_empty_no_entry():
    refs = {0x1000: [_ref(0, 0x804099)]}
    label_map = {}  # nothing resolvable
    result = build_ram_signatures(refs, label_map)
    assert 0x1000 not in result
