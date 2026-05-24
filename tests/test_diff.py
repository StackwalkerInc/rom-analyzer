"""Unit tests for diff._matches_from_vtsession and diff._func_name_at.

All tests use pure-Python mocks — no Ghidra JVM required.
"""

from rom_analyzer.diff import _func_name_at, _matches_from_vtsession
from rom_analyzer.types import MatchedFunction


# ---------------------------------------------------------------------------
# Pure-Python mock objects duck-typing the Ghidra VT API
# ---------------------------------------------------------------------------

class _MockAddr:
    def __init__(self, offset: int):
        self._offset = offset

    def getOffset(self) -> int:
        return self._offset


class _MockAssoc:
    def __init__(self, src: int, dst: int):
        self._src = _MockAddr(src)
        self._dst = _MockAddr(dst)

    def getSourceAddress(self):
        return self._src

    def getDestinationAddress(self):
        return self._dst


class _MockScore:
    def __init__(self, score: float):
        self._score = score

    def getScore(self) -> float:
        return self._score


class _MockMatch:
    def __init__(self, src: int, dst: int, score: float):
        self._assoc = _MockAssoc(src, dst)
        self._score = _MockScore(score)

    def getAssociation(self):
        return self._assoc

    def getSimilarityScore(self):
        return self._score


class _MockMatchSet:
    def __init__(self, matches: list):
        self._matches = matches

    def getMatches(self):
        return self._matches


class _MockFunc:
    def __init__(self, name: str):
        self._name = name

    def getName(self) -> str:
        return self._name


class _MockFuncMgr:
    def __init__(self, by_offset: dict):
        self._by_offset = by_offset

    def getFunctionAt(self, addr):
        return self._by_offset.get(addr.getOffset())


class _MockProgram:
    def __init__(self, by_offset: dict | None = None):
        self._fm = _MockFuncMgr(by_offset or {})

    def getFunctionManager(self):
        return self._fm


class _MockSession:
    def __init__(self, match_sets: list, src_program=None):
        self._match_sets = match_sets
        self._src = src_program or _MockProgram()

    def getMatchSets(self):
        return self._match_sets

    def getSourceProgram(self):
        return self._src


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_empty_session_returns_empty_list():
    session = _MockSession([])
    result = _matches_from_vtsession(session)
    assert result == []


def test_source_tag_is_vt_diff():
    session = _MockSession([
        _MockMatchSet([_MockMatch(0x1000, 0x2000, 1.0)])
    ])
    result = _matches_from_vtsession(session)
    assert len(result) == 1
    assert result[0].source == "vt_diff"


def test_deduplication_keeps_higher_similarity():
    # Two correlator match-sets both match ref=0x1000 → new=0x2000,
    # but with scores 0.8 and 1.0. Result must have score=1.0.
    session = _MockSession([
        _MockMatchSet([_MockMatch(0x1000, 0x2000, 0.8)]),
        _MockMatchSet([_MockMatch(0x1000, 0x2000, 1.0)]),
    ])
    result = _matches_from_vtsession(session)
    assert len(result) == 1
    assert result[0].ref_address == 0x1000
    assert result[0].new_address == 0x2000
    assert result[0].similarity == 1.0


def test_func_name_populated_when_function_exists():
    prog = _MockProgram({0x1000: _MockFunc("adc_run")})
    session = _MockSession(
        [_MockMatchSet([_MockMatch(0x1000, 0x2000, 1.0)])],
        src_program=prog,
    )
    result = _matches_from_vtsession(session)
    assert result[0].ref_name == "adc_run"


def test_func_name_empty_when_no_function_at_address():
    prog = _MockProgram({})  # no functions registered
    session = _MockSession(
        [_MockMatchSet([_MockMatch(0x1000, 0x2000, 1.0)])],
        src_program=prog,
    )
    result = _matches_from_vtsession(session)
    assert result[0].ref_name == ""


def test_func_name_at_returns_name():
    prog = _MockProgram({0xabcd: _MockFunc("rom_crc_check_step")})
    addr = _MockAddr(0xabcd)
    assert _func_name_at(prog, addr) == "rom_crc_check_step"


def test_func_name_at_returns_empty_when_missing():
    prog = _MockProgram({})
    addr = _MockAddr(0x1234)
    assert _func_name_at(prog, addr) == ""
