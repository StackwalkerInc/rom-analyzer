"""Shared dataclasses for cross-module data flow."""

from dataclasses import dataclass
from typing import Literal

SymbolCategory = Literal["function", "data", "ram_global"]
ConfidenceTier = Literal["high", "medium", "low"]
CrcBand = Literal["partial_crc", "full_crc_only", "unprotected"]


@dataclass(frozen=True)
class ReferenceSymbol:
    name: str
    address: int
    category: SymbolCategory


@dataclass(frozen=True)
class MatchedFunction:
    ref_name: str
    ref_address: int
    new_address: int
    similarity: float
    source: str = "ghidriff"


@dataclass(frozen=True)
class PropagatedSymbol:
    name: str
    ref_address: int
    new_address: int
    category: SymbolCategory
    confidence: ConfidenceTier


@dataclass(frozen=True)
class CrcRegion:
    full_start: int
    full_end: int
    partial_start: int
    partial_end: int


@dataclass(frozen=True)
class FlashFreeBlock:
    band: CrcBand
    start: int
    end: int
    length: int


@dataclass(frozen=True)
class RamFreeBlock:
    start: int
    end: int
    length: int
    note: str
