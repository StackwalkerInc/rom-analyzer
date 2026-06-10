"""Load and save annotations.json stores."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from rom_analyzer.types import ConfidenceTier


@dataclass
class AnnotationParam:
    name: str
    storage: str   # "R0"–"R3" or "stack"
    type: str      # e.g. "uint8_t"


@dataclass
class AnnotationSymbol:
    name: str
    address: int
    category: Literal["data", "ram_global"]
    data_type: str | None = None
    confidence: ConfidenceTier = "high"
    source: str = ""
    verified_by: str | None = None
    session: str = ""
    timestamp: str = ""


@dataclass
class AnnotationFunction:
    name: str
    entry_point: int
    confidence: ConfidenceTier = "high"
    source: str = ""
    verified_by: str | None = None
    session: str = ""
    timestamp: str = ""
    return_type: str | None = None
    params: list[AnnotationParam] = field(default_factory=list)


@dataclass
class StructMember:
    name: str
    offset: int
    type: str


@dataclass
class StructDefinition:
    name: str
    size: int
    members: list[StructMember] = field(default_factory=list)


@dataclass
class AnnotationComment:
    address: int
    type: str   # "end-of-line"|"pre"|"post"|"plate"|"repeatable"
    text: str
    verified_by: str | None = None
    session: str = ""
    timestamp: str = ""


@dataclass
class AnnotationStore:
    schema_version: int
    rom_id: str
    rom_sha256: str
    symbols: list[AnnotationSymbol] = field(default_factory=list)
    functions: list[AnnotationFunction] = field(default_factory=list)
    struct_definitions: list[StructDefinition] = field(default_factory=list)
    comments: list[AnnotationComment] = field(default_factory=list)


def load_annotations(path: Path) -> AnnotationStore:
    data = json.loads(path.read_text())
    symbols = [
        AnnotationSymbol(
            name=s["name"],
            address=int(s["address"], 16),
            category=s["category"],
            data_type=s.get("data_type"),
            confidence=s.get("confidence", "high"),
            source=s.get("source", ""),
            verified_by=s.get("verified_by"),
            session=s.get("session", ""),
            timestamp=s.get("timestamp", ""),
        )
        for s in data.get("symbols", [])
    ]
    functions = [
        AnnotationFunction(
            name=f["name"],
            entry_point=int(f["entry_point"], 16),
            confidence=f.get("confidence", "high"),
            source=f.get("source", ""),
            verified_by=f.get("verified_by"),
            session=f.get("session", ""),
            timestamp=f.get("timestamp", ""),
            return_type=f.get("return_type"),
            params=[
                AnnotationParam(name=p["name"], storage=p["storage"], type=p["type"])
                for p in f.get("params", [])
            ],
        )
        for f in data.get("functions", [])
    ]
    struct_definitions = [
        StructDefinition(
            name=sd["name"],
            size=sd["size"],
            members=[
                StructMember(name=m["name"], offset=m["offset"], type=m["type"])
                for m in sd.get("members", [])
            ],
        )
        for sd in data.get("struct_definitions", [])
    ]
    comments = [
        AnnotationComment(
            address=int(c["address"], 16),
            type=c["type"],
            text=c["text"],
            verified_by=c.get("verified_by"),
            session=c.get("session", ""),
            timestamp=c.get("timestamp", ""),
        )
        for c in data.get("comments", [])
    ]
    return AnnotationStore(
        schema_version=data.get("schema_version", 1),
        rom_id=data.get("rom_id", ""),
        rom_sha256=data.get("rom_sha256", ""),
        symbols=symbols,
        functions=functions,
        struct_definitions=struct_definitions,
        comments=comments,
    )


def save_annotations(path: Path, store: AnnotationStore) -> None:
    def _sym(s: AnnotationSymbol) -> dict:
        d: dict = {
            "name": s.name,
            "address": f"0x{s.address:x}",
            "category": s.category,
        }
        if s.data_type is not None:
            d["data_type"] = s.data_type
        d.update({
            "confidence": s.confidence,
            "source": s.source,
            "verified_by": s.verified_by,
            "session": s.session,
            "timestamp": s.timestamp,
        })
        return d

    def _fn(f: AnnotationFunction) -> dict:
        d: dict = {
            "name": f.name,
            "entry_point": f"0x{f.entry_point:x}",
            "confidence": f.confidence,
            "source": f.source,
            "verified_by": f.verified_by,
            "session": f.session,
            "timestamp": f.timestamp,
        }
        if f.return_type is not None:
            d["return_type"] = f.return_type
        if f.params:
            d["params"] = [
                {"name": p.name, "storage": p.storage, "type": p.type}
                for p in f.params
            ]
        return d

    def _struct(sd: StructDefinition) -> dict:
        return {
            "name": sd.name,
            "size": sd.size,
            "members": [
                {"name": m.name, "offset": m.offset, "type": m.type}
                for m in sd.members
            ],
        }

    def _comment(c: AnnotationComment) -> dict:
        return {
            "address": f"0x{c.address:x}",
            "type": c.type,
            "text": c.text,
            "verified_by": c.verified_by,
            "session": c.session,
            "timestamp": c.timestamp,
        }

    data = {
        "schema_version": store.schema_version,
        "rom_id": store.rom_id,
        "rom_sha256": store.rom_sha256,
        "symbols": [_sym(s) for s in sorted(store.symbols, key=lambda s: s.address)],
        "functions": [_fn(f) for f in sorted(store.functions, key=lambda f: f.entry_point)],
        "struct_definitions": [_struct(sd) for sd in store.struct_definitions],
        "comments": [_comment(c) for c in sorted(store.comments, key=lambda c: c.address)],
    }
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    tmp.replace(path)
