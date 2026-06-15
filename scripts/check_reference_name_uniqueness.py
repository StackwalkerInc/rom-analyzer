#!/usr/bin/env python3
"""Pre-commit hook: validate name uniqueness within reference JSON files.

Checks that every name in `symbols` and every name in `functions` is unique
within the same file.  Cross-section duplicates (a symbol and a function
sharing a name) are also flagged.
"""

import json
import sys
from collections import Counter
from pathlib import Path


def check_file(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return [f"{path}: invalid JSON — {exc}"]

    symbols = data.get("symbols", [])
    functions = data.get("functions", [])

    if not isinstance(symbols, list) or not isinstance(functions, list):
        return [f"{path}: 'symbols' and 'functions' must be JSON arrays"]

    sym_names = [e.get("name", "") for e in symbols if isinstance(e, dict)]
    fn_names = [e.get("name", "") for e in functions if isinstance(e, dict)]

    for section, names in (("symbols", sym_names), ("functions", fn_names)):
        dupes = [name for name, count in Counter(names).items() if count > 1 and name]
        for name in sorted(dupes):
            errors.append(f"{path}: duplicate {section} name '{name}'")

    cross = set(sym_names) & set(fn_names) - {""}
    for name in sorted(cross):
        errors.append(f"{path}: name '{name}' appears in both symbols and functions")

    return errors


def main(argv: list[str]) -> int:
    if not argv:
        print("No files to check.", file=sys.stderr)
        return 0

    all_errors: list[str] = []
    for arg in argv:
        all_errors.extend(check_file(Path(arg)))

    if all_errors:
        for err in all_errors:
            print(err, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
