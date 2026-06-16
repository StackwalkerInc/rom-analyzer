"""rom_analyzer.ghidra — backward-compat re-exports.

All symbols importable from rom_analyzer.ghidra before the package split
remain importable from here.
"""

from rom_analyzer.ghidra.session import (  # noqa: F401
    GhidraSession,
    HeadlessRun,
    apply_data_types,
    apply_labels,
    apply_mut_table_in_ghidra,
    decompile_function,
    ghidriff_program_name,
    import_and_dump,
    setup_environment,
)
from rom_analyzer.ghidra.fetch import (  # noqa: F401
    fetch_callees_of,
    fetch_callers_of,
    fetch_data_read_sites,
    fetch_function_entry,
    fetch_function_name,
    fetch_instructions_at,
    fetch_r0_imm_before,
)
from rom_analyzer.ghidra.domain import (  # noqa: F401
    fetch_dtc_call_sites,
    fetch_dtc_helpers_structural,
    fetch_pid_dispatch_entries,
)
