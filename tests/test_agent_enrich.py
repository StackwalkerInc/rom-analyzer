# tests/test_agent_enrich.py
import json
import pytest
from pathlib import Path
from rom_analyzer.agent_enrich import (
    QueueEntry, load_queue, save_queue,
    load_yield_history, append_yield,
    pop_batch, rescore_neighbors, check_stop_condition, is_done, write_done,
    load_var_queue, save_var_queue,
    rescore_var_neighbors,
    load_var_yield_history, append_var_yield, check_var_stop_condition,
    is_var_done, write_var_done,
)


@pytest.fixture
def state_dir(tmp_path):
    return tmp_path


def make_entry(address, priority, neighbors=None):
    return QueueEntry(
        rom="33520003",
        address=address,
        current_name=f"FUN_{address[2:].upper().zfill(8)}",
        prog_name="test.bin",
        named_neighbor_count=priority,
        priority=priority,
        neighbor_addresses=neighbors or [],
    )


def test_save_load_queue_roundtrip(state_dir):
    q = [make_entry("0x1a3f0", 8), make_entry("0x2b800", 3)]
    save_queue(state_dir, q)
    loaded = load_queue(state_dir)
    assert len(loaded) == 2
    assert loaded[0].address == "0x1a3f0"
    assert loaded[0].priority == 8
    assert loaded[1].address == "0x2b800"


def test_load_queue_sorted_descending(state_dir):
    q = [make_entry("0x100", 2), make_entry("0x200", 9), make_entry("0x300", 5)]
    save_queue(state_dir, q)
    loaded = load_queue(state_dir)
    priorities = [e.priority for e in loaded]
    assert priorities == sorted(priorities, reverse=True)


def test_load_queue_empty(state_dir):
    assert load_queue(state_dir) == []


def test_append_yield(state_dir):
    append_yield(state_dir, 1, applied=14, review=6)
    append_yield(state_dir, 2, applied=9, review=4)
    history = load_yield_history(state_dir)
    assert len(history) == 2
    assert history[0] == {"round": 1, "applied": 14, "review": 6}
    assert history[1] == {"round": 2, "applied": 9, "review": 4}


def test_pop_batch_full():
    q = [make_entry(f"0x{i:x}", i) for i in range(30, 0, -1)]
    batch, remaining = pop_batch(q, k=20)
    assert len(batch) == 20
    assert len(remaining) == 10
    assert batch[0].priority == 30


def test_pop_batch_smaller_than_k():
    q = [make_entry("0x100", 5), make_entry("0x200", 3)]
    batch, remaining = pop_batch(q, k=20)
    assert len(batch) == 2
    assert len(remaining) == 0


def test_rescore_neighbors_increments_affected(state_dir):
    q = [
        make_entry("0x100", 2, neighbors=["0x999", "0xabc"]),
        make_entry("0x200", 3, neighbors=["0x111", "0x222"]),
        make_entry("0x300", 1, neighbors=["0xabc", "0xdef"]),
    ]
    updated = rescore_neighbors(q, newly_named={"0xabc"})
    by_addr = {e.address: e for e in updated}
    assert by_addr["0x100"].priority == 3   # had 0xabc → +1
    assert by_addr["0x200"].priority == 3   # no overlap → unchanged
    assert by_addr["0x300"].priority == 2   # had 0xabc → +1


def test_rescore_flips_sort_order(state_dir):
    # 0x100 has priority 1, 0x200 has priority 0 with two neighbors
    q = [make_entry("0x100", 1), make_entry("0x200", 0, neighbors=["0xabc", "0xdef"])]
    updated = rescore_neighbors(q, newly_named={"0xabc", "0xdef"})
    # 0x200: 0 + 2 = 2; 0x100: 1 + 0 = 1 → 0x200 should now be first
    assert updated[0].address == "0x200"
    assert updated[0].priority == 2
    assert updated[1].address == "0x100"
    assert updated[1].priority == 1


def test_rescore_neighbors_empty_newly_named():
    q = [make_entry("0x100", 5, neighbors=["0x999"]), make_entry("0x200", 3)]
    updated = rescore_neighbors(q, newly_named=set())
    # Nothing changes
    assert updated[0].address == "0x100"
    assert updated[0].priority == 5
    assert updated[1].address == "0x200"
    assert updated[1].priority == 3


def test_check_stop_false_not_enough_history(state_dir):
    append_yield(state_dir, 1, applied=1, review=0)
    append_yield(state_dir, 2, applied=0, review=0)
    assert check_stop_condition(state_dir, window=3, threshold=2) is False


def test_check_stop_true(state_dir):
    append_yield(state_dir, 1, applied=1, review=0)
    append_yield(state_dir, 2, applied=0, review=0)
    append_yield(state_dir, 3, applied=1, review=0)
    assert check_stop_condition(state_dir, window=3, threshold=2) is True


def test_check_stop_false_recent_good_round(state_dir):
    append_yield(state_dir, 1, applied=1, review=0)
    append_yield(state_dir, 2, applied=0, review=0)
    append_yield(state_dir, 3, applied=5, review=2)
    assert check_stop_condition(state_dir, window=3, threshold=2) is False


def test_done_sentinel(state_dir):
    assert not is_done(state_dir)
    write_done(state_dir)
    assert is_done(state_dir)


def make_var_entry(address, priority, neighbors=None, siblings=None, category="ram_global"):
    return QueueEntry(
        rom="33520003",
        address=address,
        current_name=f"DAT_{address[2:].upper().zfill(8)}",
        prog_name="test.bin",
        named_neighbor_count=priority,
        priority=priority,
        neighbor_addresses=neighbors or [],
        item_type="variable",
        category=category,
        sibling_addresses=siblings or [],
    )


def test_queue_entry_default_item_type():
    """Existing callers that omit item_type/category/sibling_addresses get safe defaults."""
    e = QueueEntry(
        rom="33520003", address="0x100", current_name="FUN_00000100",
        prog_name="test.bin", named_neighbor_count=2, priority=2,
    )
    assert e.item_type == "function"
    assert e.category == ""
    assert e.sibling_addresses == []


def test_load_queue_backward_compat_missing_fields(state_dir):
    """Old queue.json entries without item_type/category/sibling_addresses load cleanly."""
    old = [{
        "rom": "33520003", "address": "0x100", "current_name": "FUN_00000100",
        "prog_name": "test.bin", "named_neighbor_count": 2, "priority": 2,
        "neighbor_addresses": [],
    }]
    (state_dir / "queue.json").write_text(json.dumps(old))
    loaded = load_queue(state_dir)
    assert loaded[0].item_type == "function"
    assert loaded[0].category == ""
    assert loaded[0].sibling_addresses == []


def test_save_load_var_queue_roundtrip(state_dir):
    q = [
        make_var_entry("0x804e5c", 3, siblings=["0x804e5e", "0x804e60"]),
        make_var_entry("0x804e5e", 1, category="ram_global"),
    ]
    save_var_queue(state_dir, q)
    loaded = load_var_queue(state_dir)
    assert len(loaded) == 2
    assert loaded[0].address == "0x804e5c"   # higher priority first
    assert loaded[0].item_type == "variable"
    assert loaded[0].category == "ram_global"
    assert loaded[0].sibling_addresses == ["0x804e5e", "0x804e60"]


def test_load_var_queue_absent(state_dir):
    assert load_var_queue(state_dir) == []


def test_rescore_var_neighbors_reader_writer_boost():
    """Entries with named-function EPs in neighbor_addresses get boosted when those fns are named."""
    q = [
        make_var_entry("0x804100", 1, neighbors=["0x1a3f0", "0x2b800"]),
        make_var_entry("0x804200", 0, neighbors=["0x99999"]),
    ]
    updated = rescore_var_neighbors(q, newly_named={"0x1a3f0"}, newly_named_vars=set())
    by_addr = {e.address: e for e in updated}
    assert by_addr["0x804100"].priority == 2   # 0x1a3f0 matched → +1
    assert by_addr["0x804200"].priority == 0   # no match


def test_rescore_var_neighbors_sibling_boost():
    """Entries with newly-named variable addresses in sibling_addresses get +1."""
    q = [
        make_var_entry("0x804100", 0, siblings=["0x804102", "0x804104"]),
        make_var_entry("0x804200", 0, siblings=["0x804202"]),
    ]
    updated = rescore_var_neighbors(q, newly_named=set(), newly_named_vars={"0x804102"})
    by_addr = {e.address: e for e in updated}
    assert by_addr["0x804100"].priority == 1   # sibling 0x804102 named → +1
    assert by_addr["0x804200"].priority == 0   # no sibling match


def test_rescore_var_neighbors_combined_boost():
    """Both reader/writer and sibling boosts accumulate."""
    q = [make_var_entry("0x804100", 0, neighbors=["0xabc"], siblings=["0x804102"])]
    updated = rescore_var_neighbors(q, newly_named={"0xabc"}, newly_named_vars={"0x804102"})
    assert updated[0].priority == 2


def test_rescore_var_neighbors_reorders():
    q = [
        make_var_entry("0x804100", 1, siblings=[]),
        make_var_entry("0x804200", 0, siblings=["0x804100"]),
    ]
    updated = rescore_var_neighbors(q, newly_named=set(), newly_named_vars={"0x804100"})
    assert [e.address for e in updated] == ["0x804200", "0x804100"]
    assert updated[0].priority == 1
    assert updated[1].priority == 1


def test_var_done_sentinel(state_dir):
    assert not is_var_done(state_dir)
    write_var_done(state_dir)
    assert is_var_done(state_dir)


def test_append_var_yield_and_load(state_dir):
    append_var_yield(state_dir, 1, vars_applied=4, vars_review=2)
    append_var_yield(state_dir, 2, vars_applied=0, vars_review=5)
    history = load_var_yield_history(state_dir)
    assert history == [
        {"round": 1, "vars_applied": 4, "vars_review": 2},
        {"round": 2, "vars_applied": 0, "vars_review": 5},
    ]


def test_check_var_stop_true(state_dir):
    for i in range(3):
        append_var_yield(state_dir, i + 1, vars_applied=0, vars_review=0)
    assert check_var_stop_condition(state_dir, window=3, threshold=2) is True


def test_check_var_stop_false_not_enough_history(state_dir):
    append_var_yield(state_dir, 1, vars_applied=0, vars_review=0)
    append_var_yield(state_dir, 2, vars_applied=0, vars_review=0)
    assert check_var_stop_condition(state_dir, window=3, threshold=2) is False


def test_check_var_stop_false_recent_good_round(state_dir):
    append_var_yield(state_dir, 1, vars_applied=0, vars_review=0)
    append_var_yield(state_dir, 2, vars_applied=0, vars_review=0)
    append_var_yield(state_dir, 3, vars_applied=5, vars_review=1)
    assert check_var_stop_condition(state_dir, window=3, threshold=2) is False
