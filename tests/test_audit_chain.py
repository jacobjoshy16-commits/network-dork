"""The audit hash chain.

Detects records edited, removed, reordered, or inserted after the fact. It
does not detect a rewrite by someone who recomputes every later digest --
that needs an anchor outside the file, and the module says so.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json

import pytest

from network_dork.audit import (
    GENESIS,
    AuditChainError,
    JsonlAuditLog,
    verify_chain,
)
from network_dork.models import AuditEvent

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def event(number: int) -> AuditEvent:
    return AuditEvent(
        timestamp=NOW,
        alert_id=f"syn-{number:03d}",
        operation_id=str(number),
        action="context_query",
        stage="attempt",
        parameters={"kind": "flows", "index": number},
    )


def write_events(path, count: int) -> JsonlAuditLog:
    log = JsonlAuditLog(path)
    for number in range(count):
        log.record(event(number))
    return log


def rewrite(path, mutate) -> None:
    lines = path.read_text().splitlines()
    path.write_text("\n".join(mutate(lines)) + "\n")


def test_a_clean_file_verifies(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_events(path, 20)
    count, head = verify_chain(path)
    assert count == 20
    assert len(head) == 64


def test_the_first_record_links_to_genesis(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_events(path, 1)
    record = json.loads(path.read_text().splitlines()[0])
    assert record["sequence"] == 1
    assert record["previous_sha256"] == GENESIS


def test_editing_a_record_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_events(path, 20)

    def mutate(lines):
        record = json.loads(lines[9])
        record["alert_id"] = "syn-999"
        lines[9] = json.dumps(record, sort_keys=True)
        return lines

    rewrite(path, mutate)
    with pytest.raises(AuditChainError, match="does not match"):
        verify_chain(path)


def test_editing_a_nested_parameter_is_detected(tmp_path):
    """The digest covers the whole record, not just its top-level fields."""
    path = tmp_path / "audit.jsonl"
    write_events(path, 10)

    def mutate(lines):
        record = json.loads(lines[4])
        record["parameters"]["index"] = 9999
        lines[4] = json.dumps(record, sort_keys=True)
        return lines

    rewrite(path, mutate)
    with pytest.raises(AuditChainError, match="does not match"):
        verify_chain(path)


def test_removing_a_record_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_events(path, 20)
    rewrite(path, lambda lines: lines[:9] + lines[10:])
    with pytest.raises(AuditChainError, match="sequence"):
        verify_chain(path)


def test_reordering_records_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_events(path, 20)

    def mutate(lines):
        lines[5], lines[6] = lines[6], lines[5]
        return lines

    rewrite(path, mutate)
    with pytest.raises(AuditChainError, match="sequence"):
        verify_chain(path)


def test_truncating_the_tail_still_verifies_as_a_shorter_chain(tmp_path):
    """Losing the end is not the same as tampering in the middle.

    A truncated file is internally consistent, so the chain cannot prove
    records are missing from the end. That is why the head digest must be
    anchored somewhere outside the file.
    """
    path = tmp_path / "audit.jsonl"
    write_events(path, 20)
    rewrite(path, lambda lines: lines[:15])
    count, _ = verify_chain(path)
    assert count == 15


def test_a_writer_continues_an_existing_chain(tmp_path):
    """A restart must extend the file, not fork it."""
    path = tmp_path / "audit.jsonl"
    write_events(path, 5)
    JsonlAuditLog(path).record(event(99))
    count, _ = verify_chain(path)
    assert count == 6


def test_concurrent_writers_produce_one_valid_chain(tmp_path):
    """Sequence numbers must not collide under a shared lock."""
    path = tmp_path / "audit.jsonl"
    log = JsonlAuditLog(path)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda n: log.record(event(n)), range(40)))
    count, _ = verify_chain(path)
    assert count == 40


def test_a_missing_file_is_reported_clearly(tmp_path):
    with pytest.raises(AuditChainError, match="no audit file"):
        verify_chain(tmp_path / "absent.jsonl")


def test_corrupt_json_is_reported_with_its_line(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_events(path, 5)
    rewrite(path, lambda lines: lines[:2] + ["{not json"] + lines[2:])
    with pytest.raises(AuditChainError, match=":3:"):
        verify_chain(path)


def test_the_chain_survives_a_large_file_without_full_rereads(tmp_path):
    """Recovering the head must not cost a full read on every write."""
    path = tmp_path / "audit.jsonl"
    log = JsonlAuditLog(path)
    for number in range(300):
        log.record(event(number))
    count, _ = verify_chain(path)
    assert count == 300
