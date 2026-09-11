from datetime import datetime, timedelta, timezone

import pytest

from network_dork.state import LeaseLostError, SQLiteState

def test_active_lease_excludes_second_worker_and_expired_lease_recovers(tmp_path):
    state = SQLiteState(tmp_path / "state.sqlite3")
    now = datetime(2025, 1, 1, tzinfo=timezone.utc)
    assert state.claim("source", "id", "first", now, 10)
    assert not state.claim("source", "id", "second", now, 10)
    assert state.claim(
        "source", "id", "second", now + timedelta(seconds=11), 10
    )
    row = state.inspect("source", "id")
    assert row["attempts"] == 2
    assert row["owner"] == "second"

def test_expired_worker_cannot_finish_or_renew(tmp_path):
    state = SQLiteState(tmp_path / "state.sqlite3")
    now = datetime(2025, 1, 1, tzinfo=timezone.utc)
    assert state.claim("source", "id", "first", now, 10)
    later = now + timedelta(seconds=11)
    assert not state.renew("source", "id", "first", later, 10)
    with pytest.raises(LeaseLostError):
        state.finish("source", "id", "first", "succeeded", later)

def test_terminal_state_is_restart_safe(tmp_path):
    path = tmp_path / "state.sqlite3"
    now = datetime(2025, 1, 1, tzinfo=timezone.utc)
    first = SQLiteState(path)
    assert first.claim("source", "id", "worker", now, 10)
    first.finish("source", "id", "worker", "succeeded", now)
    second = SQLiteState(path)
    assert not second.claim(
        "source", "id", "another-worker",
        now + timedelta(days=1), 10
    )
    assert second.inspect("source", "id")["status"] == "succeeded"

def test_naive_state_timestamp_is_rejected(tmp_path):
    state = SQLiteState(tmp_path / "state.sqlite3")
    with pytest.raises(ValueError, match="timezone-aware"):
        state.claim("source", "id", "worker", datetime(2025, 1, 1), 10)
