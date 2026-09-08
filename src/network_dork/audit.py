"""Hash-chained JSONL audit writer.

O_APPEND prevents seek-based overwrites by this writer. Cross-process
locking prevents cooperating writers from interleaving records.

Each record additionally carries its position in a hash chain: the digest of
the record before it, and its own digest computed over that link plus its own
content. Editing or deleting any record breaks every link after it, so
tampering becomes detectable rather than invisible. ``verify_chain`` checks a
whole file and names the first record that does not agree.

This is tamper *evidence*, not tamper *prevention*. Someone with write access
can still rewrite the file from a chosen point and recompute every subsequent
digest. Detecting that needs an anchor outside the file: ship digests to a
remote log service, or periodically record the chain head somewhere the
application cannot reach. Deployment must still place this file behind
append-only controls; a writable ordinary directory is not tamper-proof.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
from pathlib import Path
import socket
import threading
from uuid import uuid4

from network_dork.models import AuditEvent, RuntimeIdentity

try:
    import fcntl
except ImportError:
    fcntl = None

# The digest a first record links to, standing in for "nothing before this".
GENESIS = "0" * 64


def current_identity(run_id: str | None = None) -> RuntimeIdentity:
    """Describe the process producing audit records.

    Resolution never fails the run: a container without a passwd entry or a
    resolvable hostname still produces a record, marked "unknown".
    """
    try:
        user = getpass.getuser()
    except Exception:
        user = f"uid-{os.getuid()}" if hasattr(os, "getuid") else "unknown"
    try:
        host = socket.gethostname()
    except Exception:
        host = "unknown"
    return RuntimeIdentity(
        run_id=run_id or str(uuid4()),
        user=user or "unknown",
        host=host or "unknown",
        pid=os.getpid(),
    )


def link_digest(sequence: int, previous: str, body: dict) -> str:
    """Digest one record's link, over its position, predecessor, and content.

    Sorted, separator-fixed JSON so the same record always hashes the same
    way regardless of key order or the writer's formatting.
    """
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
    material = f"{sequence}\n{previous}\n{payload}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _read_last_line(handle) -> bytes:
    """Return the final non-empty line without reading the whole file.

    Audit files grow without bound, so recovering the chain head must not
    cost a full read on every single write.
    """
    handle.seek(0, os.SEEK_END)
    size = handle.tell()
    if size == 0:
        return b""
    block = 4096
    offset = size
    buffer = b""
    while offset > 0:
        step = min(block, offset)
        offset -= step
        handle.seek(offset)
        buffer = handle.read(step) + buffer
        lines = [line for line in buffer.split(b"\n") if line.strip()]
        if lines and (offset == 0 or len(lines) > 1):
            return lines[-1]
    return b""


class AuditChainError(RuntimeError):
    """The audit file does not agree with its own hash chain."""


class JsonlAuditLog:
    def __init__(
        self,
        path: str | Path,
        identity: RuntimeIdentity | None = None,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.identity = identity or current_identity()
        self._lock = threading.Lock()

    def _chain_head(self, fd: int) -> tuple[int, str]:
        """Read the current tail under the lock we already hold.

        Re-read per write rather than cached: another process may have
        appended since, and a stale head would fork the chain.
        """
        with os.fdopen(os.dup(fd), "rb") as handle:
            line = _read_last_line(handle)
        if not line:
            return 0, GENESIS
        try:
            previous = json.loads(line)
            return int(previous["sequence"]), str(previous["record_sha256"])
        except (ValueError, KeyError, TypeError) as exc:
            raise AuditChainError(
                f"{self.path}: the last audit record is unreadable, so a new "
                "record cannot be linked to it"
            ) from exc

    def record(self, event: AuditEvent) -> None:
        if event.identity is None:
            event = event.model_copy(update={"identity": self.identity})
        body = event.model_dump(mode="json")

        flags = os.O_RDWR | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        with self._lock:
            fd = os.open(self.path, flags, 0o600)
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                sequence, previous = self._chain_head(fd)
                sequence += 1
                record = {
                    **body,
                    "sequence": sequence,
                    "previous_sha256": previous,
                }
                record["record_sha256"] = link_digest(
                    sequence, previous, body
                )
                payload = (
                    json.dumps(record, sort_keys=True) + "\n"
                ).encode("utf-8")

                os.lseek(fd, 0, os.SEEK_END)
                view = memoryview(payload)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("Audit write made no progress")
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)


def verify_chain(path: str | Path) -> tuple[int, str]:
    """Check every link. Returns (records, chain head digest).

    Raises AuditChainError naming the first record that does not agree, which
    is where tampering or truncation begins.
    """
    path = Path(path)
    if not path.exists():
        raise AuditChainError(f"{path}: no audit file")

    expected_sequence = 0
    previous = GENESIS
    count = 0

    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError as exc:
                raise AuditChainError(
                    f"{path}:{line_number}: record is not valid JSON"
                ) from exc

            body = {
                key: value
                for key, value in record.items()
                if key not in {"sequence", "previous_sha256", "record_sha256"}
            }
            expected_sequence += 1
            if record.get("sequence") != expected_sequence:
                raise AuditChainError(
                    f"{path}:{line_number}: expected sequence "
                    f"{expected_sequence}, found {record.get('sequence')!r}. "
                    "Records were removed, reordered, or inserted."
                )
            if record.get("previous_sha256") != previous:
                raise AuditChainError(
                    f"{path}:{line_number}: record does not link to its "
                    "predecessor. The chain was broken at or before here."
                )
            digest = link_digest(expected_sequence, previous, body)
            if record.get("record_sha256") != digest:
                raise AuditChainError(
                    f"{path}:{line_number}: record content does not match "
                    "its digest. This record was modified after it was "
                    "written."
                )
            previous = digest
            count += 1

    return count, previous
