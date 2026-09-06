"""Synchronous JSONL audit writer.

O_APPEND prevents seek-based overwrites by this writer. Cross-process
locking prevents cooperating writers from interleaving records.

This is NOT by itself an OS-enforced append-only security boundary.
Deployment must enforce the boundary separately; a writable ordinary
directory is not tamper-proof.
"""

from __future__ import annotations

import os
from pathlib import Path
import threading

from network_dork.models import AuditEvent

try:
    import fcntl
except ImportError:
    fcntl = None

class JsonlAuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record(self, event: AuditEvent) -> None:
        payload = (event.model_dump_json() + "\n").encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        with self._lock:
            fd = os.open(self.path, flags, 0o600)
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                view = memoryview(payload)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("Audit write made no progress")
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
