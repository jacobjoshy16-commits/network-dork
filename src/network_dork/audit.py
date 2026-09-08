"""Synchronous JSONL audit writer.

O_APPEND prevents seek-based overwrites by this writer. Cross-process
locking prevents cooperating writers from interleaving records.

This is NOT by itself an OS-enforced append-only security boundary.
Deployment must enforce the boundary separately; a writable ordinary
directory is not tamper-proof.
"""

from __future__ import annotations

import getpass
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

    def record(self, event: AuditEvent) -> None:
        if event.identity is None:
            event = event.model_copy(update={"identity": self.identity})
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
