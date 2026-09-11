"""Read normalized existing alerts from JSON Lines.

Source polling intentionally does not track offsets: restart-safe
deduplication belongs to the processed-alert store.
"""

from collections.abc import Iterable
from pathlib import Path

from pydantic import ValidationError

from network_dork.models import Alert

class FileAlertSource:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def poll(self) -> Iterable[Alert]:
        with self.path.open("r", encoding="utf-8") as stream:
            for number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    yield Alert.model_validate_json(line)
                except ValidationError as exc:
                    raise ValueError(
                        f"{self.path}:{number}: invalid normalized alert"
                    ) from exc
