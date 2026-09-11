"""Normalization of native event identifiers into safe alert identifiers.

Native identifiers from sensors and SIEMs are untrusted strings. They reach
storage keys and REST paths, so they are normalized into the restricted
``AlertId`` shape before an Alert is constructed.

Normalization never drops an alert. An identifier that cannot be represented
verbatim is rewritten and given a digest suffix, so distinct native values stay
distinct. The unmodified native value remains available in ``Alert.original``.
"""

from __future__ import annotations

import hashlib
import re

# Mirrors the AlertId / SourceName patterns in network_dork.models.
_ALERT_ID_ALLOWED = re.compile(r"[^A-Za-z0-9._:@+-]")
_SOURCE_ALLOWED = re.compile(r"[^A-Za-z0-9._-]")
_MAX_ALERT_ID = 512
_DIGEST_LENGTH = 12


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:_DIGEST_LENGTH]


def normalize_source_name(value: str) -> str:
    """Return a source name matching the SourceName constraint."""
    cleaned = _SOURCE_ALLOWED.sub("-", value.strip())
    cleaned = cleaned.lstrip("._-")
    return cleaned or "source"


def normalize_alert_id(source_name: str, native_id: object) -> str:
    """Return ``<source>:<native>`` reduced to the AlertId character set.

    A digest suffix is appended whenever the native identifier is altered, so
    two different native identifiers cannot collapse onto one alert id.
    """
    source = normalize_source_name(source_name)
    native = "" if native_id is None else str(native_id).strip()
    if not native:
        native = "no-id"

    cleaned = _ALERT_ID_ALLOWED.sub("-", native)
    # A leading character outside [A-Za-z0-9] would break the pattern anchor.
    trimmed = cleaned.lstrip("._:@+-")
    altered = trimmed != native

    plain_budget = _MAX_ALERT_ID - len(source) - 1
    suffixed_budget = plain_budget - _DIGEST_LENGTH - 1
    if suffixed_budget < 1:
        raise ValueError("Source name leaves no room for an alert identifier")

    if not altered and len(trimmed) <= plain_budget:
        return f"{source}:{trimmed}"

    trimmed = trimmed[:suffixed_budget] or "id"
    return f"{source}:{trimmed}.{_digest(native)}"
