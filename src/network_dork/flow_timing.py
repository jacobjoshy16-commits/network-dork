"""Timing statistics derived from the flows already in a context.

This is not a new evidence source. It queries nothing, needs no credential
and adds no adapter: it is arithmetic over the flow records the configured
context provider already gathered, and it exists because that arithmetic was
the missing half of the evidence.

The gap it closes, observed rather than theorised. Given the three flows
supplied for a beaconing alert --

    ts 1736941500  orig_bytes 160  resp_bytes 512  duration 0.25
    ts 1736941800  orig_bytes 160  resp_bytes 512  duration 0.25
    ts 1736942100  orig_bytes 160  resp_bytes 512  duration 0.25

-- qwen2.5:3b-instruct called the alert a known benign pattern. The signal is
right there: 300 seconds apart to the second, identical payload every time.
What a human reads instantly from those rows is inter-arrival regularity, and
nothing in the prompt asked the model to compute it. `regularity.py` measures
exactly this, but only inside the forecast enrichment path, which is off by
default -- so the discriminating feature was computed elsewhere and never
shown to the model deciding the alert.

Regularity here is deliberately *absolute*, not relative to the host's own
history: with no history there is no baseline, and inventing one from an hour
of traffic would produce anomaly scores that mean nothing. So this states a
plain observation about the supplied window and leaves the judgement to the
model. A steady host is not suspicious for being steady, and the prompt says
so; what this removes is the model's excuse for not knowing it was steady.

Both the prompt renderer and the pipeline's allow-list call `observations`
over the same context. It is a pure function of that context, so the two
agree without the pipeline having to trust what the renderer wrote.
"""

from __future__ import annotations

import statistics
from typing import Any

from network_dork.models import AlertContext, EvidenceRecord
from network_dork.regularity import MAX_REGULARITY

# Two intervals are the minimum from which variance can be computed at all,
# so a pair needs three connections before it says anything.
MIN_CONNECTIONS = 3


def _pair(record: EvidenceRecord) -> str | None:
    """Return "src->dst" for a flow record, or None if it names neither."""
    fields = record.fields
    source = fields.get("id.orig_h") or fields.get("src_ip")
    destination = fields.get("id.resp_h") or fields.get("dst_ip")
    if not isinstance(source, str) or not isinstance(destination, str):
        return None
    return f"{source}->{destination}"


def _numbers(values: list[Any]) -> list[float]:
    return [
        float(value)
        for value in values
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    ]


def observations(context: AlertContext) -> list[tuple[str, dict[str, Any]]]:
    """Return (evidence_id, fields) per source-destination pair, id-sorted.

    Empty when no pair has enough connections to have a timing pattern, which
    is the common case for a one-off alert and is not a failure.
    """
    grouped: dict[str, list[EvidenceRecord]] = {}
    for record in context.flows:
        pair = _pair(record)
        if pair is not None:
            grouped.setdefault(pair, []).append(record)

    results: list[tuple[str, dict[str, Any]]] = []
    for pair, records in sorted(grouped.items()):
        if len(records) < MIN_CONNECTIONS:
            continue
        ordered = sorted(records, key=lambda item: item.timestamp)
        intervals = [
            (later.timestamp - earlier.timestamp).total_seconds()
            for earlier, later in zip(ordered, ordered[1:])
        ]
        if not intervals:
            continue

        mean_interval = statistics.mean(intervals)
        deviation = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        variation = deviation / mean_interval if mean_interval > 0 else None
        if variation is None:
            regularity = None
        elif variation <= 0:
            regularity = MAX_REGULARITY
        else:
            regularity = round(min(MAX_REGULARITY, 1.0 / variation), 4)

        sent = _numbers([record.fields.get("orig_bytes") for record in ordered])
        fields: dict[str, Any] = {
            "connections": len(ordered),
            "mean_interval_seconds": round(mean_interval, 3),
            "interval_stdev_seconds": round(deviation, 3),
            # Reciprocal coefficient of variation, as in regularity.py: high
            # means a near-constant rate, low means bursty. Capped, because a
            # perfectly constant rate has zero variation.
            "interval_regularity": regularity,
            "identical_intervals": deviation == 0.0,
        }
        if sent:
            fields["distinct_bytes_sent"] = len(set(sent))
            fields["identical_bytes_sent"] = len(set(sent)) == 1
        results.append((f"timing:{pair}", fields))
    return results


def prompt_payload(context: AlertContext) -> list[dict[str, Any]]:
    """The same observations, shaped for the model's user payload."""
    return [
        {"observation_id": identifier, **fields}
        for identifier, fields in observations(context)
    ]


def identifiers(context: AlertContext) -> list[str]:
    """Identifiers the model may cite, for the response allow-list."""
    return [identifier for identifier, _ in observations(context)]
