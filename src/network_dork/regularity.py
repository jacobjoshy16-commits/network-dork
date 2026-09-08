"""How evenly spaced a host's connections are, bucket by bucket.

Volume metrics answer "how much"; this answers "how rhythmically". The two
catch different things, and the evaluation showed the gap concretely: the
seasonal-naive baseline finds exfiltration and scanning at precision 1.00 and
cannot find low-rate beaconing, because beaconing is not a volume event. A
callback every sixty seconds looks like a small, unremarkable amount of
traffic. What gives it away is that it does not vary -- not with the working
day, not with the user being at lunch, not at all.

No forecaster of magnitude encodes that, however good it is. So rather than
reach for a larger model, this derives a series that carries the signal
directly, and it then flows through the same forecast-and-score path as every
other metric: history sets what regularity is normal for this host, and a
departure from it becomes evidence.

The measure is the reciprocal of the coefficient of variation over a
trailing window: high means a near-constant rate, low means bursty.

The reciprocal matters. A bounded form such as 1/(1+CV) was tried first and
failed in evaluation: it compresses everything into (0, 1], so a beacon
moved the value by 0.09 while the scorer's band floor was 0.12, and the
signal vanished inside the band. The reciprocal keeps the same multiplicative
dynamic range as the count metrics -- CV 0.30 becomes 3.3, CV 0.03 becomes
31 -- so the scoring already in place works on it unchanged.

It is deliberately relative to the host's own history: a genuinely steady
server is not suspicious for being steady, only for becoming steadier than
it has ever been.
"""

from __future__ import annotations

import statistics


# A perfectly constant rate has zero variation, so the reciprocal is
# unbounded. Cap it rather than emit an infinity the models cannot carry.
MAX_REGULARITY = 100.0


def rolling_regularity(
    values: list[float], window: int, *, cap: float = MAX_REGULARITY
) -> list[float]:
    """Return per-bucket regularity over a trailing window of buckets.

    Buckets with no traffic score 0.0: an idle host is not "regular", it is
    absent, and treating silence as rhythm would flag every quiet night.
    """
    if window < 2:
        raise ValueError("window must span at least two buckets")
    if cap <= 0:
        raise ValueError("cap must be positive")

    regularity: list[float] = []
    for index in range(len(values)):
        chunk = values[max(0, index - window + 1): index + 1]
        if len(chunk) < 2:
            regularity.append(0.0)
            continue
        mean = statistics.mean(chunk)
        if mean <= 0:
            regularity.append(0.0)
            continue
        variation = statistics.stdev(chunk) / mean
        if variation <= 0:
            regularity.append(cap)
            continue
        regularity.append(round(min(cap, 1.0 / variation), 4))
    return regularity
