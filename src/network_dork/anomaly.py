"""Scoring observed values against a forecast band.

A forecaster predicts; it does not judge. This module turns a prediction and
an observation into a deviation score, and nothing here decides that a
deviation is malicious. A high score means "this volume was unusual for this
entity", which is a statistical statement about traffic, not a detection.

The baseline forecaster lives here too. Any learned forecaster has to beat it
on the evaluation corpus to be worth its dependencies; keeping the two side by
side makes that comparison the default rather than an afterthought.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import statistics

from network_dork.models import Forecast, TimeSeries

# Scales the median absolute deviation to a normal standard deviation, and
# the ~80% central interval used for the band (0.1 to 0.9 quantiles).
_MAD_TO_SIGMA = 1.4826
_Q10_SIGMA = 1.2816


class InsufficientHistory(RuntimeError):
    """Not enough history to forecast this entity."""


@dataclass(frozen=True)
class Deviation:
    timestamp: datetime
    actual: float
    predicted: float
    lower: float
    upper: float
    # 0.0 inside the band; otherwise band-widths outside it.
    score: float

    @property
    def direction(self) -> str:
        if self.score == 0.0:
            return "within_forecast"
        return "above_forecast" if self.actual > self.upper else "below_forecast"


def score(
    *,
    series: TimeSeries,
    actual: list[float],
    forecast: Forecast,
    first_index: int,
) -> list[Deviation]:
    """Compare observed values against the forecast band, bucket by bucket.

    ``first_index`` is the position in ``series`` that ``actual[0]`` occupies,
    so deviations carry real timestamps.
    """
    if len(actual) != len(forecast.median):
        raise ValueError("Actual and forecast lengths differ")

    deviations: list[Deviation] = []
    for offset, observed in enumerate(actual):
        lower = forecast.lower[offset]
        upper = forecast.upper[offset]
        width = upper - lower
        if observed > upper:
            excess = observed - upper
        elif observed < lower:
            excess = lower - observed
        else:
            excess = 0.0
        # A degenerate band (a perfectly flat history) would divide by zero;
        # fall back to the prediction's own magnitude, then to a unit scale.
        scale = width or abs(forecast.median[offset]) or 1.0
        deviations.append(
            Deviation(
                timestamp=series.timestamp_at(first_index + offset),
                actual=observed,
                predicted=forecast.median[offset],
                lower=lower,
                upper=upper,
                score=round(excess / scale, 4),
            )
        )
    return deviations


def most_deviant(deviations: list[Deviation], limit: int) -> list[Deviation]:
    """Return the highest-scoring buckets, oldest first.

    Numeric evidence is sent to a language model with a character budget, so
    the full series is summarized down to the buckets that carry the signal.
    """
    if limit < 1:
        raise ValueError("limit must be positive")
    ranked = sorted(deviations, key=lambda item: item.score, reverse=True)
    selected = [item for item in ranked[:limit] if item.score > 0]
    return sorted(selected, key=lambda item: item.timestamp)


class SeasonalNaiveForecaster:
    """Predict each bucket from the same bucket one period ago.

    This is the baseline. Network telemetry is strongly daily, so "the same
    time yesterday" is a genuinely hard reference point to beat, and the band
    comes from how badly that rule has done recently rather than from any
    distributional assumption.
    """

    name = "seasonal-naive"

    def __init__(
        self,
        *,
        period_buckets: int,
        band_sigma: float = _Q10_SIGMA,
        min_band_fraction: float = 0.15,
        min_history_buckets: int | None = None,
    ) -> None:
        if period_buckets < 1:
            raise ValueError("period_buckets must be positive")
        if band_sigma <= 0:
            raise ValueError("band_sigma must be positive")
        if min_band_fraction < 0:
            raise ValueError("min_band_fraction must not be negative")
        self.period_buckets = period_buckets
        self.band_sigma = band_sigma
        self.min_band_fraction = min_band_fraction
        self.min_history_buckets = min_history_buckets or period_buckets * 2

    def forecast(self, series: TimeSeries, horizon: int) -> Forecast:
        if horizon < 1:
            raise ValueError("horizon must be positive")
        values = series.values
        needed = max(self.min_history_buckets, self.period_buckets + horizon)
        if len(values) < needed:
            raise InsufficientHistory(
                f"{series.entity}/{series.metric} has {len(values)} buckets; "
                f"{needed} are required"
            )

        # Repeat the most recent period, wrapping when the horizon is longer
        # than one period.
        last_period = values[len(values) - self.period_buckets:]
        median = [
            last_period[offset % self.period_buckets]
            for offset in range(horizon)
        ]

        residuals = [
            values[index] - values[index - self.period_buckets]
            for index in range(self.period_buckets, len(values))
        ]
        centre = statistics.median(residuals)
        spread = statistics.median(
            [abs(residual - centre) for residual in residuals]
        ) * _MAD_TO_SIGMA
        margin = self.band_sigma * spread

        # A flawlessly periodic history yields a zero-width band, which would
        # make every deviation score maximally. Floor the band against the
        # prediction's own magnitude so ordinary variation stays inside it.
        centred = [value + centre for value in median]
        margins = [
            max(margin, self.min_band_fraction * abs(value))
            for value in centred
        ]
        return Forecast(
            model=self.name,
            model_digest=None,
            median=centred,
            lower=[
                value - width for value, width in zip(centred, margins)
            ],
            upper=[
                value + width for value, width in zip(centred, margins)
            ],
        )
