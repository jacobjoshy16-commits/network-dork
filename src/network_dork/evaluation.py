"""Measure a forecaster against the labelled corpus.

This exists so "the forecaster helps" is a number rather than an opinion, and
so a learned forecaster has to earn its dependencies against the baseline
instead of being adopted because it is newer.

The evaluation slides an imagined alert time across the corpus. At each point
it forecasts the preceding window from prior history and takes the largest
deviation, exactly as enrichment does at investigation time. A point is
positive when that window overlaps a malicious label.

Benign labelled windows -- the backup, the patch cycle, the onboarded host --
count as negatives. Flagging one is a false positive, and the confounder
flag rate is reported separately because that number, not recall, is what
decides whether an analyst keeps trusting the evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
from pathlib import Path
from typing import Iterable

from network_dork.anomaly import InsufficientHistory
from network_dork.interfaces import Forecaster
from network_dork.models import TimeSeries

DEFAULT_CORPUS = Path("fixtures/timeseries")


@dataclass(frozen=True)
class LabelWindow:
    entity: str
    category: str
    malicious: bool
    start: datetime
    end: datetime

    def overlaps(self, start: datetime, end: datetime) -> bool:
        return start < self.end and self.start < end


@dataclass(frozen=True)
class EvaluationPoint:
    entity: str
    metric: str
    alert_time: datetime
    window_start: datetime
    malicious: bool
    category: str | None
    peak_score: float


@dataclass
class Corpus:
    start: datetime
    bucket_seconds: int
    metrics: list[str]
    hosts: dict[str, dict]
    labels: list[LabelWindow] = field(default_factory=list)

    @classmethod
    def load(cls, directory: Path = DEFAULT_CORPUS) -> "Corpus":
        raw = json.loads((directory / "corpus.json").read_text("utf-8"))
        labels_raw = json.loads((directory / "labels.json").read_text("utf-8"))
        return cls(
            start=datetime.fromisoformat(raw["start"]),
            bucket_seconds=raw["bucket_seconds"],
            metrics=list(raw["metrics"]),
            hosts=raw["hosts"],
            labels=[
                LabelWindow(
                    entity=item["entity"],
                    category=item["category"],
                    malicious=bool(item["malicious"]),
                    start=datetime.fromisoformat(item["start"]),
                    end=datetime.fromisoformat(item["end"]),
                )
                for item in labels_raw["windows"]
            ],
        )

    def at(self, index: int) -> datetime:
        return self.start + timedelta(seconds=self.bucket_seconds * index)

    def series(self, entity: str, metric: str) -> list[float]:
        return self.hosts[entity]["series"][metric]

    def label_for(
        self, entity: str, start: datetime, end: datetime
    ) -> LabelWindow | None:
        for window in self.labels:
            if window.entity == entity and window.overlaps(start, end):
                return window
        return None


def _has_usable_history(
    values: list[float], *, min_observations: int, min_span_fraction: float
) -> bool:
    """Mirror the bucketizer's coverage guard.

    A mostly-empty history is not history. Evaluating it would credit or
    blame the forecaster for a decision the real system never makes, because
    the provider refuses to forecast at all in that case.
    """
    non_zero = [index for index, value in enumerate(values) if value > 0]
    if len(non_zero) < min_observations:
        return False
    span = non_zero[-1] - non_zero[0]
    return span >= len(values) * min_span_fraction


def evaluate(
    forecaster: Forecaster,
    corpus: Corpus,
    *,
    history_buckets: int = 4032,
    horizon_buckets: int = 72,
    stride_buckets: int = 72,
    min_observations: int = 100,
    min_span_fraction: float = 0.5,
    metrics: Iterable[str] | None = None,
) -> tuple[list[EvaluationPoint], int]:
    """Return (scored points, count skipped for insufficient history)."""
    from network_dork.anomaly import score as score_window

    points: list[EvaluationPoint] = []
    skipped = 0
    chosen = list(metrics or corpus.metrics)
    total_needed = history_buckets + horizon_buckets

    for entity in corpus.hosts:
        for metric in chosen:
            values = corpus.series(entity, metric)
            index = total_needed
            while index <= len(values):
                history = values[index - total_needed: index - horizon_buckets]
                actual = values[index - horizon_buckets: index]
                alert_time = corpus.at(index)
                window_start = corpus.at(index - horizon_buckets)

                if not _has_usable_history(
                    history,
                    min_observations=min_observations,
                    min_span_fraction=min_span_fraction,
                ):
                    skipped += 1
                    index += stride_buckets
                    continue

                series = TimeSeries(
                    metric=metric,
                    entity=entity,
                    bucket_seconds=corpus.bucket_seconds,
                    start=corpus.at(index - total_needed),
                    values=history,
                )
                try:
                    prediction = forecaster.forecast(series, horizon_buckets)
                except InsufficientHistory:
                    skipped += 1
                    index += stride_buckets
                    continue

                deviations = score_window(
                    series=series,
                    actual=actual,
                    forecast=prediction,
                    first_index=0,
                )
                label = corpus.label_for(entity, window_start, alert_time)
                points.append(
                    EvaluationPoint(
                        entity=entity,
                        metric=metric,
                        alert_time=alert_time,
                        window_start=window_start,
                        malicious=bool(label and label.malicious),
                        category=label.category if label else None,
                        peak_score=max(
                            (item.score for item in deviations), default=0.0
                        ),
                    )
                )
                index += stride_buckets
    return points, skipped


@dataclass(frozen=True)
class Scoreboard:
    threshold: float
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    confounder_flags: int
    confounder_total: int

    @property
    def precision(self) -> float:
        flagged = self.true_positives + self.false_positives
        return self.true_positives / flagged if flagged else 0.0

    @property
    def recall(self) -> float:
        actual = self.true_positives + self.false_negatives
        return self.true_positives / actual if actual else 0.0

    @property
    def f1(self) -> float:
        if not (self.precision and self.recall):
            return 0.0
        return 2 * self.precision * self.recall / (self.precision + self.recall)

    @property
    def false_positive_rate(self) -> float:
        negatives = self.false_positives + self.true_negatives
        return self.false_positives / negatives if negatives else 0.0

    @property
    def confounder_rate(self) -> float:
        if not self.confounder_total:
            return 0.0
        return self.confounder_flags / self.confounder_total


def tally(points: list[EvaluationPoint], threshold: float) -> Scoreboard:
    tp = fp = fn = tn = 0
    confounder_flags = confounder_total = 0
    for point in points:
        flagged = point.peak_score >= threshold
        if point.malicious:
            tp += flagged
            fn += not flagged
        else:
            fp += flagged
            tn += not flagged
        # A benign labelled window is the hard negative: unusual, but fine.
        if point.category is not None and not point.malicious:
            confounder_total += 1
            confounder_flags += flagged
    return Scoreboard(
        threshold=threshold,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        confounder_flags=confounder_flags,
        confounder_total=confounder_total,
    )


def sweep(
    points: list[EvaluationPoint], thresholds: Iterable[float]
) -> list[Scoreboard]:
    return [tally(points, threshold) for threshold in thresholds]


def attacks_found(
    points: list[EvaluationPoint], threshold: float
) -> dict[str, bool]:
    """Was each malicious campaign caught by any evaluation point?

    Per-point recall understates real usefulness: evaluation points that
    barely clip the edge of an attack window cannot be detected and should
    not be. What matters operationally is whether the campaign surfaced at
    all, which is what this reports.
    """
    caught: dict[str, bool] = {}
    for point in points:
        if not point.malicious or point.category is None:
            continue
        hit = point.peak_score >= threshold
        caught[point.category] = caught.get(point.category, False) or hit
    return caught


def recall_by_category(
    points: list[EvaluationPoint], threshold: float
) -> dict[str, tuple[int, int]]:
    """Per-category (found, total) for malicious windows."""
    found: dict[str, tuple[int, int]] = {}
    for point in points:
        if not point.malicious or point.category is None:
            continue
        hits, total = found.get(point.category, (0, 0))
        found[point.category] = (
            hits + (point.peak_score >= threshold),
            total + 1,
        )
    return found
