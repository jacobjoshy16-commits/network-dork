"""Adds forecast-versus-actual evidence to an existing context provider.

This decorates whatever provider is already configured. The wrapped provider's
evidence passes through untouched; this only appends a fifth evidence kind.

The enrichment boundary, restated because it is the reason this design is
acceptable in a controlled network:

* it runs only for an alert that already exists, never on a schedule,
* it never emits an alert, so alert volume is unchanged,
* it reads the same telemetry through the same read-only path,
* a forecaster outage marks forecast context unavailable, exactly as a
  missing log file does, and the investigation still completes.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from network_dork.anomaly import Deviation, InsufficientHistory, most_deviant, score
from network_dork.interfaces import (
    AuditLog,
    ContextProvider,
    Forecaster,
    TimeSeriesProvider,
)
from network_dork.models import Alert, AlertContext, AuditEvent, EvidenceRecord


class ForecastEnrichingContextProvider:
    def __init__(
        self,
        inner: ContextProvider,
        series_provider: TimeSeriesProvider,
        forecaster: Forecaster,
        audit: AuditLog,
        *,
        metrics: list[str] | None = None,
        bucket_seconds: int = 300,
        history_buckets: int = 4032,
        horizon_buckets: int = 72,
        max_evidence: int = 5,
        min_score: float = 24.0,
        min_score_by_metric: dict[str, float] | None = None,
        baseline_started_at: datetime | None = None,
    ) -> None:
        if bucket_seconds < 1:
            raise ValueError("bucket_seconds must be positive")
        if history_buckets < 1 or horizon_buckets < 1:
            raise ValueError("history and horizon must be positive")
        if max_evidence < 1:
            raise ValueError("max_evidence must be positive")
        if min_score < 0:
            raise ValueError("min_score must not be negative")
        if any(value < 0 for value in (min_score_by_metric or {}).values()):
            raise ValueError("per-metric thresholds must not be negative")
        self.inner = inner
        self.series_provider = series_provider
        self.forecaster = forecaster
        self.audit = audit
        self.metrics = list(
            metrics
            or [
                "conn_count",
                "bytes_out",
                "distinct_destinations",
                "conn_regularity",
            ]
        )
        self.bucket_seconds = bucket_seconds
        self.history_buckets = history_buckets
        self.horizon_buckets = horizon_buckets
        self.max_evidence = max_evidence
        self.min_score = min_score
        self.min_score_by_metric = dict(min_score_by_metric or {})
        self.baseline_started_at = baseline_started_at

    def close(self) -> None:
        for candidate in (self.inner, self.series_provider, self.forecaster):
            close = getattr(candidate, "close", None)
            if callable(close):
                close()

    def _record(
        self,
        alert: Alert,
        operation_id: str,
        stage: str,
        parameters: dict[str, Any],
    ) -> None:
        self.audit.record(
            AuditEvent(
                timestamp=datetime.now(timezone.utc),
                alert_id=alert.alert_id,
                operation_id=operation_id,
                action="context_query",
                stage=stage,
                parameters=parameters,
            )
        )

    def _baseline_pending(self, alert: Alert) -> str | None:
        """Reason to hold off, while the deployment is still accumulating.

        A forecast built on a partial history is worse than none: the missing
        stretch reads as absence, and ordinary traffic then looks like a
        large deviation. Nothing is being trained here -- the wait is for
        data, not for a model to learn.
        """
        if self.baseline_started_at is None:
            return None
        needed = timedelta(
            seconds=self.bucket_seconds * self.history_buckets
        )
        ready_at = self.baseline_started_at + needed
        if alert.timestamp >= ready_at:
            return None
        remaining = (ready_at - alert.timestamp).total_seconds() / 86400
        return (
            "Baseline period is still in progress: collection began "
            f"{self.baseline_started_at.date()} and needs "
            f"{needed.days} days of history; about {remaining:.1f} days "
            "remain before forecasting begins"
        )

    @staticmethod
    def _entity(alert: Alert) -> str | None:
        if alert.src_ip is not None:
            return str(alert.src_ip)
        if alert.dst_ip is not None:
            return str(alert.dst_ip)
        return None

    def _evidence(
        self, metric: str, entity: str, deviation: Deviation
    ) -> EvidenceRecord:
        bucket = deviation.timestamp.isoformat()
        return EvidenceRecord(
            evidence_id=f"forecast:{metric}:{bucket}",
            kind="forecast",
            source=f"forecast:{self.forecaster.__class__.__name__}:{metric}",
            timestamp=deviation.timestamp,
            fields={
                "metric": metric,
                "entity": entity,
                "bucket_seconds": self.bucket_seconds,
                "observed": deviation.actual,
                "predicted": deviation.predicted,
                "predicted_range": [deviation.lower, deviation.upper],
                "deviation_score": deviation.score,
                "direction": deviation.direction,
                "note": (
                    "Statistical deviation from a predicted range. Not a "
                    "detection and not evidence of malicious activity."
                ),
            },
        )

    def _threshold(self, metric: str) -> float:
        """Each metric carries its own noise floor; one bar does not fit all."""
        return self.min_score_by_metric.get(metric, self.min_score)

    def _forecast_metric(
        self, alert: Alert, metric: str, entity: str
    ) -> list[EvidenceRecord]:
        total = self.history_buckets + self.horizon_buckets
        series = self.series_provider.series(
            metric=metric,
            entity=entity,
            end=alert.timestamp,
            buckets=total,
            bucket_seconds=self.bucket_seconds,
        )
        if len(series.values) < total:
            raise InsufficientHistory(
                f"{entity}/{metric} returned {len(series.values)} of "
                f"{total} buckets"
            )

        history = series.model_copy(
            update={"values": series.values[: self.history_buckets]}
        )
        actual = series.values[self.history_buckets:]
        prediction = self.forecaster.forecast(history, self.horizon_buckets)
        deviations = score(
            series=series,
            actual=actual,
            forecast=prediction,
            first_index=self.history_buckets,
        )
        return [
            self._evidence(metric, entity, deviation)
            for deviation in most_deviant(
                deviations, self.max_evidence, self._threshold(metric)
            )
        ]

    def gather(self, alert: Alert) -> AlertContext:
        base = self.inner.gather(alert)
        operation_id = str(uuid4())
        entity = self._entity(alert)
        parameters: dict[str, Any] = {
            "kind": "forecast",
            "entity": entity,
            "metrics": self.metrics,
            "bucket_seconds": self.bucket_seconds,
            "history_buckets": self.history_buckets,
            "horizon_buckets": self.horizon_buckets,
        }
        self._record(alert, operation_id, "attempt", parameters)

        pending = self._baseline_pending(alert)
        if pending is not None:
            self._record(
                alert,
                operation_id,
                "success",
                {**parameters, "available": False, "reason": pending},
            )
            return self._merge(base, [], pending)

        if entity is None:
            reason = "Alert names no IP address to forecast"
            self._record(
                alert,
                operation_id,
                "success",
                {**parameters, "available": False, "reason": reason},
            )
            return self._merge(base, [], reason)

        evidence: list[EvidenceRecord] = []
        skipped: list[str] = []
        for metric in self.metrics:
            try:
                evidence.extend(self._forecast_metric(alert, metric, entity))
            except InsufficientHistory as exc:
                skipped.append(f"{metric}: {exc}")
            except Exception as exc:
                # A forecaster outage must not fail the investigation.
                skipped.append(f"{metric}: {type(exc).__name__}")

        if not evidence and len(skipped) < len(self.metrics):
            reason = (
                "Traffic was forecastable and stayed within its predicted "
                "range (no deviation reached this metric's evidence "
                "threshold)"
            )
            self._record(
                alert,
                operation_id,
                "success",
                {**parameters, "available": True, "result_count": 0,
                 "reason": reason, "skipped": skipped},
            )
            return self._merge(base, [], reason)

        if len(skipped) == len(self.metrics):
            reason = "No metric had enough history to forecast"
            self._record(
                alert,
                operation_id,
                "success",
                {
                    **parameters,
                    "available": False,
                    "reason": reason,
                    "skipped": skipped,
                },
            )
            return self._merge(base, [], reason)

        self._record(
            alert,
            operation_id,
            "success",
            {
                **parameters,
                "available": True,
                "result_count": len(evidence),
                "skipped": skipped,
            },
        )
        return self._merge(base, evidence, None)

    @staticmethod
    def _merge(
        base: AlertContext,
        evidence: list[EvidenceRecord],
        unavailable_reason: str | None,
    ) -> AlertContext:
        unavailable = dict(base.unavailable)
        if unavailable_reason is not None:
            unavailable["forecast"] = unavailable_reason
        # Rebuilt rather than copied so the context validators run again.
        return AlertContext(
            alert=base.alert,
            window_start=base.window_start,
            window_end=base.window_end,
            flows=base.flows,
            dns=base.dns,
            auth=base.auth,
            forecast=evidence,
            prior_alert_count=base.prior_alert_count,
            unavailable=unavailable,
            truncated=base.truncated,
        )
