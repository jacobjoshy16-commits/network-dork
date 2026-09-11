"""An explicit no-telemetry provider; it issues no context queries."""

from datetime import timedelta

from network_dork.models import Alert, AlertContext

class NullContextProvider:
    def __init__(self, window_days: int = 7) -> None:
        if window_days < 1:
            raise ValueError("window_days must be positive")
        self.window_days = window_days

    def gather(self, alert: Alert) -> AlertContext:
        return AlertContext(
            alert=alert,
            window_start=alert.timestamp - timedelta(days=self.window_days),
            window_end=alert.timestamp,
            flows=[],
            dns=[],
            auth=[],
            prior_alert_count=None,
            unavailable={
                "flows": "No telemetry provider configured",
                "dns": "No telemetry provider configured",
                "auth": "No telemetry provider configured",
                "prior_alerts": "No telemetry provider configured",
            },
        )
