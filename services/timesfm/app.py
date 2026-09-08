#!/usr/bin/env python3
"""TimesFM forecasting sidecar.

Runs in its own container so that torch and the HuggingFace stack stay out of
the investigation runtime. Deliberately built on the standard library HTTP
server: this service should add no dependencies of its own beyond the model.

It forecasts and nothing else. It holds no alert data, makes no outbound
calls, and never decides that a series is anomalous -- scoring belongs to
network_dork.anomaly, on the other side of this boundary.

Licensing: only TimesFM weights up to 2.5 are Apache-2.0. The 3.0 weights
forbid production use, so this service refuses to load them.

Weights are never downloaded at request time. Stage them once with
scripts/stage_timesfm_weights.py and point NETWORK_DORK_TIMESFM_CHECKPOINT at
the local directory; HF_HUB_OFFLINE=1 keeps the loader from reaching out.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import sys
from typing import Any

LOGGER = logging.getLogger("timesfm-sidecar")

MAX_REQUEST_BYTES = 8 * 1024 * 1024
MAX_HORIZON = 1024
MAX_CONTEXT = 16384
# TimesFM 3.x weights are non-commercial; refuse them rather than let a
# deployment discover the licence problem in production.
NON_COMMERCIAL = re.compile(r"timesfm[-_]?3(\.|$|[-_])", re.IGNORECASE)
QUANTILES = (0.1, 0.9)


class ModelUnavailable(RuntimeError):
    pass


def checkpoint_digest(path: Path) -> str | None:
    """Hash the staged weights so a report can name what produced it."""
    manifest = path / "SHA256SUMS"
    if manifest.is_file():
        return hashlib.sha256(manifest.read_bytes()).hexdigest()
    return None


class TimesFMModel:
    """Thin wrapper around the timesfm package.

    Import is deferred so the service can start, report its health, and fail
    with a clear message when weights are missing, instead of dying on import.
    """

    def __init__(self, checkpoint: str) -> None:
        if NON_COMMERCIAL.search(checkpoint):
            raise ModelUnavailable(
                f"Refusing checkpoint {checkpoint!r}: TimesFM 3.x weights are "
                "licensed for non-commercial, non-production use. Pin 2.5."
            )
        self.checkpoint = checkpoint
        self.name = Path(checkpoint).name or checkpoint
        self.digest = checkpoint_digest(Path(checkpoint))
        self._model: Any = None

    def _load(self) -> Any:
        if self._model is not None:
            return self._model
        try:
            import timesfm
        except ImportError as exc:  # pragma: no cover - container-only path
            raise ModelUnavailable(
                "The timesfm package is not installed in this container"
            ) from exc
        LOGGER.info("loading checkpoint %s", self.checkpoint)
        self._model = timesfm.TimesFM_2p5_200M_torch.from_pretrained(
            self.checkpoint
        )
        self._model.compile(
            timesfm.ForecastConfig(
                max_context=MAX_CONTEXT,
                max_horizon=MAX_HORIZON,
                normalize_inputs=True,
                use_continuous_quantile_head=True,
            )
        )
        return self._model

    def forecast(
        self, values: list[float], horizon: int
    ) -> tuple[list[float], list[float], list[float]]:
        model = self._load()
        point, quantile = model.forecast(
            horizon=horizon, inputs=[values]
        )
        median = [float(value) for value in point[0][:horizon]]
        # The quantile head returns [batch, horizon, quantile]; fall back to
        # the point forecast when a build ships without it.
        try:
            lower = [float(quantile[0][step][1]) for step in range(horizon)]
            upper = [float(quantile[0][step][9]) for step in range(horizon)]
        except (IndexError, TypeError):
            lower = list(median)
            upper = list(median)
        return median, lower, upper


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    model: TimesFMModel

    def log_message(self, fmt: str, *args: Any) -> None:
        LOGGER.info("%s - %s", self.address_string(), fmt % args)

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        if self.path != "/health":
            self._send(404, {"error": "not found"})
            return
        self._send(
            200,
            {
                "status": "ok",
                "model": self.model.name,
                "model_digest": self.model.digest,
            },
        )

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        if self.path != "/forecast":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send(400, {"error": "invalid content length"})
            return
        if length <= 0 or length > MAX_REQUEST_BYTES:
            self._send(413, {"error": "request too large"})
            return

        try:
            request = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeError):
            self._send(400, {"error": "invalid JSON"})
            return
        if not isinstance(request, dict):
            self._send(400, {"error": "request must be an object"})
            return

        values = request.get("values")
        horizon = request.get("horizon")
        if (
            not isinstance(values, list)
            or not values
            or len(values) > MAX_CONTEXT
            or any(
                isinstance(value, bool) or not isinstance(value, (int, float))
                for value in values
            )
        ):
            self._send(400, {"error": "values must be a list of numbers"})
            return
        if (
            isinstance(horizon, bool)
            or not isinstance(horizon, int)
            or not 1 <= horizon <= MAX_HORIZON
        ):
            self._send(400, {"error": "horizon out of range"})
            return

        try:
            median, lower, upper = self.model.forecast(
                [float(value) for value in values], horizon
            )
        except ModelUnavailable as exc:
            self._send(503, {"error": str(exc)})
            return
        except Exception:
            LOGGER.exception("forecast failed")
            self._send(500, {"error": "forecast failed"})
            return

        self._send(
            200,
            {
                "model": self.model.name,
                "model_digest": self.model.digest,
                "median": median,
                "lower": lower,
                "upper": upper,
            },
        )


def main() -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    checkpoint = os.environ.get(
        "NETWORK_DORK_TIMESFM_CHECKPOINT", "/models/timesfm-2.5-200m"
    )
    host = os.environ.get("NETWORK_DORK_TIMESFM_HOST", "127.0.0.1")
    port = int(os.environ.get("NETWORK_DORK_TIMESFM_PORT", "11435"))

    try:
        model = TimesFMModel(checkpoint)
    except ModelUnavailable as exc:
        print(f"timesfm sidecar refused to start: {exc}", file=sys.stderr)
        return 1

    handler = type("BoundHandler", (Handler,), {"model": model})
    server = ThreadingHTTPServer((host, port), handler)
    LOGGER.info("timesfm sidecar listening on %s:%s", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
