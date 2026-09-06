"""Explicit deterministic test client. Never impersonates a real model."""

from __future__ import annotations

import json

class FakeLLMClient:
    def __init__(
        self,
        responses: list[str | Exception] | None = None,
    ) -> None:
        self.responses = None if responses is None else list(responses)
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        if self.responses is not None:
            if not self.responses:
                raise RuntimeError("FakeLLMClient canned responses exhausted")
            result = self.responses.pop(0)
            if isinstance(result, Exception):
                raise result
            return result

        request = json.loads(user)
        identity = request["required_identity"]
        context = request["supplied_context"]
        missing = sorted(context["unavailable"])
        summary = (
            "This deterministic test response does not classify the alert. "
            "An analyst must review the supplied evidence."
        )
        if missing:
            summary += " Unavailable context: " + ", ".join(missing) + "."
        return json.dumps(
            {
                **identity,
                "summary": summary,
                "mitre_technique": None,
                "nist_control": None,
                "confidence": "low",
                "context_used": [
                    f"alert:{context['alert']['alert_id']}"
                ],
                "suggested_next_step": (
                    "A human analyst should review the original alert "
                    "and the available telemetry."
                ),
            }
        )
