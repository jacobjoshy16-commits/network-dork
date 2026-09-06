# Contributing

Requires Python 3.11+ and uv.

```sh
uv sync --extra dev
make test
uv run python -m network_dork adapters
```

The project is under phased construction. Phase 1 implements normalized
file alerts, schema validation, layered configuration, adapter discovery,
and synthetic fixture data. It does not yet implement investigations,
Ollama calls, persistent reports, evaluation, or deployment boundaries.

Do not introduce detection logic or remediation capabilities.
Telemetry must be protected by actual permissions and credentials;
opening a file in read mode is not a security boundary.

Tests must not contact external services. Integration tests requiring
local services must clearly identify those requirements and must not
silently replace the services with fake implementations.

All fixtures must document their origin. Do not supply synthetic
labels for public captures without evidence supporting those labels.

Configuration is trusted executable input because it names Python
adapter classes. Never accept adapter references from an alert or LLM.

Phase 1 pins direct dependencies. The executing agent must generate
and commit uv.lock; subsequent clean-clone verification must use it.
