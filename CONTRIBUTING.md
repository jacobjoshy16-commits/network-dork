# Contributing

Requirements for local development:

- Python 3.11+
- `uv`
- Docker for container-path checks
- Ollama only when exercising the real model demo

## Local development loop

```sh
uv sync --extra dev
make test
make adapters
make context
make run-fake
```

## Packaging path

```sh
make up
make demo
make down
```

## Rules for contributions

- Do not add detection logic. This project consumes existing alerts only.
- Do not add remediation capability, response hooks, or “future action” stubs.
- Preserve the read-only telemetry boundary and separate report-writing identity.
- Keep pipeline orchestration importing interfaces, not concrete adapters.
- Tests must not contact public services.
- If you add fixtures, document their origin and keep ground truth out of prompts.
- Run the tests you add and keep `uv.lock` up to date.

## OpenSearch integrations

When working on OpenSearch support:

- telemetry credentials must be read-only
- report credentials must be write-scoped only to the report index
- use `scripts/bootstrap_opensearch_security.py` to create distinct roles
- keep the automated permission test proving the telemetry identity cannot write

## CI expectations

The GitHub Actions workflow runs:

- lockfile verification
- the full pytest suite
- adapter listing smoke test
- fake end-to-end pipeline smoke test

Keep those commands passing before opening a PR.
