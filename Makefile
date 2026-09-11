UV ?= uv
CONFIG ?= config/default.yaml
COMPOSE ?= docker compose
SERVICE ?= network-dork
TIMESFM_VENV ?= .venv-timesfm

.PHONY: sync test adapters context run-fake demo-local up down demo ci-local corpus eval eval-reports preflight timesfm-up timesfm-down timesfm-local-setup timesfm-local

sync:
	$(UV) sync --extra dev

test: sync
	$(UV) run --extra dev pytest

adapters: sync
	$(UV) run python -m network_dork adapters --config "$(CONFIG)"

context: sync
	$(UV) run python -m network_dork context --config "$(CONFIG)" --alert-id syn-001

run-fake: sync
	NETWORK_DORK_STATE_PATH=var/fake/state.sqlite3 \
	NETWORK_DORK_REPORTS_PATH=var/fake/reports.sqlite3 \
	NETWORK_DORK_AUDIT_PATH=var/fake/audit.jsonl \
	$(UV) run python -m network_dork run --config "$(CONFIG)" --fake

preflight: sync
	$(UV) run python -m network_dork preflight --config "$(CONFIG)"

timesfm-up:
	$(COMPOSE) --profile timesfm up --build -d timesfm

timesfm-down:
	$(COMPOSE) --profile timesfm down --remove-orphans

timesfm-local-setup:
	$(UV) venv --python 3.11 $(TIMESFM_VENV)
	VIRTUAL_ENV=$(TIMESFM_VENV) $(UV) pip install "torch==2.5.1" "timesfm[torch]==2.5.0"

timesfm-local:
	NETWORK_DORK_TIMESFM_CHECKPOINT=$(CURDIR)/models/timesfm-2.5-200m \
	HF_HUB_OFFLINE=1 \
	$(TIMESFM_VENV)/bin/python services/timesfm/app.py

corpus: sync
	$(UV) run python scripts/generate_timeseries_corpus.py

eval: sync
	$(UV) run python -m network_dork eval --config "$(CONFIG)" --forecaster all

eval-reports: sync
	$(UV) run python -m network_dork eval-reports var/demo/*

demo-local: sync
	$(UV) run python -m network_dork demo --config "$(CONFIG)"

up:
	$(COMPOSE) up --build -d $(SERVICE)

down:
	$(COMPOSE) down --remove-orphans

demo:
	$(COMPOSE) run --rm $(SERVICE) \
		python -m network_dork demo --config /workspace/$(CONFIG)

ci-local: sync
	$(UV) run --extra dev pytest
	$(UV) run python -m network_dork adapters --config "$(CONFIG)"
	NETWORK_DORK_STATE_PATH=var/ci/state.sqlite3 \
	NETWORK_DORK_REPORTS_PATH=var/ci/reports.sqlite3 \
	NETWORK_DORK_AUDIT_PATH=var/ci/audit.jsonl \
	$(UV) run python -m network_dork run --config "$(CONFIG)" --fake
