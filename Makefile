UV ?= uv
CONFIG ?= config/default.yaml
COMPOSE ?= docker compose
SERVICE ?= network-dork

.PHONY: sync test adapters context run-fake demo-local up down demo ci-local

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
