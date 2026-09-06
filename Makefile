UV ?= uv
CONFIG ?= config/default.yaml

.PHONY: sync test adapters context demo

sync:
	$(UV) sync --extra dev

test: sync
	$(UV) run --extra dev pytest

adapters: sync
	$(UV) run python -m network_dork adapters --config "$(CONFIG)"

context: sync
	$(UV) run python -m network_dork context --config "$(CONFIG)" --alert-id syn-001

demo: sync
	$(UV) run python -m network_dork demo --config "$(CONFIG)"
