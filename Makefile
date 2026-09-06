UV ?= uv

.PHONY: sync test adapters

sync:
	$(UV) sync --extra dev

test: sync
	$(UV) run --extra dev pytest

adapters: sync
	$(UV) run python -m network_dork adapters
