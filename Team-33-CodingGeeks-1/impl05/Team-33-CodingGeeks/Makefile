ENV_FILE := .socp.env
-include $(ENV_FILE)

SOCP_BACKDOORED ?= 0

.PHONY: setup run-server run-client test fmt backdoored clean-backdoor

setup:
	python -m pip install -r requirements.txt

run-server:
	SOCP_BACKDOORED=$(SOCP_BACKDOORED) python -m socp.cmd.server --config configs/server.yaml

run-client:
	python -m socp.cmd.client --server ws://127.0.0.1:7001

backdoored:
	@echo "SOCP_BACKDOORED=1" > $(ENV_FILE)
	@echo "Backdoored build enabled (weak keys + replay bypass)."

clean-backdoor:
	@echo "SOCP_BACKDOORED=0" > $(ENV_FILE)
	@echo "Backdoors disabled."

test:
	python -m pytest -q

fmt:
	python -m pip install ruff
	ruff check --fix . || true
