# Bayora Makefile
# Source: docs/architecture.md §13

.PHONY: up down logs test test-security breakit timing verify-log lint sync-agents check

VENV := .venv
PYTHON := $(VENV)/bin/python3
PYTEST := $(VENV)/bin/pytest

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

sync-agents:
	./scripts/sync-agents.sh

lint:
	@echo "lint: not implemented yet (T07)"

test:
	$(PYTEST) tests/unit tests/integration -v

test-security:
	@echo "test-security: not implemented yet (T09)"

breakit:
	@echo "breakit: not implemented yet (T09)"

timing:
	@echo "timing: not implemented yet (T08)"

verify-log:
	@docker compose exec -T verifier python3 -c "import urllib.request as u, json, sys; res = json.loads(u.urlopen('http://127.0.0.1:8002/verify').read().decode()); print(json.dumps(res, indent=2)); sys.exit(0 if res.get('ok') else 1)"

check: lint test test-security breakit
