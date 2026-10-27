# Bayora Makefile
# Source: docs/architecture.md §13

.PHONY: up prod-up down logs test test-security breakit timing verify-log lint sync-agents check

VENV := .venv
PYTHON := $(VENV)/bin/python3
PYTEST := $(VENV)/bin/pytest

up:
	docker compose up -d

prod-up:
	docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

down:
	docker compose down

logs:
	docker compose logs -f

sync-agents:
	./scripts/sync-agents.sh

lint:
	@$(PYTHON) -m py_compile $$(find gateway logger verifier red blue breakit scripts tests -name '*.py')
	@echo "lint: python syntax ok"

test:
	$(PYTEST) tests/unit tests/integration -v

test-security:
	@docker compose pause red blue >/dev/null 2>&1 || true
	@$(PYTEST) tests/security -v; status=$$?; \
	docker compose unpause red blue >/dev/null 2>&1 || true; \
	exit $$status

breakit:
	$(PYTHON) -m breakit.harness

timing:
	$(PYTHON) experiments/timing/run.py

verify-log:
	@docker compose exec -T verifier python3 -c "import urllib.request as u, json, sys; res = json.loads(u.urlopen('http://127.0.0.1:8002/verify').read().decode()); print(json.dumps(res, indent=2)); sys.exit(0 if res.get('ok') else 1)"

check: lint test test-security breakit
