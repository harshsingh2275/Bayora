# Bayora Makefile
# Source: docs/architecture.md §13

.PHONY: up down logs test test-security breakit timing verify-log lint sync-agents check

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

sync-agents:
	./scripts/sync-agents.sh

lint:
	@echo "lint: not implemented yet"

test:
	@echo "test: not implemented yet"

test-security:
	@echo "test-security: not implemented yet"

breakit:
	@echo "breakit: not implemented yet"

timing:
	@echo "timing: not implemented yet"

verify-log:
	@echo "verify-log: not implemented yet"

check: lint test test-security breakit
