PYTHON_VERSIONS = 3.10 3.11 3.12 3.13 3.14 3.15
DEFAULT_PYTHON = 3.10
CLEAN_CACHES = find . \( -name '__pycache__' -o -name '*.pyc' -o -name '*.pyo' -o -name '.pytest_cache' -o -name '.ruff_cache' -o -name '.mypy_cache' \) -prune -exec rm -rf {} +


.PHONY: sync
sync:
	@uv run --no-sync python scripts/unasync.py


.PHONY: check-sync
check-sync:
	@uv run --no-sync python scripts/unasync.py --check


.PHONY: install
install:
	@uv sync
	@$(CLEAN_CACHES)


.PHONY: install-dev
install-dev:
	@uv sync --extra dev --extra otel --extra logfire
	@$(CLEAN_CACHES)


.PHONY: lock
lock:
	@uv lock
	@$(CLEAN_CACHES)


.PHONY: upgrade
upgrade:
	@uv lock --upgrade
	@uv sync --all-extras
	@$(CLEAN_CACHES)


.PHONY: stop
stop:
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f


.PHONY: restart
restart: stop


.PHONY: lint
lint:
	@echo 'Checking formatting w/ Ruff...'
	@echo ''
	@uv run ruff format --check .
	@echo ''
	@echo ''
	@echo 'Linting w/ Ruff...'
	@echo ''
	@uv run ruff check .
	@echo ''
	@echo 'Type checking w/ Mypy...'
	@echo ''
	@uv run mypy .
	@echo ''
	@echo ''
	@echo 'Finding dead code w/ Vulture...'
	@echo ''
	@uv run vulture
	@echo ''
	@$(CLEAN_CACHES)


.PHONY: fix
fix:
	@echo "Fixing formatting w/ Ruff..."
	@echo ''
	@uv run ruff check --fix .
	@$(CLEAN_CACHES)


.PHONY: vulture
vulture:
	@echo "Finding dead code with Vulture..."
	@echo ''
	@uv run vulture
	@$(CLEAN_CACHES)


.PHONY: bandit
bandit:
	@echo "Running Bandit security scan..."
	@echo ''
	@uv run bandit -c pyproject.toml -r guard_core -q
	@$(CLEAN_CACHES)


.PHONY: safety
safety:
	@echo "Checking dependencies with Safety..."
	@echo ''
	@uv run safety scan
	@$(CLEAN_CACHES)


.PHONY: pip-audit
pip-audit:
	@echo "Auditing dependencies with pip-audit..."
	@echo ''
	@uv run pip-audit
	@$(CLEAN_CACHES)


.PHONY: radon
radon:
	@echo "Analyzing code complexity with Radon..."
	@echo ''
	@echo "Cyclomatic Complexity:"
	@uv run radon cc guard_core -nc
	@echo ''
	@echo "Maintainability Index:"
	@uv run radon mi guard_core -nc
	@echo ''
	@echo "Raw Metrics:"
	@uv run radon raw guard_core
	@$(CLEAN_CACHES)


.PHONY: xenon
xenon:
	@echo "Checking complexity thresholds with Xenon..."
	@echo ''
	@uv run xenon guard_core --max-absolute B --max-modules A --max-average A
	@$(CLEAN_CACHES)


.PHONY: deptry
deptry:
	@echo "Analyzing dependencies with Deptry..."
	@echo ''
	@uv run deptry .
	@$(CLEAN_CACHES)


.PHONY: semgrep
semgrep:
	@echo "Running Semgrep static analysis..."
	@echo ''
	@uv run semgrep --config=auto guard_core
	@$(CLEAN_CACHES)


.PHONY: security
security: bandit safety pip-audit
	@echo "All security checks completed."


.PHONY: quality
quality: lint vulture radon xenon
	@echo "All code quality checks completed."


.PHONY: analysis
analysis: deptry semgrep
	@echo "All analysis tools completed."


.PHONY: check-all
check-all: lint security quality analysis
	@echo "All checks completed."


.PHONY: test
test:
	@COMPOSE_BAKE=true PYTHON_VERSION=$(DEFAULT_PYTHON) docker compose run --rm --build guard-core pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f


.PHONY: test-all
test-all: test-3.10 test-3.11 test-3.12 test-3.13 test-3.14 test-3.15


.PHONY: test-3.10
test-3.10:
	@docker compose down -v guard-core
	@COMPOSE_BAKE=true PYTHON_VERSION=3.10 docker compose build guard-core
	@PYTHON_VERSION=3.10 docker compose run --rm guard-core pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f


.PHONY: test-3.11
test-3.11:
	@docker compose down -v guard-core
	@COMPOSE_BAKE=true PYTHON_VERSION=3.11 docker compose build guard-core
	@PYTHON_VERSION=3.11 docker compose run --rm guard-core pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f


.PHONY: test-3.12
test-3.12:
	@docker compose down -v guard-core
	@COMPOSE_BAKE=true PYTHON_VERSION=3.12 docker compose build guard-core
	@PYTHON_VERSION=3.12 docker compose run --rm guard-core pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f


.PHONY: test-3.13
test-3.13:
	@docker compose down -v guard-core
	@COMPOSE_BAKE=true PYTHON_VERSION=3.13 docker compose build guard-core
	@PYTHON_VERSION=3.13 docker compose run --rm guard-core pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f


.PHONY: test-3.14
test-3.14:
	@docker compose down -v guard-core
	@COMPOSE_BAKE=true PYTHON_VERSION=3.14 docker compose build guard-core
	@PYTHON_VERSION=3.14 docker compose run --rm guard-core pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

.PHONY: test-3.15
test-3.15:
	@docker compose down -v guard-core
	@COMPOSE_BAKE=true PYTHON_VERSION=3.15 docker compose build guard-core
	@PYTHON_VERSION=3.15 docker compose run --rm guard-core pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f


.PHONY: local-test
local-test:
	@REDIS_URL=redis://localhost:6379 uv run pytest -v --cov=guard_core --cov-report=term-missing
	@$(CLEAN_CACHES)


.PHONY: attack-sim
attack-sim:
	@uv run python -m tests.attack_simulation


.PHONY: integration-test
integration-test:
	@STATUS=0; \
	INTEGRATION_TESTS=1 REDIS_URL=$${REDIS_URL:-redis://localhost:6379} IPINFO_TOKEN=$${IPINFO_TOKEN:-test_token} env $${REDIS_PREFIX:+REDIS_PREFIX="$$REDIS_PREFIX"} uv run pytest tests/integration -m integration -v || STATUS=1; \
	INTEGRATION_TESTS=1 REDIS_URL=$${REDIS_URL:-redis://localhost:6379} IPINFO_TOKEN=$${IPINFO_TOKEN:-test_token} env $${REDIS_PREFIX:+REDIS_PREFIX="$$REDIS_PREFIX"} uv run pytest tests/test_sync/integration -m integration -v || STATUS=1; \
	$(CLEAN_CACHES); \
	exit $$STATUS


.PHONY: live-smoke
live-smoke:
	@mkdir -p tests/live_smoke/stack/wheels && find tests/live_smoke/stack/wheels -name 'guard_core-*.whl' -delete
	@uv build --wheel --out-dir tests/live_smoke/stack/wheels
	@uv run python tests/live_smoke/fetch_example_app.py
	@uv run python tests/live_smoke/patch_example_config.py
	@LIVE_SMOKE=1 uv run pytest tests/live_smoke -m live_smoke -v; \
	STATUS=$$?; \
	(cd tests/live_smoke/stack && docker compose -p guard-core-live-smoke down -v --remove-orphans) >/dev/null 2>&1; \
	exit $$STATUS


.PHONY: serve-docs
serve-docs:
	@UV_PROJECT_ENVIRONMENT=.venv/docs uv run --python 3.14 --extra dev --group docs mkdocs serve
	@$(CLEAN_CACHES)


.PHONY: lint-docs
lint-docs:
	@uv run --group docs pymarkdownlnt scan -r --respect-gitignore .
	@$(CLEAN_CACHES)


.PHONY: fix-docs
fix-docs:
	@uv run --group docs pymarkdownlnt fix -r --respect-gitignore .
	@$(CLEAN_CACHES)


.PHONY: prune
prune:
	@docker system prune -f


.PHONY: clean
clean:
	@$(CLEAN_CACHES)


.PHONY: bump-version
bump-version:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make bump-version VERSION=x.y.z"; exit 1; fi
	@uv run python .github/scripts/bump_version.py $(VERSION)


.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'


.DEFAULT_GOAL := help


.PHONY: show-python-versions
show-python-versions:
	@echo "Supported Python versions: $(PYTHON_VERSIONS)"
	@echo "Default Python version: $(DEFAULT_PYTHON)"
