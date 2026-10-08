# AGENTS.md
Guidance for AI agents (including Claude Code) working in this repository.

## Project Overview

Guard Core is the framework-agnostic engine library that powers the Guard ecosystem. It contains all shared security logic: detection engines, handlers, models, protocols, checks, rate limiting, IP management, cloud provider handling, and Redis integration. Framework-specific libraries (FastAPI Guard, FlaskAPI Guard, DjAPI Guard, TornadoAPI Guard) depend on this package as a PyPI dependency and serve as thin adapters that wire Guard Core into their respective frameworks.

- IP control and rate limiting
- Request logging and monitoring
- Penetration attempt detection
- Security headers management
- Redis-based distributed caching

- **PyPI Package**: `guard-core`
- **Import Name**: `guard_core`
- **Python Support**: 3.10, 3.11, 3.12, 3.13, 3.14
- **Package Manager**: uv (modern Python package manager)
- **Build System**: Docker + Make

## Ecosystem Position

```text
guard-core (this repo)        <- Engine: all security logic lives here
├── fastapi-guard             <- Adapter: ASGI middleware for FastAPI
├── flaskapi-guard            <- Adapter: Flask extension over the sync mirror
├── djapi-guard               <- Adapter: Django middleware adapter
└── tornadoapi-guard          <- Adapter: Tornado handler/middleware adapter
```

Guard Core is the single source of truth for security behavior. Every adapter depends on it via PyPI and contains no security logic of its own. The async tree (`guard_core.*`) is the authored source; adapters whose framework is synchronous (Flask, Django) import the unasync-generated `guard_core.sync.*` mirror, while async frameworks (FastAPI/Starlette, Tornado) use `guard_core.*` directly.

### Protocol Layer (`guard_core/protocols/`)

Guard Core defines protocols (abstract interfaces) for:

- **Request**: Framework-agnostic request representation (headers, path, method, client IP, body)
- **Response**: Framework-agnostic response representation (status code, headers, body)
- **Middleware**: Base middleware protocol that framework adapters implement

Framework adapters implement these protocols by wrapping their native request/response objects.

### How Framework Adapters Use Guard Core

Each framework adapter:

1. Implements guard-core protocols by wrapping native request/response objects
2. Implements a middleware class that delegates to `SecurityCheckPipeline`
3. Re-exports `SecurityConfig` and decorator interfaces from guard-core
4. Contains framework-specific decorator implementations

## Boundary Rules

- **guard-core MUST NOT** import FastAPI, Flask, Django, Tornado, Starlette, Werkzeug, or any web framework
- **guard-core MUST NOT** contain example apps (those belong in adapter repos)
- **guard-core MUST** define protocols/ABCs for any framework-specific behavior
- **Framework adapters MUST NOT** contain security logic (that belongs here)
- **Framework adapters MUST** implement guard-core protocols for their native request/response types

## Quick Start

```bash
# Install dependencies with uv
make install-dev

# Run tests locally
make local-test

# Run linting and formatting
make fix
```

## Development Commands

### Package Management (uv)

- `make install` - Install core dependencies
- `make install-dev` - Install with dev dependencies
- `make lock` - Update lock file
- `make upgrade` - Upgrade lock dependencies and install

### Testing

- `make test` - Run tests in Docker (Python 3.10)
- `make test-all` - Test all Python versions (3.10-3.14)
- `make test-3.11` - Test specific Python version
- `make local-test` - Run tests locally with uv
- `make integration-test` - Run Docker-backed integration tests (opt-in; requires Docker)

### Code Quality

- `make lint` - Run ruff format, ruff check, mypy, and vulture in Docker
- `make fix` - Auto-fix formatting issues with ruff
- `make vulture` - Find dead code with Vulture
- `make radon` - Analyze code complexity (cyclomatic complexity, maintainability index, raw metrics)
- `make xenon` - Enforce complexity thresholds (max-absolute B, max-modules A, max-average A)
- `make deptry` - Analyze dependencies for issues
- `make semgrep` - Static analysis with Semgrep
- `make quality` - Run all code quality checks (lint + vulture + radon + xenon)

### Security

- `make bandit` - Security scan with Bandit
- `make safety` - Check dependencies with Safety
- `make pip-audit` - Audit dependencies with pip-audit
- `make security` - Run all security checks (bandit + safety + pip-audit)

### Combined Checks

- `make analysis` - Run all analysis tools (deptry + semgrep)
- `make check-all` - Run everything (lint + security + quality + analysis)

### Documentation

- `make serve-docs` - Serve MkDocs locally
- `make lint-docs` - Lint markdown files
- `make fix-docs` - Fix markdown issues

### Docker Operations

- `make stop` - Stop all containers
- `make restart` - Restart services
- `make prune` - Clean Docker resources
- `make clean` - Clean Python cache files

Environment variables:

- `PYTHON_VERSION` - Python version (3.10-3.14)
- `REDIS_URL` - Redis connection string
- `REDIS_PREFIX` - Key prefix for Redis
- `IPINFO_TOKEN` - IPInfo API token

Services: `guard-core` (test runner) and `redis` (cache).

### Version Management

- `make bump-version VERSION=x.y.z` - Bump package version

### Sync Mirror

- `make sync` - Regenerate `guard_core/sync/` from `guard_core/` with unasync
- `make check-sync` - Verify the sync mirror is up to date

## Project Structure

```text
guard-core/
├── guard_core/            # Main package (import name, async source)
│   ├── __init__.py
│   ├── models.py          # Pydantic models (SecurityConfig, etc.)
│   ├── utils.py           # Utilities
│   ├── protocols/         # Abstract protocols for framework adapters
│   ├── sync/              # unasync-generated sync mirror; never hand-edit
│   ├── core/              # Modular architecture
│   │   ├── checks/              # Security check implementations
│   │   │   ├── base.py         # SecurityCheck base class
│   │   │   ├── pipeline.py     # SecurityCheckPipeline (Chain of Responsibility)
│   │   │   ├── helpers.py      # Shared check utilities
│   │   │   └── implementations/
│   │   │       ├── route_config.py
│   │   │       ├── emergency_mode.py
│   │   │       ├── https_enforcement.py
│   │   │       ├── request_logging.py
│   │   │       ├── request_size_content.py
│   │   │       ├── required_headers.py
│   │   │       ├── authentication.py
│   │   │       ├── referrer.py
│   │   │       ├── custom_validators.py
│   │   │       ├── time_window.py
│   │   │       ├── cloud_ip_refresh.py
│   │   │       ├── ip_security.py
│   │   │       ├── cloud_provider.py
│   │   │       ├── user_agent.py
│   │   │       ├── rate_limit.py
│   │   │       ├── suspicious_activity.py
│   │   │       └── custom_request.py
│   │   ├── events/              # Event system
│   │   │   ├── middleware_events.py
│   │   │   └── metrics.py
│   │   ├── initialization/      # Handler initialization
│   │   │   └── handler_initializer.py
│   │   ├── responses/           # Response handling
│   │   │   ├── context.py
│   │   │   └── factory.py
│   │   ├── routing/             # Routing & decorator resolution
│   │   │   ├── context.py
│   │   │   └── resolver.py
│   │   ├── validation/          # Request validation
│   │   │   ├── context.py
│   │   │   └── validator.py
│   │   ├── bypass/              # Security bypass handling
│   │   │   ├── context.py
│   │   │   └── handler.py
│   │   └── behavioral/          # Behavioral rule processing
│   │       ├── context.py
│   │       └── processor.py
│   ├── handlers/          # Request handlers
│   ├── detection_engine/  # Attack detection
│   └── scripts/           # Helper scripts
├── guard_core/.agents/skills/guard-core/   # Package skill (SKILL.md + references)
├── tests/                 # Test suite (100% coverage)
│   └── conftest.py
├── vulture_whitelist.py  # Vulture false positive suppressions
├── docs/                  # MkDocs documentation
├── Makefile              # Build automation
├── compose.yml           # Docker Compose config
├── Dockerfile            # Docker image definition
├── pyproject.toml        # Project metadata & config
├── uv.lock              # Locked dependencies
├── setup.py             # Package setup
└── .pre-commit-config.yaml  # Pre-commit hooks
```

### Core Modules (`guard_core/core/`)

1. **Security Checks (`core/checks/`)** - Pattern: Chain of Responsibility. Components: `SecurityCheck` base class, `SecurityCheckPipeline`, 17 concrete implementations. Key files: `base.py`, `pipeline.py`, `helpers.py`, `implementations/*.py`.
2. **Event System (`core/events/`)** - Components: `SecurityEventBus`, `MetricsCollector`. Key methods: `send_middleware_event()`, `send_https_violation_event()`, `collect_request_metrics()`.
3. **Handler Initialization (`core/initialization/`)** - Component: `HandlerInitializer`. Key methods: `initialize_redis_handlers()`, `initialize_agent_integrations()`.
4. **Response Handling (`core/responses/`)** - Components: `ErrorResponseFactory`, `ResponseContext`. Key methods: `create_error_response()`, `create_https_redirect()`, `process_response()`.
5. **Routing Resolution (`core/routing/`)** - Components: `RouteConfigResolver`, `RoutingContext`. Key methods: `get_route_config()`, `should_bypass_check()`, `get_cloud_providers_to_check()`.
6. **Request Validation (`core/validation/`)** - Components: `RequestValidator`, `ValidationContext`. Key methods: `is_request_https()`, `is_trusted_proxy()`, `check_time_window()`, `is_path_excluded()`.
7. **Bypass Handling (`core/bypass/`)** - Components: `BypassHandler`, `BypassContext`. Key methods: `handle_passthrough()`, `handle_security_bypass()`.
8. **Behavioral Processing (`core/behavioral/`)** - Components: `BehavioralProcessor`, `BehavioralContext`. Key methods: `process_usage_rules()`, `process_return_rules()`, `get_endpoint_id()`.

All core modules use **Context objects** for clean dependency injection (`ResponseContext`, `RoutingContext`, `ValidationContext`, etc.), which prevents tight coupling, improves testability, and makes dependencies explicit.

### Sync Mirror (`guard_core/sync/`)

`guard_core.sync.*` is generated from `guard_core.*` via unasync (`make sync`). Never hand-edit files under `guard_core/sync/`; edit the async source and regenerate. Synchronous adapters (Flask, Django) import the sync mirror.

### Configuration Files

- **pyproject.toml** - Project metadata and dependencies; tool configurations for ruff, mypy, pytest, vulture, bandit, radon, xenon, deptry, pymarkdown; Python 3.10+ requirement
- **uv.lock** - Locked dependency versions for reproducible builds, updated with `make lock`
- **compose.yml / Dockerfile** - Multi-version Python support (3.10-3.14), Redis service for testing, volume mounts for development
- **.pre-commit-config.yaml** - ruff format, ruff check, mypy, vulture, bandit, safety, radon cc, xenon, deptry

## Technology Stack

### Core Dependencies

- **Pydantic** - Data validation
- **redis** - Distributed caching
- **httpx** - Async HTTP client
- **cachetools** - Local caching utilities
- **maxminddb** - GeoIP database reader
- **ipaddress** - IP manipulation
- **typing-extensions** - Backported type hints

### NOT Dependencies (framework-specific, belong in adapters)

- **FastAPI** / **Starlette** / **uvicorn** - belongs in fastapi-guard
- **Flask** / **Werkzeug** - belongs in flaskapi-guard
- **Django** - belongs in djapi-guard
- **Tornado** - belongs in tornadoapi-guard

### Development Tools

- **uv** - Fast Python package manager
- **pytest** - Testing framework
- **pytest-asyncio** - Async test support
- **pytest-cov** - Coverage reporting
- **pytest-mock** - Mock fixtures
- **ruff** - Fast Python linter/formatter
- **mypy** - Static type checker
- **vulture** - Dead code detection
- **bandit** - Security vulnerability scanner
- **safety** - Dependency vulnerability checking
- **pip-audit** - Dependency auditing
- **radon** - Code complexity analysis
- **xenon** - Complexity threshold enforcement
- **deptry** - Dependency analysis
- **semgrep** - Static analysis
- **pre-commit** - Git hooks
- **mkdocs** - Documentation generator
- **mkdocs-material** - MkDocs theme
- **pymarkdownlnt** - Markdown linter

## Testing & Conformance

### Running Tests

```bash
# Local testing with coverage
make local-test

# Docker testing (default Python 3.10)
make test

# Test all Python versions
make test-all

# Specific Python version
make test-3.12
```

### Test Configuration (pyproject.toml)

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
python_files = ["test_*.py"]
asyncio_default_fixture_loop_scope = "function"
addopts = "--cov=guard_core --cov-report=term-missing"
```

### Running Specific Tests

```bash
# Run specific test file
REDIS_URL=redis://localhost:6379 uv run pytest tests/test_checks.py -v

# Run with pattern matching
REDIS_URL=redis://localhost:6379 uv run pytest -k "rate_limit" -v

# Force gc.collect() after every test to localise a leaked-resource ResourceWarning to the test that caused it (opt-in, adds real wall time, so it stays off by default)
GUARD_TESTS_GC_PER_TEST=1 REDIS_URL=redis://localhost:6379 uv run pytest -v
```

### Testing Modular Components

Each module is independently testable:

```python
from guard_core.core.checks.implementations import IpSecurityCheck


async def test_ip_security():
    middleware = create_test_middleware()
    check = IpSecurityCheck(middleware)
    response = await check.check(test_request)
    assert response is None
```

### No Example Apps

Guard Core has no example apps. Examples live in the framework-specific adapter repos.

### Quality Targets

- All modules: Rank A maintainability (MI 56-82)
- Average cyclomatic complexity: < 3
- Test coverage: 100%
- Zero dead code (vulture)
- Zero security findings (bandit)
- Zero dependency vulnerabilities (safety + pip-audit)

## Code Quality Standards

### Ruff Configuration

- Target Python 3.10+
- Selected rules: E, F, UP, B, I
- Auto-fixable issues

### MyPy Configuration

- Strict type checking enabled
- No implicit Optional
- Warn on unused configs
- Check untyped definitions
- Disallow untyped decorators
- Strict optional checking
- Warn on unreachable code

### Vulture Configuration

- Paths: `guard_core`, `tests`, `vulture_whitelist.py`
- Excludes: `conftest.py`, `.venv`
- Min confidence: 100
- Ignores test/fixture/validator decorators and names
- Sort by size

### Bandit Configuration

- Skips: B101 (assert), B601 (shell)
- Excludes: tests, .venv
- Severity: medium

### Radon Configuration

- CC min: C
- MI min: A
- Show closures, total average

### Xenon Configuration

- Max absolute: B
- Max modules: A
- Max average: A

### Pre-commit Workflow

1. Automatic formatting with ruff
2. Linting checks with ruff
3. Type checking with mypy
4. Dead code detection with vulture
5. Security scanning with bandit
6. Dependency vulnerability checking with safety
7. Cyclomatic complexity with radon
8. Complexity thresholds with xenon
9. Dependency analysis with deptry
10. All run via `uv run` commands

## Development Workflow

### Initial Setup

```bash
# Clone repository
git clone <repo>
cd guard-core

# Install with dev dependencies
make install-dev

# Set up pre-commit hooks
uv run pre-commit install
```

### Daily Development

```bash
# Make changes and test locally
make local-test

# Fix code issues
make fix

# Run full test suite
make test-all
```

### Before Committing

```bash
# Run all quality checks
make lint

# Fix any issues
make fix

# Run tests
make test

# Commit (pre-commit hooks will run)
git commit
```

### Debugging Tips

```bash
# Clean all caches and containers
make clean
make prune

# Upgrade dependencies
make upgrade
```

### Adding New Security Checks

1. **Create implementation** in `guard_core/core/checks/implementations/`:

```python
from guard_core.core.checks.base import SecurityCheck


class MyCustomCheck(SecurityCheck):
    check_name = "my_custom_check"

    async def check(self, request):
        if condition_fails:
            return await self.create_error_response(403, "Check failed")
        return None
```

2. Register in pipeline

3. **Export** in `guard_core/core/checks/__init__.py`

All framework adapters automatically pick up the new check. Check execution order in the pipeline is: route_config, emergency_mode, https_enforcement, request_logging, request_size_content, required_headers, authentication, referrer, custom_validators, time_window, cloud_ip_refresh, ip_security, cloud_provider, user_agent, rate_limit, suspicious_activity, custom_request.

## Best Practices

1. **Always use uv** for package management
2. **Run tests** before committing
3. **Use Make commands** for consistency
4. **Test multiple Python versions** for compatibility
5. **Keep dependencies updated** with `make upgrade`
6. **Use type hints** and run mypy
7. **Follow ruff** formatting standards
8. **Document changes** in appropriate docs/

### Security Considerations

- This is a security library - all code must be defensive
- Validate all inputs with Pydantic
- Use Redis for distributed rate limiting
- Implement proper error handling
- Log security events appropriately
- Never expose sensitive data in logs

## Related Projects

- **fastapi-guard** - ASGI middleware adapter for FastAPI: <https://github.com/Guard-Core/fastapi-guard>
- **flaskapi-guard** - Flask extension adapter (sync mirror): <https://github.com/Guard-Core/flaskapi-guard>
- **djapi-guard** - Django middleware adapter (sync mirror): <https://github.com/Guard-Core/djapi-guard>
- **tornadoapi-guard** - Tornado handler/middleware adapter: <https://github.com/Guard-Core/tornadoapi-guard>
- **guard-agent** - Telemetry and monitoring agent for the adapters: <https://github.com/Guard-Core/guard-agent>
- **guard-core-mcp** - MCP server for config validation and docs search: <https://github.com/Guard-Core/guard-core-mcp>
- **guard-core-app** - SaaS platform (API, dashboard, playground): <https://github.com/Guard-Core/guard-core-app>
