---

title: Installation - Guard Core
description: How to add guard-core as a dependency in your adapter library and set up a contributor development environment
keywords: guard-core, installation, adapter dependency, development setup, python security engine
---

Installation
============

guard-core is consumed as a **library dependency** by framework-specific adapters. This page covers two scenarios: depending on guard-core from your adapter's package, and setting up a local development environment to contribute to guard-core itself.

___

Add guard-core as an Adapter Dependency
----------------------------------------

In your adapter's `pyproject.toml`, add guard-core as a core dependency:

=== "pyproject.toml (PEP 621)"

    ```toml
    [project]
    name = "fastapi-guard"
    requires-python = ">=3.10"
    dependencies = [
        "guard-core",
    ]
    ```

=== "pyproject.toml (Poetry)"

    ```toml
    [tool.poetry.dependencies]
    python = "^3.10"
    guard-core = "*"
    ```

=== "setup.cfg"

    ```ini
    [options]
    install_requires =
        guard-core
    python_requires = >=3.10
    ```

After adding the dependency, your adapter can import the public API:

```python
from guard_core import (
    SecurityConfig,
    GuardRequest,
    GuardResponse,
    GuardResponseFactory,
)
from guard_core.core.checks import SecurityCheckPipeline, SecurityCheck
from guard_core.core.events import SecurityEventBus, MetricsCollector
from guard_core.core.initialization import HandlerInitializer
from guard_core.core.responses import ErrorResponseFactory, ResponseContext
from guard_core.core.routing import RouteConfigResolver, RoutingContext
from guard_core.core.validation import RequestValidator, ValidationContext
from guard_core.core.bypass import BypassHandler, BypassContext
from guard_core.core.behavioral import BehavioralProcessor, BehavioralContext
```

### Optional Dependency Extras

guard-core ships three packaging extras that group its heavier third-party dependencies by feature:

| Extra | Installs | Gated by |
|---|---|---|
| `redis` | `redis` | `SecurityConfig(enable_redis=True)` |
| `cloud` | `aiohttp`, `requests` | `SecurityConfig(block_cloud_providers=...)` (or `enable_dynamic_rules=True`, which can turn cloud blocking on at runtime) |
| `geo` | `maxminddb` | Country rules (`blocked_countries`/`whitelist_countries`) with no custom `geo_ip_handler` supplied, since guard-core then constructs its own `IPInfoManager` |

=== "uv"

    ```bash
    uv add "guard-core[redis,cloud,geo]"
    ```

=== "poetry"

    ```bash
    poetry add "guard-core[redis,cloud,geo]"
    ```

=== "pip"

    ```bash
    pip install "guard-core[redis,cloud,geo]"
    ```

The extras are additive for the 3.x line: `aiohttp`, `redis`, `requests`, and `maxminddb` all stay in guard-core's base `dependencies` too, so an existing install that never opts into an extra keeps working exactly as before. They become the exclusive way to pull in those packages only at 4.0.

Configuring a feature whose extra is not installed raises a `SecurityConfig` validation error naming the missing extra's install command (for example `pip install guard-core[geo]`) at config-construction time, instead of letting the feature fail later mid-request with a raw `ImportError`.

`guard-agent` (`SecurityConfig(enable_agent=True)`) and `guard-core[otel]`/`guard-core[logfire]` are separate, unrelated to the three extras above; see [Telemetry](architecture/telemetry.md) for those.

### Import Cost

`import guard_core` no longer pulls `aiohttp`, `maxminddb`, `redis`, `guard_agent`, or `cryptography` into `sys.modules`; every one of those loads lazily on first use of the feature that needs it. A cold `import guard_core` costs roughly 2ms (measured via `python -X importtime`, Python 3.10.19).

___

Contributor Development Setup
-----------------------------

To work on guard-core itself:

### Prerequisites

- Python 3.10+ (3.10, 3.11, 3.12, 3.13, 3.14 are all tested)
- [uv](https://docs.astral.sh/uv/) (modern Python package manager)
- Docker and Docker Compose (for containerized tests)
- Redis (for local integration tests)

### Clone and Install

```bash
git clone https://github.com/Guard-Core/guard-core.git
cd guard-core
make install-dev
```

This runs `uv sync --extra dev`, which installs all development dependencies including pytest, ruff, mypy, and pre-commit.

### Run Tests

```bash
make local-test
```

This executes `uv run pytest` with coverage reporting. A Redis instance must be running locally at `redis://localhost:6379` (or set the `REDIS_URL` environment variable).

To test across all supported Python versions using Docker:

```bash
make test-all
```

To test a specific Python version:

```bash
make test-3.12
```

### Code Quality

```bash
make fix
```

Runs `ruff format` and `ruff check --fix` across the codebase.

```bash
make lint
```

Runs ruff and mypy in Docker.

### Pre-commit Hooks

```bash
uv run pre-commit install
```

This installs hooks that run `ruff format`, `ruff check`, and `mypy` before every commit.

___

Project Layout
--------------

```text
guard-core/
├── guard_core/                 # Main package
│   ├── __init__.py            # Public API exports
│   ├── models.py              # SecurityConfig, DynamicRules
│   ├── utils.py               # Shared utilities
│   ├── protocols/             # Protocol definitions (the adapter contract)
│   │   ├── request_protocol.py
│   │   ├── response_protocol.py
│   │   ├── middleware_protocol.py
│   │   ├── geo_ip_protocol.py
│   │   ├── redis_protocol.py
│   │   ├── cloud_ip_store_protocol.py
│   │   └── agent_protocol.py
│   ├── core/                  # Modular engine internals
│   │   ├── checks/            # SecurityCheck base + 17 implementations + pipeline
│   │   ├── events/            # SecurityEventBus + MetricsCollector
│   │   ├── initialization/    # HandlerInitializer
│   │   ├── responses/         # ErrorResponseFactory + ResponseContext
│   │   ├── routing/           # RouteConfigResolver + RoutingContext
│   │   ├── validation/        # RequestValidator + ValidationContext
│   │   ├── bypass/            # BypassHandler + BypassContext
│   │   └── behavioral/        # BehavioralProcessor + BehavioralContext
│   ├── handlers/              # Singleton handlers (Redis, IP ban, rate limit, etc.)
│   ├── detection_engine/      # Attack pattern detection
│   └── decorators/            # Route-level security decorators
├── tests/                     # Test suite (100% coverage)
├── Makefile                   # Build automation
├── pyproject.toml             # Project metadata and tool config
└── uv.lock                   # Locked dependencies
```
