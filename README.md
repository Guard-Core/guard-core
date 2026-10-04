<p align="center">
    <a href="https://rennf93.github.io/guard-core/latest/">
        <img src="https://rennf93.github.io/guard-core/latest/assets/guard_core_legend.svg" alt="Guard Core">
    </a>
</p>

___

<p align="center">
    <strong>guard-core is the framework-agnostic security engine that powers the Guard ecosystem. It provides IP control, rate limiting, signature-based attack-pattern detection, security headers, and threshold-based behavior tracking through a protocol-based architecture. Framework-specific adapters (fastapi-guard, flaskapi-guard, djapi-guard) consume this library.</strong>
</p>

<p align="center">
    <a href="https://badge.fury.io/py/guard-core">
        <img src="https://badge.fury.io/py/guard-core.svg?cache=none&icon=si%3Apython&icon_color=%23008cb4" alt="PyPiVersion">
    </a>
    <a href="https://github.com/rennf93/guard-core/actions/workflows/release.yml">
        <img src="https://github.com/rennf93/guard-core/actions/workflows/release.yml/badge.svg" alt="Release">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
    <a href="https://github.com/rennf93/guard-core/actions/workflows/ci.yml">
        <img src="https://github.com/rennf93/guard-core/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/rennf93/guard-core/actions/workflows/code-ql.yml">
        <img src="https://github.com/rennf93/guard-core/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL">
    </a>
</p>

<p align="center">
    <a href="https://github.com/rennf93/guard-core/actions/workflows/pages/pages-build-deployment">
        <img src="https://github.com/rennf93/guard-core/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages" alt="PagesBuildDeployment">
    </a>
    <a href="https://github.com/rennf93/guard-core/actions/workflows/docs.yml">
        <img src="https://github.com/rennf93/guard-core/actions/workflows/docs.yml/badge.svg" alt="DocsUpdate">
    </a>
    <img src="https://img.shields.io/github/last-commit/rennf93/guard-core?style=flat&amp;logo=git&amp;logoColor=white&amp;color=0080ff" alt="last-commit">
</p>

<p align="center">
    <img src="https://img.shields.io/badge/Python-3776AB.svg?style=flat&amp;logo=Python&amp;logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/Redis-FF4438.svg?style=flat&amp;logo=Redis&amp;logoColor=white" alt="Redis">
    <a href="https://pepy.tech/project/guard-core">
        <img src="https://pepy.tech/badge/guard-core" alt="Downloads">
    </a>
</p>

<p align="center">
    <a href="https://guard-core.com">Website</a> &middot;
    <a href="https://rennf93.github.io/guard-core/latest/">Docs</a> &middot;
    <a href="https://playground.guard-core.com">Playground</a> &middot;
    <a href="https://app.guard-core.com">Dashboard</a> &middot;
    <a href="https://discord.gg/ZW7ZJbjMkK">Discord</a>
</p>

___

Documentation
=============

📚 **[Documentation](https://rennf93.github.io/guard-core)** - Full technical documentation for adapter developers.

🤖 **[Monitoring Agent Integration](https://github.com/rennf93/guard-agent)** - Monitor your Guard instance with a monitoring agent.

___

Ecosystem
---------

Guard Core is the Python engine. Framework adapters are thin wrappers that translate native request/response types into Guard Core's protocols. The telemetry agent ships security events and metrics to the monitoring backend. Parallel implementations exist for TypeScript (on npm) and Rust (on crates.io).

### Python

| Package | Role | PyPI |
|---|---|---|
| [guard-core](https://github.com/rennf93/guard-core) | Framework-agnostic security engine (this package) | [![PyPI](https://img.shields.io/pypi/v/guard-core)](https://pypi.org/project/guard-core/) |
| [guard-agent](https://github.com/rennf93/guard-agent) | Telemetry agent | [![PyPI](https://img.shields.io/pypi/v/guard-agent)](https://pypi.org/project/guard-agent/) |
| [fastapi-guard](https://github.com/rennf93/fastapi-guard) | FastAPI / Starlette adapter | [![PyPI](https://img.shields.io/pypi/v/fastapi-guard)](https://pypi.org/project/fastapi-guard/) |
| [flaskapi-guard](https://github.com/rennf93/flaskapi-guard) | Flask adapter | [![PyPI](https://img.shields.io/pypi/v/flaskapi-guard)](https://pypi.org/project/flaskapi-guard/) |
| [djapi-guard](https://github.com/rennf93/djapi-guard) | Django adapter | [![PyPI](https://img.shields.io/pypi/v/djapi-guard)](https://pypi.org/project/djapi-guard/) |
| [tornadoapi-guard](https://github.com/rennf93/tornadoapi-guard) | Tornado adapter | [![PyPI](https://img.shields.io/pypi/v/tornadoapi-guard)](https://pypi.org/project/tornadoapi-guard/) |

### TypeScript / JavaScript

Published under the [`@guardcore`](https://www.npmjs.com/org/guardcore) npm scope. Source in the [guard-core-ts](https://github.com/rennf93/guard-core-ts) monorepo. **Production-ready.**

| Package | Role | npm |
|---|---|---|
| [@guardcore/core](https://github.com/rennf93/guard-core-ts/tree/master/packages/core) | Core engine | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fcore)](https://www.npmjs.com/package/@guardcore/core) |
| [@guardcore/express](https://github.com/rennf93/guard-core-ts/tree/master/packages/express) | Express adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fexpress)](https://www.npmjs.com/package/@guardcore/express) |
| [@guardcore/nestjs](https://github.com/rennf93/guard-core-ts/tree/master/packages/nestjs) | NestJS adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fnestjs)](https://www.npmjs.com/package/@guardcore/nestjs) |
| [@guardcore/fastify](https://github.com/rennf93/guard-core-ts/tree/master/packages/fastify) | Fastify adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Ffastify)](https://www.npmjs.com/package/@guardcore/fastify) |
| [@guardcore/hono](https://github.com/rennf93/guard-core-ts/tree/master/packages/hono) | Hono adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fhono)](https://www.npmjs.com/package/@guardcore/hono) |

### Rust

Published on crates.io. **🚧 Placeholder crates, implementation in progress.**

| Package | Role | crates.io |
|---|---|---|
| [guard-core](https://github.com/rennf93/guard-core-rs) | Core engine | [![crates.io](https://img.shields.io/crates/v/guard-core)](https://crates.io/crates/guard-core) |
| [actix-guard-rs](https://github.com/rennf93/actix-guard-rs) | Actix adapter | [![crates.io](https://img.shields.io/crates/v/actix-guard-rs)](https://crates.io/crates/actix-guard-rs) |
| [axum-guard-rs](https://github.com/rennf93/axum-guard-rs) | Axum adapter | [![crates.io](https://img.shields.io/crates/v/axum-guard-rs)](https://crates.io/crates/axum-guard-rs) |
| [rocket-guard-rs](https://github.com/rennf93/rocket-guard-rs) | Rocket adapter | [![crates.io](https://img.shields.io/crates/v/rocket-guard-rs)](https://crates.io/crates/rocket-guard-rs) |
| [tower-guard-rs](https://github.com/rennf93/tower-guard-rs) | Tower adapter | [![crates.io](https://img.shields.io/crates/v/tower-guard-rs)](https://crates.io/crates/tower-guard-rs) |

### AI Coding Agents

| Package | Role | PyPI |
|---|---|---|
| [guard-core-mcp](https://github.com/rennf93/guard-core-mcp) | MCP server, config validation, docs search, detection sandbox | [![PyPI](https://img.shields.io/pypi/v/guard-core-mcp)](https://pypi.org/project/guard-core-mcp/) |

An MCP server that answers questions about Guard Core from the version **installed in your project**, rather than from a model's memory of it. It validates a config against the real `SecurityConfig` model, catching silently-ignored typos like `redis_failopen`, looks up any field's type, default and description, searches the bundled docs, and runs a payload through the real detection engine to show whether it would be blocked and by which pattern.

```bash
uv add --dev guard-core-mcp
claude mcp add guard-core -- uv run guard-core-mcp
```

Install it into the same environment as Guard Core, it introspects what is actually installed there, so an isolated run (`uvx`) has nothing to read.

Adapter developers implement three protocols (`GuardRequest`, `GuardResponse`, and `GuardResponseFactory`) to bridge their framework into the security pipeline. Everything else (the 17-check catalogue, detection engine, Redis state, event telemetry) works out of the box.

___

Features
--------

- **IP Whitelisting and Blacklisting**: Control access based on IP addresses and CIDR ranges.
- **User Agent Filtering**: Block requests from specific user agents.
- **Rate Limiting**: Sliding window algorithm with in-memory and Redis-backed storage.
- **Automatic IP Banning**: Threshold-based banning with configurable duration.
- **Penetration Attempt Detection**: SQL injection, XSS, command injection, path traversal detection with semantic analysis.
- **HTTP Security Headers**: CSP, HSTS, X-Frame-Options, and OWASP best practices.
- **Cloud Provider IP Blocking**: Block requests from AWS, GCP, Azure IP ranges.
- **IP Geolocation**: Country-based access control via GeoIP databases.
- **Threshold-Based Behavior Tracking**: Per-IP request counting, response-pattern matching, suspicious-frequency triggers (deterministic threshold matching, not learning-based).
- **Security Decorators**: Route-level security with composable decorator mixins.
- **Detection Engine**: Multi-layered threat detection with regex, semantic analysis, and performance monitoring.
- **Distributed State Management**: Redis integration for shared state across instances.
- **Protocol-Based Architecture**: Framework-agnostic via `GuardRequest`/`GuardResponse` protocols.

___

How Detection Works
-------------------

1. Request inputs (query, headers, body) are decoded through up to 16 iterations covering URL (including percent-U escapes and overlong-UTF-8 percent runs), HTML entities, base64, hex, Unicode escapes, and LDAP hex escapes, then a final SQL-comment strip.
2. Decoded content is matched against 157 regex patterns across 19 attack categories, with patterns context-filtered to relevant input zones.
3. Matched payloads receive a multi-metric semantic score combining keyword overlap, Shannon entropy, encoding-layer count, and obfuscation indicators.
4. ReDoS protection rejects any custom pattern whose validation probe runs longer than 50ms, and caps every custom pattern's live match at `detection_compiler_timeout` (default 2.0s, configurable 0.1-10.0s). Built-in patterns match directly with no per-match timeout.

The engine is signature-based with multi-metric semantic scoring on top. It is not machine-learning-based and does not learn from traffic.

___

Installation
------------

```bash
pip install guard-core
```

___

For Adapter Developers
----------------------

If you're building a framework adapter, add guard-core as a dependency:

```toml
[project]
dependencies = [
    "guard-core",
]
```

Then implement the three protocols:

```python
from guard_core.protocols import GuardRequest, GuardResponse, GuardResponseFactory


class MyFrameworkRequest:
    """Wraps your framework's request into GuardRequest protocol."""

    def __init__(self, native_request):
        self._request = native_request

    @property
    def url_path(self) -> str:
        return self._request.path

    @property
    def method(self) -> str:
        return self._request.method

    @property
    def client_host(self) -> str | None:
        return self._request.remote_addr

    @property
    def headers(self):
        return dict(self._request.headers)

    # ... implement remaining protocol properties
```

See the [Building Adapters Guide](https://rennf93.github.io/guard-core/latest/adapters/getting-started/) for the complete walkthrough.

___

Security Pipeline
-----------------

Guard Core ships a catalogue of 17 security checks, run in this fixed order:

1. Route configuration extraction
2. Emergency mode
3. HTTPS enforcement
4. Request logging
5. Size/content validation
6. Required headers
7. Authentication
8. Referrer validation
9. Custom validators
10. Time windows
11. Cloud IP refresh
12. IP security (whitelist/blacklist)
13. Cloud provider blocking
14. User agent filtering
15. Rate limiting
16. Suspicious activity detection
17. Custom request checks

A deployment's actual pipeline is usually a subset: each check declares an `applies_to(config, route_configs)` classmethod, and only checks whose effective configuration can trigger them are built. `IpSecurityCheck` is never eliminated. A default `SecurityConfig()` with no route decorators registered builds just `route_config`, `ip_security`, `rate_limit`, and `suspicious_activity`. See the [Pipeline Architecture](https://rennf93.github.io/guard-core/latest/architecture/pipeline/) for the elimination rules.

Each check returns `None` (pass) or a `GuardResponse` (block). The pipeline short-circuits on the first blocking response.

___

SecurityConfig
--------------

All behavior is controlled through `SecurityConfig`:

```python
from guard_core.models import SecurityConfig

config = SecurityConfig(
    whitelist=["192.168.1.0/24"],
    blacklist=["10.0.0.1"],
    blocked_user_agents=["curl", "wget"],
    auto_ban_threshold=5,
    auto_ban_duration=86400,
    rate_limit=100,
    rate_limit_window=60,
    enforce_https=True,
    block_cloud_providers={"AWS", "GCP", "Azure"},
    enable_redis=True,
    redis_url="redis://localhost:6379",
)
```

See the [SecurityConfig Reference](https://rennf93.github.io/guard-core/latest/configuration/security-config/) for all fields.

___

Migration: fail_secure default flipped
--------------------------------------

`SecurityConfig.fail_secure` now defaults to `True`. When a security check raises an unexpected exception, the request is blocked with HTTP 500 instead of falling through.

**Why**: the old fail-open default silently masked check bugs. The new default surfaces them so they can be fixed instead of leaking past the security layer.

**Migration**: to restore the previous fail-open behavior, opt in explicitly:

```python
config = SecurityConfig(fail_secure=False)
```

Recommended path: keep the new default and fix any check exceptions that surface. The old default could mask genuine bugs.

___

Detection Engine
----------------

Multi-layered threat detection:

- **PatternCompiler**: ReDoS-safe regex compilation with LRU caching and timeout protection.
- **ContentPreprocessor**: Unicode normalization, encoding detection, attack-region-aware truncation.
- **SemanticAnalyzer**: Attack probability scoring, entropy analysis, obfuscation detection.
- **PerformanceMonitor**: Slow-pattern detection via execution-time statistics (mean/stddev thresholds), not anomaly learning.

See the [Detection Engine Internals](https://rennf93.github.io/guard-core/latest/internals/detection-engine/) for details.

___

Redis Integration
-----------------

Distributed state management across multiple instances:

```python
config = SecurityConfig(
    enable_redis=True,
    redis_url="redis://prod-redis:6379/1",
    redis_prefix="myapp:security:",
)
```

Provides atomic rate limiting, distributed IP ban tracking, cloud IP range caching, and pattern storage.

___

Development
-----------

```bash
# Clone and install
git clone https://github.com/rennf93/guard-core.git
cd guard-core
make install-dev

# Run tests (100% coverage)
make local-test

# Run all quality checks
make check-all

# Serve documentation
make serve-docs
```

___

Contributing
------------

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

___

License
-------

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

___

Author
------

Renzo Franceschini - [rennf93@users.noreply.github.com](mailto:rennf93@users.noreply.github.com)

___

Acknowledgements
----------------

- [Pydantic](https://docs.pydantic.dev/)
- [Redis](https://redis.io/)
- [aiohttp](https://docs.aiohttp.org/)
- [cachetools](https://cachetools.readthedocs.io/)
- [MaxMind DB](https://maxmind.github.io/MaxMind-DB/)
