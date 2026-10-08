---

title: Guard Core - Framework-Agnostic Security Engine for Python
description: The protocol-based security engine that powers framework-specific adapters like fastapi-guard, flaskapi-guard, and djapi-guard
keywords: guard-core, security engine, python, protocol-based, adapter development, middleware engine
---

Guard Core
==========

![Guard Core Logo](assets/guard_core_legend.svg)

[![PyPI version](https://badge.fury.io/py/guard-core.svg?cache=none&icon=si%3Apython&icon_color=%23008cb4)](https://badge.fury.io/py/guard-core)
[![Release](https://github.com/Guard-Core/guard-core/actions/workflows/release.yml/badge.svg)](https://github.com/Guard-Core/guard-core/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/Guard-Core/guard-core/actions/workflows/ci.yml/badge.svg)](https://github.com/Guard-Core/guard-core/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Guard-Core/guard-core/actions/workflows/code-ql.yml/badge.svg)](https://github.com/Guard-Core/guard-core/actions/workflows/code-ql.yml)

`guard-core` is the **framework-agnostic security engine** that provides IP control, rate limiting, penetration detection, security headers, and behavioral analysis through a protocol-based architecture. It is designed to be consumed by **framework-specific adapters** -- not directly by end users.

```mermaid
graph TD
    GC["guard-core"]
    GC --> FG["fastapi-guard"]
    GC --> FlG["flaskapi-guard"]
    GC --> DG["djapi-guard"]
    FG --> FA["FastAPI App"]
    FlG --> FlA["Flask App"]
    DG --> DA["Django App"]
```

Adapter developers implement three protocols -- `GuardRequest`, `GuardResponse`, and `GuardResponseFactory` -- to bridge their framework's native objects into `guard-core`'s security pipeline. Everything else (the 17-check security pipeline, built to just the checks a deployment's configuration can trigger, the detection engine, Redis state management, event telemetry) works out of the box.

___

What it's useful for
--------------------

It catches the HTTP-layer attacks an automated, AI-orchestrated attacker runs at scale:

- **Polymorphic payloads**, variation-based SQLi/XSS that defeats signature WAFs (token-overlap scoring catches them)
- **Reconnaissance**, endpoint enumeration, 404 spam, honeypot probing, banner grabbing
- **Distributed attacks**, when paired with behavioral patterns enabled (per-IP rate limits alone are not enough)
- **Known bad actors**, country/cloud/tor blocking, IP reputation
- **Layer-7 abuse**, auto-ban thresholds, custom rate limits per route, CORS enforcement, security headers

It does **not** cover prompt injection against LLM endpoints, model-output exfiltration, application-logic vulnerabilities (auth bypass, IDOR, business-logic flaws), or network-layer DDoS, those are out-of-scope by design and belong to other layers of your stack.

If you're integrating into FastAPI, jump straight to the [**fastapi-guard Integration Guide**](https://guard-core.github.io/fastapi-guard/latest/tutorial/integration/), it has the decision tree across standalone / SaaS / encrypted-SaaS paths and the common pitfalls.

___

Key Design Properties
---------------------

- **Protocol-based contracts**: `GuardRequest`, `GuardResponse`, and `GuardResponseFactory` are `typing.Protocol` classes with `@runtime_checkable`. Your adapter implements them; guard-core consumes them.
- **A 17-check catalogue in a chain-of-responsibility pipeline**: Each check is an independent `SecurityCheck` subclass that declares its own `applies_to(config, route_configs)` predicate, so `build_default_pipeline` only instantiates the checks a deployment's configuration and registered routes can actually trigger. The `SecurityCheckPipeline` executes the built subset in catalogue order and short-circuits on the first blocking response.
- **Dependency injection via context dataclasses**: Every core module receives its dependencies through a typed context object (`ResponseContext`, `RoutingContext`, `ValidationContext`, `BypassContext`, `BehavioralContext`).
- **Singleton handlers with async initialization**: `ip_ban_manager`, `cloud_handler`, `rate_limit_handler`, `sus_patterns_handler`, and `redis_handler` are module-level singletons initialized through `HandlerInitializer`.
- **Detection engine**: Regex-based and semantic attack pattern detection with configurable thresholds, timeouts, and content length limits.
- **Redis-backed distributed state**: Rate limits, IP bans, cloud IP ranges, and suspicious pattern counts persist across instances when Redis is enabled. Falls back to in-memory storage automatically.
- **Event system**: `SecurityEventBus` dispatches security events and `MetricsCollector` tracks request metrics, both feeding into the optional guard-agent telemetry platform.

___

Install
-------

=== "uv"

    ```bash
    uv add guard-core
    ```

=== "poetry"

    ```bash
    poetry add guard-core
    ```

=== "pip"

    ```bash
    pip install guard-core
    ```

!!! info "Python 3.10+"
    guard-core requires Python 3.10 or higher.

___

Documentation
-------------

### For Adapter Developers

- [Installation and Dev Setup](installation.md) -- how to depend on guard-core and set up a contributor environment
- [Architecture Overview](architecture/overview.md) -- module map, request lifecycle, design principles
- [Protocol Reference](architecture/protocols.md) -- `GuardRequest`, `GuardResponse`, `GuardResponseFactory`, `GuardMiddlewareProtocol`
- [Security Pipeline](architecture/pipeline.md) -- `SecurityCheckPipeline`, the 17-check catalogue and the `applies_to` build-time filter, adding custom checks
- [Event System](architecture/events.md) -- `SecurityEventBus`, `MetricsCollector`, hooking into events
- [Telemetry](architecture/telemetry.md) -- muting events/metrics/check logs, OpenTelemetry, Logfire, adapter wiring
- [Dependency Injection](architecture/dependency-injection.md) -- context objects, `HandlerInitializer`, singleton lifecycle

### API Reference

- [Models](api/models.md)
- [Protocols](api/protocols.md)
- [Handlers](api/handlers.md)
- [DetectionResult](api/detection-result.md)
- [Ban Configuration](api/ban-config.md)
- [Behavior Rules](api/behavior-rules.md)
- [Cloud IP Store](api/cloud-ip-store.md)
- [Decorators](api/decorators.md)
- [Utilities](api/utilities.md)

### Upgrading

- [Migrating from v1.x to v2.0](migration/v1-to-v2.md) -- breaking changes shipped in 2.0.0 and the migration steps
