"""Reference harness for the misconfiguration suites of the conformance corpus.

Drives the REAL reporting code of guard_core (the SecurityConfig construction
validator, the dynamic-rule validator, the decorators and the startup and request
time reporters) and records the stable problem kinds it reports. The message text
is never recorded: a port words its own English, the kind and the subject are the
contract.

Every case runs twice. The first run keeps the engine starting
(``fail_on_misconfiguration=False``) and records every problem the engine reports
(``reported``). The second run asks the engine to refuse
(``fail_on_misconfiguration=True``) and records what the one raise carries
(``fatal``). A case never encodes which problem came first.

Case input, by suite file (a ``[kind, subject]`` pair is ``["<kind>", "<subject>"]``,
the subject is ``null`` when the kind has none):

misconfiguration_config
    ``config``: the stated SecurityConfig fields, snake_case, JSON safe. The runner
    states ``fail_on_misconfiguration`` itself, unless ``flag_stated`` is false,
    which leaves the field unset (the case then holds no error problem). ``geo``:
    optional, ``"stub"`` gives the config a GeoIP handler, which the country fields
    need.

misconfiguration_dynamic_rules
    ``dynamic_rules``: the DynamicRulesProtocol fields the validator reads. A field
    the case leaves out is empty or null. Every problem rejects the whole rule set
    (``fatal`` is then every problem), whatever the flag says.

misconfiguration_decorators
    ``config`` as above, ``geo``: null or ``"stub"`` (a configured GeoIP handler),
    ``decorators``: a list of ``{"name": ..., "args": {...}}`` applied one by one to
    a fresh function with the Python keyword names. ``reported`` is the union over
    the decorators, ``fatal`` the union of what each decorator's raise carries.

misconfiguration_runtime
    ``seam``: which reporter the case drives, plus that seam's fields (see
    ``SEAMS``). Tier 2: a port wires the same stubs around its own reporter.
"""

from __future__ import annotations

import contextlib
import logging
import warnings
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import replace
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from typing import cast

from fixture_types import JsonObject, JsonValue
from pydantic import ValidationError
from typing_extensions import get_protocol_members

from guard_core import _staged_defaults
from guard_core._misconfiguration import report_misconfigurations
from guard_core._misconfiguration_kinds import (
    KINDS,
    Problem,
)
from guard_core._security_headers_override import CorsParams
from guard_core._utils import body_reader, ip_extraction
from guard_core._utils.app_managers import (
    _PrefixedRedisConfig,
    _warn_split_connection,
)
from guard_core._utils.route_gate import detection_exclusion_path_param_problems
from guard_core.core.behavioral import _throttle
from guard_core.core.checks.endpoint_limit_keys import (
    EndpointLimitKeyMap,
    RouteResolver,
)
from guard_core.core.checks.route_prefixes import (
    warn_unmatched_endpoint_keys,
    warn_unmatched_exclude_paths,
)
from guard_core.core.initialization._ban_threshold_report import (
    _BanThresholdContext,
    report_unreachable_ban_thresholds,
)
from guard_core.core.initialization._country_decorator_report import (
    report_country_decorators_without_geoip,
)
from guard_core.core.initialization._handler_initializer_steps import (
    _HandlerInitializerStepsMixin,
)
from guard_core.core.initialization._nat64 import apply_nat64_prefixes
from guard_core.core.initialization._redis_handler_members import (
    report_incomplete_redis_handler,
)
from guard_core.core.routing.resolver import RouteConfigResolver
from guard_core.decorators import SecurityDecorator
from guard_core.decorators.base import BaseSecurityDecorator
from guard_core.exceptions import MisconfigurationError
from guard_core.handlers._dynamic_rule_purge import DynamicRulePurgeMixin
from guard_core.handlers._dynamic_rule_validation import (
    MalformedDynamicRules,
    find_malformed_values,
)
from guard_core.handlers._ipban_prefix_contract import enforce_prefix_length_contract
from guard_core.handlers._ipban_sharing import IpBanSharedAppsMixin
from guard_core.handlers._security_headers_config import SecurityHeadersConfigMixin
from guard_core.handlers._security_headers_cors import SecurityHeadersCorsMixin
from guard_core.handlers._security_headers_override_state import (
    SecurityHeadersOverrideMixin,
)
from guard_core.handlers.behavior_handler import BehaviorRule
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.models import SecurityConfig
from guard_core.protocols.agent_protocol import DynamicRulesProtocol
from guard_core.protocols.geo_ip_protocol import GeoIPHandler
from guard_core.protocols.redis_protocol import RedisHandlerProtocol
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.route_identity import RouteIdentity

Pair = tuple[str, str | None]
FatalSink = list[Pair]
# A driver returns the pairs it saw without a log record or a warning (none, for
# every driver but the dynamic-rule one) and fills the fatal sink when it raises.
Driver = Callable[[bool, FatalSink], Awaitable[list[Pair]]]

SUITE_FILES = {
    "misconfiguration_config": "config",
    "misconfiguration_dynamic_rules": "dynamic_rules",
    "misconfiguration_decorators": "decorators",
    "misconfiguration_runtime": "runtime",
}
SEAMS = (
    "ban_thresholds",
    "nat64",
    "redis_handler",
    "country_decorators",
    "ipv6_prefix_length",
    "endpoint_key_routes",
    "exclude_paths_routes",
    "declared_path_params",
    "lazy_init_without_redis",
    "ipinfo_download_url_ignored",
    "purge_on_start_left_set",
    "security_headers_config",
    "cors_response_wildcard",
    "redis_prefix_split",
    "unenforced_ban",
    "route_unknown_to_decorator",
    "redis_url_none",
    "cors_override",
    "cors_header_value",
    "dynamic_rules_agent",
    "forwarded_header",
    "body_reader_fallback",
    "throttle_without_middleware",
)
_LOGGER = logging.getLogger("guard_core")
QUIET_RUNTIME: JsonObject = {
    "enable_redis": False,
    "rate_limit": 10,
    "ban_on_hostile_signals": False,
}
_DYNAMIC_FIELDS = {
    "ip_blacklist": list,
    "ip_whitelist": list,
    "emergency_whitelist": list,
    "blocked_countries": list,
    "whitelist_countries": list,
    "endpoint_rate_limits": dict,
}
_DYNAMIC_NULLS = (
    "global_rate_limit",
    "global_rate_window",
    "ip_ban_duration",
    "auto_ban_duration",
)


class _Sink(logging.Handler):
    def __init__(self, pairs: list[Pair]) -> None:
        super().__init__(logging.WARNING)
        self.pairs = pairs

    def emit(self, record: logging.LogRecord) -> None:
        self.pairs.extend(getattr(record, "problems", ()))


@contextlib.contextmanager
def _capture() -> Iterator[list[Pair]]:
    pairs: list[Pair] = []
    sink = _Sink(pairs)
    previous = _LOGGER.level
    _LOGGER.setLevel(logging.WARNING)
    _LOGGER.addHandler(sink)
    # The reference warns once per process about a default redis_prefix.
    _staged_defaults._default_prefix_warned = False
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            yield pairs
    finally:
        _LOGGER.removeHandler(sink)
        _LOGGER.setLevel(previous)
    for warning in caught:
        carried = warning.message
        problem = carried.args[0] if isinstance(carried, Warning) else None
        if isinstance(problem, Problem):
            pairs.append((problem.kind, problem.subject))


def _require_flag_true_log_is_the_warn_part(
    reported: list[Pair], logged: list[Pair]
) -> None:
    """With the flag True the engine still logs every warn problem and logs no
    error problem (it raises them): the log equals the warn part of reported."""
    warn_part = sorted(pair for pair in reported if KINDS[pair[0]].severity == "warn")
    if sorted(logged) != warn_part:
        raise SystemExit(
            f"with the flag True the engine logged {sorted(logged)} but the warn "
            f"part of what it reports is {warn_part}: the reference rule of the "
            "misconfiguration suites no longer holds"
        )


def _raised_pairs(error: BaseException) -> FatalSink:
    if isinstance(error, MisconfigurationError):
        return [(problem.kind, problem.subject) for problem in error.problems]
    if isinstance(error, ValidationError):
        carried = [
            detail["ctx"]["error"]
            for detail in error.errors()
            if isinstance(detail.get("ctx", {}).get("error"), MisconfigurationError)
        ]
        if carried:
            return [pair for one in carried for pair in _raised_pairs(one)]
    raise error


def _try_fatal(sink: FatalSink, action: Callable[[], object]) -> None:
    try:
        action()
    except MalformedDynamicRules as error:
        sink.extend(_pairs_of(error.problems))
    except (MisconfigurationError, ValidationError) as error:
        sink.extend(_raised_pairs(error))


def _sorted(pairs: list[Pair]) -> list[list[str | None]]:
    ordered = sorted(pairs, key=lambda pair: (pair[0], pair[1] or ""))
    return [[kind, subject] for kind, subject in ordered]


async def _observe(driver: Driver) -> JsonObject:
    with _capture() as reported:
        reported.extend(await driver(False, []))
    fatal: FatalSink = []
    with _capture() as logged_when_refusing:
        await driver(True, fatal)
    _require_flag_true_log_is_the_warn_part(reported, logged_when_refusing)
    return {
        "raises": bool(fatal),
        "reported": cast("JsonValue", _sorted(reported)),
        "fatal": cast("JsonValue", _sorted(fatal)),
    }


def _config(
    stated: JsonObject,
    flag: bool,
    *,
    flag_stated: bool = True,
    geo_ip_handler: GeoIPHandler | None = None,
) -> SecurityConfig:
    fields = dict(stated)
    if flag_stated:
        fields["fail_on_misconfiguration"] = flag
    if geo_ip_handler is not None:
        fields["geo_ip_handler"] = cast("JsonValue", geo_ip_handler)
    return SecurityConfig(**fields)


def _config_driver(case_input: JsonObject) -> Driver:
    stated = cast("JsonObject", case_input["config"])
    flag_stated = case_input.get("flag_stated", True) is not False
    geo = case_input.get("geo")

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        handler = _StubGeo() if geo == "stub" else None
        _try_fatal(
            fatal,
            lambda: _config(
                stated, flag, flag_stated=flag_stated, geo_ip_handler=handler
            ),
        )
        return []

    return drive


def _dynamic_rules(case_input: JsonObject) -> DynamicRulesProtocol:
    given = cast("JsonObject", case_input["dynamic_rules"])
    fields: dict[str, object] = {name: kind() for name, kind in _DYNAMIC_FIELDS.items()}
    fields.update({name: None for name in _DYNAMIC_NULLS})
    fields["blocked_cloud_providers"] = set()
    fields.update(given)
    providers = fields["blocked_cloud_providers"]
    fields["blocked_cloud_providers"] = set(cast("list[str]", providers))
    return cast("DynamicRulesProtocol", SimpleNamespace(**fields))


def _dynamic_driver(case_input: JsonObject) -> Driver:
    rules = _dynamic_rules(case_input)

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        problems = find_malformed_values(rules)
        if not flag:
            return _pairs_of(problems)
        _try_fatal(fatal, lambda: _reject(problems))
        return []

    return drive


def _reject(problems: list[str]) -> None:
    if problems:
        raise MalformedDynamicRules(problems)


def _pairs_of(problems: list[str]) -> list[Pair]:
    return [
        (problem.kind, problem.subject)
        for problem in problems
        if isinstance(problem, Problem)
    ]


class _StubGeo:
    is_initialized = True

    async def initialize(self) -> None:
        return None

    async def refresh(self) -> None:
        return None

    def close(self) -> None:
        return None

    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None:
        return None

    async def initialize_agent(self, agent_handler: object) -> None:
        return None

    def get_country(self, ip: str) -> str | None:
        return None


def _route() -> None:
    return None


def _apply_decorator(decorator: SecurityDecorator, step: JsonObject) -> None:
    args = cast("dict[str, object]", step.get("args", {}))
    getattr(decorator, cast("str", step["name"]))(**args)(_route)


def _decorator_driver(case_input: JsonObject) -> Driver:
    stated = cast("JsonObject", case_input.get("config", {}))
    steps = cast("list[JsonObject]", case_input["decorators"])
    geo = case_input.get("geo")

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        handler = _StubGeo() if geo == "stub" else None
        decorator = SecurityDecorator(_config(stated, flag, geo_ip_handler=handler))
        for step in steps:
            _try_fatal(fatal, partial(_apply_decorator, decorator, step))
        return []

    return drive


def _ban_threshold_driver(case_input: JsonObject) -> Driver:
    stated = cast("JsonObject", case_input["config"])
    redis_shared = case_input.get("redis_shared", False) is True

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        config = _config(stated, flag)
        context = _BanThresholdContext(lambda: (), lambda: redis_shared)
        _try_fatal(
            fatal,
            lambda: report_unreachable_ban_thresholds(
                config, context, _LOGGER, stacklevel=2
            ),
        )
        return []

    return drive


def _nat64_driver(case_input: JsonObject) -> Driver:
    stated = cast("JsonObject", case_input["config"])

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        config = _config(stated, flag)
        _try_fatal(fatal, lambda: apply_nat64_prefixes(config, _LOGGER))
        return []

    return drive


def _redis_handler_stub(spec: JsonObject) -> object:
    lacks = set(cast("list[str]", spec.get("lacks", [])))
    members: dict[str, object] = {
        name: (lambda self, *args, **kwargs: None)
        for name in get_protocol_members(RedisHandlerProtocol)
        if name not in lacks
    }
    mode = spec.get("is_connected", "sync")
    if mode == "missing":
        members.pop("is_connected", None)
    elif mode == "async":

        async def is_connected(self: object) -> bool:
            return True

        members["is_connected"] = is_connected
    else:
        members["is_connected"] = lambda self: True
    return type("StubRedisHandler", (), members)()


def _redis_handler_driver(case_input: JsonObject) -> Driver:
    stated = cast("JsonObject", case_input["config"])
    handler = _redis_handler_stub(cast("JsonObject", case_input["redis_handler"]))

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        config = _config(stated, flag)
        _try_fatal(
            fatal, lambda: report_incomplete_redis_handler(config, handler, _LOGGER)
        )
        return []

    return drive


def _country_decorator_driver(case_input: JsonObject) -> Driver:
    stated = cast("JsonObject", case_input["config"])
    routes = cast("dict[str, JsonObject]", case_input["routes"])

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        config = _config(stated, flag)
        configs = {
            route_id: SimpleNamespace(
                blocked_countries=spec.get("blocked_countries", []),
                whitelist_countries=spec.get("whitelist_countries", []),
                geo_rate_limits=spec.get("geo_rate_limits", {}),
            )
            for route_id, spec in routes.items()
        }
        owner = cast(
            "BaseSecurityDecorator",
            SimpleNamespace(config=config, _route_configs=configs),
        )
        _try_fatal(
            fatal,
            lambda: report_country_decorators_without_geoip(
                config, owner, None, _LOGGER
            ),
        )
        return []

    return drive


class _RecordedRedis:
    def __init__(self, recorded: int | None) -> None:
        self.config = SimpleNamespace(redis_prefix="guard_core:")
        self.recorded = recorded

    async def set_key_if_absent(self, namespace: str, key: str, value: str) -> bool:
        return self.recorded is None

    async def get_key(self, namespace: str, key: str) -> str | None:
        return None if self.recorded is None else str(self.recorded)


def _ipv6_prefix_driver(case_input: JsonObject) -> Driver:
    stated = cast("JsonObject", case_input["config"])
    recorded = cast("int | None", case_input.get("redis_recorded_ipv6_prefix_length"))

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        config = _config(stated, flag)
        try:
            await enforce_prefix_length_contract(
                cast("RedisHandlerProtocol", _RecordedRedis(recorded)),
                config,
                _LOGGER,
            )
        except MisconfigurationError as error:
            fatal.extend(_raised_pairs(error))
        return []

    return drive


def _resolver(mode: object) -> RouteResolver:
    def raises(key: str) -> tuple[RouteIdentity, ...]:
        raise RuntimeError("resolve_route failed")

    def no_match(key: str) -> tuple[RouteIdentity, ...]:
        return ()

    return raises if mode == "raises" else no_match


def _endpoint_key_routes_driver(case_input: JsonObject) -> Driver:
    keys = cast("list[str]", case_input["endpoint_rate_limit_keys"])
    resolver = _resolver(case_input["resolve_route"])

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        middleware = SimpleNamespace()
        mapping = EndpointLimitKeyMap(keys, resolver)
        warn_unmatched_endpoint_keys(middleware, mapping.unresolved)
        return []

    return drive


def _exclude_paths_routes_driver(case_input: JsonObject) -> Driver:
    stated = cast("JsonObject", case_input["config"])
    prefixes = case_input["static_route_prefixes"]

    def provider() -> list[str]:
        if prefixes == "raises":
            raise RuntimeError("static_route_prefixes failed")
        return cast("list[str]", prefixes)

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        config = _config(stated, flag)
        middleware = SimpleNamespace(static_route_prefixes=provider)
        warn_unmatched_exclude_paths(middleware, config)
        return []

    return drive


def _declared_path_params_driver(case_input: JsonObject) -> Driver:
    stated = cast("JsonObject", case_input["config"])
    template = cast("str", case_input["template"])
    declared = cast("list[str]", case_input["declared"])

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        config = _config(stated, flag)
        problems = detection_exclusion_path_param_problems("route", template, declared)
        _try_fatal(
            fatal,
            lambda: report_misconfigurations(
                config, problems, logger=_LOGGER, stacklevel=2
            ),
        )
        return []

    return drive


def _lazy_init_driver(case_input: JsonObject) -> Driver:
    stub = SimpleNamespace(
        geo_ip_handler=object() if case_input["geo_handler"] else None,
        logger=_LOGGER,
        _cloud_providers_to_load=lambda: bool(case_input["cloud_providers"]),
    )

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        _HandlerInitializerStepsMixin._warn_if_lazy_init_is_inert(
            cast("_HandlerInitializerStepsMixin", stub)
        )
        return []

    return drive


def _ipinfo_driver(case_input: JsonObject) -> Driver:
    manager = SimpleNamespace(
        _download_url=case_input["manager_download_url"], logger=_LOGGER
    )

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        IPInfoManager._warned_ignored_urls = set()
        IPInfoManager._warn_once_if_download_url_ignored(
            cast("IPInfoManager", manager),
            Path("ipinfo.mmdb"),
            cast("str | None", case_input["download_url"]),
        )
        return []

    return drive


def _purge_driver(case_input: JsonObject) -> Driver:
    async def purge_dynamic_rules(rule_id: str, version: int) -> bool:
        return bool(case_input["matches"])

    stub = SimpleNamespace(
        config=SimpleNamespace(purge_dynamic_rules_on_start=case_input["target"]),
        logger=_LOGGER,
        purge_dynamic_rules=purge_dynamic_rules,
    )

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        await DynamicRulePurgeMixin.purge_configured_dynamic_rules(
            cast("DynamicRulePurgeMixin", stub)
        )
        return []

    return drive


def _security_headers_driver(case_input: JsonObject) -> Driver:
    csp = cast("dict[str, list[str]] | None", case_input.get("csp"))
    hsts = cast("JsonObject | None", case_input.get("hsts"))
    cors = cast("JsonObject | None", case_input.get("cors"))
    stub = cast("SecurityHeadersConfigMixin", SimpleNamespace(logger=_LOGGER))

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        SecurityHeadersConfigMixin._compute_csp_config(stub, csp)
        if hsts is not None:
            SecurityHeadersConfigMixin._compute_hsts_config(
                stub,
                cast("int", hsts["max_age"]),
                cast("bool", hsts["include_subdomains"]),
                cast("bool", hsts["preload"]),
            )
        if cors is not None:
            SecurityHeadersConfigMixin._compute_cors_config(
                stub,
                cast("list[str]", cors["origins"]),
                cast("bool", cors["allow_credentials"]),
                None,
                None,
            )
        return []

    return drive


def _cors_response_driver(case_input: JsonObject) -> Driver:
    origins = cast("list[str]", case_input["origins"])
    credentials = cast("bool", case_input["allow_credentials"])
    stub = cast("SecurityHeadersCorsMixin", SimpleNamespace(logger=_LOGGER))

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        SecurityHeadersCorsMixin._is_wildcard_with_credentials(
            stub, origins, {"allow_credentials": credentials}
        )
        return []

    return drive


def _redis_prefix_split_driver(case_input: JsonObject) -> Driver:
    first = SimpleNamespace(
        redis_prefix=case_input["prefix"], redis_url=case_input["first_url"]
    )
    second = SimpleNamespace(
        redis_prefix=case_input["prefix"], redis_url=case_input["second_url"]
    )

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        _warn_split_connection(
            cast("_PrefixedRedisConfig", first),
            cast("_PrefixedRedisConfig", second),
            None,
            None,
        )
        return []

    return drive


def _unenforced_ban_driver(case_input: JsonObject) -> Driver:
    repeat = cast("int", case_input.get("repeat", 1))
    refuses = case_input["self_dos"] is True

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        config = _config(dict(QUIET_RUNTIME), flag)
        stub = SimpleNamespace(
            logger=_LOGGER,
            _self_dos_refusal_reason=lambda ip, config: "loopback" if refuses else None,
        )
        manager = cast("IpBanSharedAppsMixin", stub)
        for _ in range(repeat):
            IpBanSharedAppsMixin._ban_stands_for(manager, "192.0.2.7", config)
        return []

    return drive


def _redis_url_none_driver(case_input: JsonObject) -> Driver:
    @contextlib.asynccontextmanager
    async def lock() -> AsyncIterator[None]:
        yield

    async def discard_client() -> None:
        return None

    stub = SimpleNamespace(
        config=SimpleNamespace(enable_redis=case_input["enable_redis"], redis_url=None),
        logger=_LOGGER,
        _connection_lock_here=lock,
        _discard_client=discard_client,
    )

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        await RedisManager.initialize(cast("RedisManager", stub))
        return []

    return drive


def _cors_override_driver(case_input: JsonObject) -> Driver:
    base = CorsParams(
        enabled=True,
        origins=("https://a.example",),
        credentials=False,
        methods=("GET",),
        headers=("*",),
        max_age=3600,
        expose=(),
    )
    wider = replace(base, origins=("https://a.example", "https://b.example"))
    branches = {
        "fields_refused": (wider, "why"),
        "refused": (base, "why"),
        "widens": (wider, None),
        "unchanged": (base, None),
    }
    merged, reason = branches[cast("str", case_input["branch"])]
    stub = cast("SecurityHeadersOverrideMixin", SimpleNamespace(logger=_LOGGER))

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        SecurityHeadersOverrideMixin._log_cors_override(stub, base, merged, reason)
        return []

    return drive


def _cors_header_value_driver(case_input: JsonObject) -> Driver:
    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        manager = SecurityHeadersManager.isolated()
        manager.logger = _LOGGER
        manager.cors_config = {
            "origins": ["https://a.example"],
            "allow_credentials": False,
            "allow_methods": [cast("str", case_input["method"])],
            "allow_headers": ["*"],
            "max_age": 1,
        }
        await manager.get_cors_headers(cast("str", case_input["origin"]))
        return []

    return drive


def _dynamic_rules_agent_driver(case_input: JsonObject) -> Driver:
    stub = SimpleNamespace(
        config=SimpleNamespace(enable_dynamic_rules=case_input["enable_dynamic_rules"]),
        agent_handler=None,
        logger=_LOGGER,
    )

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        await _HandlerInitializerStepsMixin.initialize_dynamic_rule_manager(
            cast("_HandlerInitializerStepsMixin", stub)
        )
        return []

    return drive


_FORWARDED_WARNINGS = {
    "preempted": ("_forwarded_header_preemption_warned", 2),
    "chain_too_short": ("_forwarded_header_chain_too_short_warned", 1),
    "selects_trusted_proxy": (
        "_forwarded_header_selected_entry_trusted_proxy_warned",
        1,
    ),
    "overcounts_hops": ("_forwarded_header_depth_overcounts_hops_warned", 2),
}


def _forwarded_header_driver(case_input: JsonObject) -> Driver:
    name = cast("str", case_input["warning"])
    flag_name = _FORWARDED_WARNINGS[name][0]
    repeat = cast("int", case_input.get("repeat", 1))
    calls = {
        "preempted": lambda: ip_extraction._warn_forwarded_header_preempted(
            "203.0.113.7", "203.0.113.7, 198.51.100.1"
        ),
        "chain_too_short": lambda: ip_extraction._warn_forwarded_header_chain_too_short(
            "198.51.100.1", 1
        ),
        "selects_trusted_proxy": lambda: (
            ip_extraction._warn_forwarded_header_selected_entry_trusted_proxy(
                "10.0.0.1"
            )
        ),
        "overcounts_hops": lambda: (
            ip_extraction._warn_forwarded_header_depth_overcounts_hops(
                2, "198.51.100.1, 198.51.100.2"
            )
        ),
    }

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        setattr(ip_extraction, flag_name, False)
        for _ in range(repeat):
            calls[name]()
        return []

    return drive


class _PlainRequest:
    pass


def _body_reader_fallback_driver(case_input: JsonObject) -> Driver:
    kind = (
        body_reader._PREFIX
        if case_input["reader"] == "prefix"
        else body_reader._FULL_BODY
    )
    repeat = cast("int", case_input.get("repeat", 1))

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        body_reader._fallback_warned_kinds.clear()
        request = cast("GuardRequest", _PlainRequest())
        for _ in range(repeat):
            body_reader._warn_body_reader_fallback_once_per_app(request, kind, None)
        return []

    return drive


def _throttle_without_middleware_driver(case_input: JsonObject) -> Driver:
    repeat = cast("int", case_input.get("repeat", 1))

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        _throttle._missing_middleware_warned = False
        rules = [BehaviorRule("usage", 5, window=60, action="throttle")]
        for _ in range(repeat):
            _throttle.warn_throttle_needs_middleware(rules)
        return []

    return drive


def _route_unknown_driver(case_input: JsonObject) -> Driver:
    repeat = cast("int", case_input.get("repeat", 1))

    async def drive(flag: bool, fatal: FatalSink) -> list[Pair]:
        resolver = SimpleNamespace(
            _warned_foreign_route_ids=set(), context=SimpleNamespace(logger=_LOGGER)
        )
        request = SimpleNamespace(state=SimpleNamespace())
        for _ in range(repeat):
            RouteConfigResolver._flag_route_unknown_to_decorator(
                cast("RouteConfigResolver", resolver),
                cast("GuardRequest", request),
                cast("str", case_input["route_id"]),
            )
        return []

    return drive


_RUNTIME_DRIVERS: dict[str, Callable[[JsonObject], Driver]] = {
    "ban_thresholds": _ban_threshold_driver,
    "nat64": _nat64_driver,
    "redis_handler": _redis_handler_driver,
    "country_decorators": _country_decorator_driver,
    "ipv6_prefix_length": _ipv6_prefix_driver,
    "endpoint_key_routes": _endpoint_key_routes_driver,
    "exclude_paths_routes": _exclude_paths_routes_driver,
    "declared_path_params": _declared_path_params_driver,
    "lazy_init_without_redis": _lazy_init_driver,
    "ipinfo_download_url_ignored": _ipinfo_driver,
    "purge_on_start_left_set": _purge_driver,
    "security_headers_config": _security_headers_driver,
    "cors_response_wildcard": _cors_response_driver,
    "redis_prefix_split": _redis_prefix_split_driver,
    "unenforced_ban": _unenforced_ban_driver,
    "route_unknown_to_decorator": _route_unknown_driver,
    "redis_url_none": _redis_url_none_driver,
    "cors_override": _cors_override_driver,
    "cors_header_value": _cors_header_value_driver,
    "dynamic_rules_agent": _dynamic_rules_agent_driver,
    "forwarded_header": _forwarded_header_driver,
    "body_reader_fallback": _body_reader_fallback_driver,
    "throttle_without_middleware": _throttle_without_middleware_driver,
}


def _driver_for(suite: str, case_input: JsonObject) -> Driver:
    scope = SUITE_FILES[suite]
    if scope == "config":
        return _config_driver(case_input)
    if scope == "dynamic_rules":
        return _dynamic_driver(case_input)
    if scope == "decorators":
        return _decorator_driver(case_input)
    return _RUNTIME_DRIVERS[cast("str", case_input["seam"])](case_input)


async def run_misconfiguration_case(suite: str, case_input: JsonObject) -> JsonObject:
    return await _observe(_driver_for(suite, case_input))


def intended_kinds(expected: JsonObject) -> list[str]:
    reported = cast("list[list[str]]", expected["reported"])
    fatal = cast("list[list[str]]", expected["fatal"])
    return sorted(
        [kind for kind, _ in reported]
        + [kind for kind, _ in fatal if KINDS[kind].fatal_only]
    )
