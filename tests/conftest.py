import gc
import logging
import os
import re
import secrets
import sys
import uuid
from collections.abc import AsyncGenerator, Callable, Generator, Iterator
from importlib.machinery import ModuleSpec
from pathlib import Path
from types import FrameType
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qsl

import pytest
from guard_agent.models import AgentConfig, SecurityEvent, SecurityMetric
from pytest import TempPathFactory

from guard_core import _security_config_field_validators as _field_validators_module
from guard_core import _staged_defaults as _staged_defaults_module
from guard_core._utils import body_reader
from guard_core._utils import detection_scan as _detection_scan_module
from guard_core._utils import ip_extraction as _ip_extraction_module
from guard_core.core.checks.implementations import (
    emergency_mode as _emergency_mode_module,
)
from guard_core.core.checks.implementations import (
    suspicious_activity as _suspicious_activity_module,
)
from guard_core.core.events import logfire_handler as _logfire_handler_module
from guard_core.core.events import otel_handler as _otel_handler_module
from guard_core.handlers import ipban_handler as _ipban_module
from guard_core.handlers import security_headers_handler as _security_headers_module
from guard_core.handlers import suspatterns_handler as _suspatterns_module
from guard_core.handlers.cloud_handler import (
    _ALL_PROVIDERS,
    CloudManager,
    cloud_handler,
)
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.handlers.suspatterns_handler import (
    _LEGACY_DETECTION_STATE,
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.models import SecurityConfig

if TYPE_CHECKING:
    from tests.live_smoke.driver import ScenarioContext, Stack

_suspatterns_module._legacy_detection_warned = True
_field_validators_module._hostile_signal_ban_default_warned = True
_staged_defaults_module._redis_default_warned = True
_staged_defaults_module._rate_limit_default_warned = True
_staged_defaults_module._default_prefix_warned = True
_staged_defaults_module._whitelist_access_only_warned = True

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN") or "test_token"
REDIS_URL = os.getenv("REDIS_URL") or "redis://localhost:6379"
_REDIS_PREFIX_BASE = os.getenv("REDIS_PREFIX") or "test:guard_core:"
REDIS_PREFIX = f"{_REDIS_PREFIX_BASE}{os.getpid()}:{secrets.token_hex(4)}:"
GUARD_TESTS_GC_PER_TEST = os.getenv("GUARD_TESTS_GC_PER_TEST") == "1"
_MAX_TEST_SECONDS_ENV = "GUARD_TESTS_MAX_TEST_SECONDS"
_TEST_NODE_DURATIONS: dict[str, float] = {}

_TESTS_DIR = Path(__file__).parent
_TEST_AGENT_DIR = _TESTS_DIR / "test_agent"
_TEST_SUS_PATTERNS_DIR = _TESTS_DIR / "test_sus_patterns"
_TEST_CLOUD_IPS_DIR = _TESTS_DIR / "test_cloud_ips"
_TEST_UTILS_DIR = _TESTS_DIR / "test_utils"
_CLOUD_IP_REDIS_PREFIX = f"test:guard_core_cloud_ip_isolation:{uuid.uuid4().hex}:"


def _guard_core_logger_names() -> list[str]:
    return [
        name
        for name, obj in logging.Logger.manager.loggerDict.items()
        if isinstance(obj, logging.Logger)
        and (name == "guard_core" or name.startswith("guard_core."))
    ]


@pytest.fixture(autouse=True)
def _isolate_guard_core_logger_levels() -> Any:
    original_root_level = logging.getLogger().level
    original_levels = {
        name: logging.getLogger(name).level for name in _guard_core_logger_names()
    }
    yield
    logging.getLogger().setLevel(original_root_level)
    for name in _guard_core_logger_names():
        logging.getLogger(name).setLevel(original_levels.get(name, logging.NOTSET))


@pytest.fixture(autouse=True)
def _isolate_detection_singleton() -> Any:
    handler = _suspatterns_module.sus_patterns_handler
    saved_state = handler._detection_state
    saved_instance = SusPatternsManager._instance
    saved_config = SusPatternsManager._config
    saved_global = _suspatterns_module.sus_patterns_handler
    saved_sensitive_headers_union = SusPatternsManager._sensitive_headers_union
    saved_sensitive_params_union = SusPatternsManager._sensitive_params_union
    saved_sensitive_body_fields_union = SusPatternsManager._sensitive_body_fields_union
    yield
    handler._detection_state = saved_state
    SusPatternsManager._instance = saved_instance
    SusPatternsManager._config = saved_config
    _suspatterns_module.sus_patterns_handler = saved_global
    SusPatternsManager._sensitive_headers_union = saved_sensitive_headers_union
    SusPatternsManager._sensitive_params_union = saved_sensitive_params_union
    SusPatternsManager._sensitive_body_fields_union = saved_sensitive_body_fields_union


def _restore_submodule_identity(module: Any) -> None:
    """Undo a test that reimported a submodule (`sys.modules.pop` + fresh
    `import_module`/`reload`), which rebinds the module as a *package*
    attribute but leaves the old, still-imported package attribute pointing
    at an orphaned module object that later `unittest.mock.patch()` calls
    (which resolve targets via attribute traversal, not `sys.modules`) will
    silently patch instead of the real one.
    """
    sys.modules[module.__name__] = module
    package_name, _, leaf = module.__name__.rpartition(".")
    package = sys.modules.get(package_name)
    if package is not None:
        setattr(package, leaf, module)


@pytest.fixture(autouse=True)
def _isolate_event_handler_modules() -> Any:
    yield
    _restore_submodule_identity(_otel_handler_module)
    _restore_submodule_identity(_logfire_handler_module)


_ORIGINAL_IP_BAN_MANAGER = _ipban_module.ip_ban_manager
_ORIGINAL_SECURITY_HEADERS_MANAGER = _security_headers_module.security_headers_manager


def _reset_untrusted_forwarded_for_tracking() -> None:
    _ip_extraction_module._untrusted_peers.clear()
    _suspicious_activity_module._disabled_detection_samples.clear()
    _emergency_mode_module._emergency_samples.clear()


def _reset_ip_ban_manager() -> None:
    IPBanManager._instance = _ORIGINAL_IP_BAN_MANAGER
    _ipban_module.ip_ban_manager = _ORIGINAL_IP_BAN_MANAGER
    _ORIGINAL_IP_BAN_MANAGER.banned_ips.clear()
    _ORIGINAL_IP_BAN_MANAGER.banned_networks.clear()
    _ORIGINAL_IP_BAN_MANAGER.rule_exempt_networks = ()
    _ORIGINAL_IP_BAN_MANAGER._operator_networks = None
    _ORIGINAL_IP_BAN_MANAGER.redis_handler = None
    _ORIGINAL_IP_BAN_MANAGER.agent_handler = None
    _ORIGINAL_IP_BAN_MANAGER.evictions_count = 0


def _reset_cloud_handler() -> None:
    from guard_core.handlers.cloud_ip_stores import InMemoryCloudIpStore

    CloudManager._instance = cloud_handler
    cloud_handler.ip_ranges = {provider: set() for provider in _ALL_PROVIDERS}
    cloud_handler.network_regions = {provider: {} for provider in _ALL_PROVIDERS}
    cloud_handler.last_updated = {provider: None for provider in _ALL_PROVIDERS}
    cloud_handler.redis_handler = None
    cloud_handler.agent_handler = None
    cloud_handler._store = InMemoryCloudIpStore()
    cloud_handler._refresh_task = None
    cloud_handler._refresh_in_flight = False
    cloud_handler._empty_ranges_warned_at = {}


def _reset_ipinfo_manager() -> None:
    instance = IPInfoManager._instance
    if instance is not None:
        if instance.reader:
            instance.reader.close()
        instance.agent_handler = None
        instance.redis_handler = None
    IPInfoManager._instance = None


async def _reset_dynamic_rule_manager() -> None:
    instance = DynamicRuleManager._instance
    if instance is not None:
        if instance.update_task:
            await instance.stop()
        instance.agent_handler = None
        instance.redis_handler = None
    DynamicRuleManager._instance = None


async def _reset_redis_manager() -> None:
    instance = RedisManager._instance
    if instance is not None:
        await instance.close()
        instance.agent_handler = None
    RedisManager._instance = None


SINGLETON_RESET_HELPERS: dict[str, Callable[[], Any]] = {
    "CloudManager": _reset_cloud_handler,
    "IPInfoManager": _reset_ipinfo_manager,
    "DynamicRuleManager": _reset_dynamic_rule_manager,
    "RedisManager": _reset_redis_manager,
}


def _reset_detection_scan_budgets() -> None:
    _detection_scan_module._scanned_value_count.set(0)
    _detection_scan_module._scan_value_cap.set(
        _detection_scan_module._DEFAULT_MAX_SCAN_VALUES
    )
    _detection_scan_module._scanned_char_count.set(0)
    _detection_scan_module._scan_char_cap.set(
        _detection_scan_module._DEFAULT_MAX_SCAN_CHARS
    )
    _detection_scan_module._scan_char_cap_warned.set(False)
    _detection_scan_module._json_depth_cap.set(
        _detection_scan_module._DEFAULT_MAX_JSON_DEPTH
    )
    _detection_scan_module._json_depth_warned.set(False)


async def _reset_security_headers_manager() -> None:
    SecurityHeadersManager._instance = _ORIGINAL_SECURITY_HEADERS_MANAGER
    _security_headers_module.security_headers_manager = (
        _ORIGINAL_SECURITY_HEADERS_MANAGER
    )
    await _ORIGINAL_SECURITY_HEADERS_MANAGER.reset()
    _ORIGINAL_SECURITY_HEADERS_MANAGER.agent_handler = None
    _ORIGINAL_SECURITY_HEADERS_MANAGER.redis_handler = None


class MockState:
    def __init__(self) -> None:
        self._attrs: dict[str, Any] = {}

    def __getattr__(self, name: str) -> Any:
        if name == "_attrs":
            return super().__getattribute__(name)
        return self._attrs.get(name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "_attrs":
            super().__setattr__(name, value)
        else:
            self._attrs[name] = value


def _split_query_from_path(path: str) -> tuple[str, str]:
    path_only, _, query = path.partition("?")
    return path_only, query


def _parse_query_params(query: str) -> dict[str, str]:
    return dict(parse_qsl(query, keep_blank_values=True))


def declare_route(request: Any, template: str) -> Any:
    request.state.guard_route_template = template
    return request


class MockGuardRequest:
    def __init__(
        self,
        path: str = "/",
        method: str = "GET",
        headers: dict[str, str] | None = None,
        client_host: str | None = "127.0.0.1",
        scheme: str = "https",
        query_params: dict[str, str] | None = None,
        body_content: bytes = b"",
        scope: dict[str, Any] | None = None,
    ) -> None:
        self._path = path
        self._method = method
        self._headers = headers or {}
        self._client_host = client_host
        self._scheme = scheme
        path_only, query = _split_query_from_path(path)
        self._url_path = path_only
        self._query_params = (
            query_params if query_params is not None else _parse_query_params(query)
        )
        self._body = body_content
        self._state = MockState()
        self._scope = scope or {}

    @property
    def url_path(self) -> str:
        return self._url_path

    @property
    def url_scheme(self) -> str:
        return self._scheme

    @property
    def url_full(self) -> str:
        return f"{self._scheme}://test{self._path}"

    def url_replace_scheme(self, scheme: str) -> str:
        return f"{scheme}://test{self._path}"

    @property
    def method(self) -> str:
        return self._method

    @property
    def client_host(self) -> str | None:
        return self._client_host

    @property
    def headers(self) -> dict[str, str]:
        return self._headers

    @property
    def query_params(self) -> dict[str, str]:
        return self._query_params

    async def body(self) -> bytes:
        return self._body

    @property
    def state(self) -> MockState:
        return self._state

    @property
    def scope(self) -> dict[str, Any]:
        return self._scope


class MockGuardResponse:
    def __init__(
        self,
        content: str = "",
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._status_code = status_code
        self._headers: dict[str, str] = headers or {}
        self._body = content.encode() if isinstance(content, str) else content

    @property
    def status_code(self) -> int:
        return self._status_code

    @property
    def headers(self) -> dict[str, str]:
        return self._headers

    @property
    def body(self) -> bytes:
        return self._body


class MockGuardResponseFactory:
    def create_response(self, content: str, status_code: int) -> MockGuardResponse:
        return MockGuardResponse(content, status_code)

    def create_redirect_response(self, url: str, status_code: int) -> MockGuardResponse:
        return MockGuardResponse(f"Redirect to {url}", status_code, {"Location": url})


@pytest.fixture(autouse=True)
async def reset_state() -> AsyncGenerator[None, None]:
    _reset_untrusted_forwarded_for_tracking()
    _reset_ip_ban_manager()
    _reset_cloud_handler()
    _reset_detection_scan_budgets()
    await _reset_security_headers_manager()
    _reset_ipinfo_manager()

    yield
    spm = type(sus_patterns_handler)
    spm._instance = sus_patterns_handler
    spm._config = None
    _suspatterns_module.sus_patterns_handler = sus_patterns_handler
    sus_patterns_handler.patterns = [p[0] for p in spm._pattern_definitions]
    sus_patterns_handler.compiled_patterns = [
        (re.compile(pattern, re.IGNORECASE), contexts, category)
        for pattern, contexts, category in spm._pattern_definitions
    ]
    sus_patterns_handler.custom_patterns = set()
    sus_patterns_handler.compiled_custom_patterns = set()
    sus_patterns_handler._detection_state = _LEGACY_DETECTION_STATE
    _suspatterns_module._legacy_detection_warned = True
    _field_validators_module._hostile_signal_ban_default_warned = True
    _staged_defaults_module._redis_default_warned = True
    _staged_defaults_module._rate_limit_default_warned = True
    _staged_defaults_module._default_prefix_warned = True
    _staged_defaults_module._whitelist_access_only_warned = True

    _reset_ip_ban_manager()
    _reset_cloud_handler()
    _reset_detection_scan_budgets()
    await _reset_security_headers_manager()
    await _reset_dynamic_rule_manager()


@pytest.fixture
def security_config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        whitelist=["127.0.0.1"],
        blacklist=["192.168.1.1"],
        blocked_user_agents=[r"badbot"],
        auto_ban_threshold=3,
        auto_ban_duration=300,
        custom_log_file="test_log.log",
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests",
        },
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
        cors_allow_credentials=True,
        cors_expose_headers=["X-Custom-Header"],
        cors_max_age=600,
    )


@pytest.fixture(scope="session")
def ipinfo_db_path(tmp_path_factory: TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("ipinfo_data") / "country_asn.mmdb"


@pytest.fixture
def security_config_redis(ipinfo_db_path: Path) -> SecurityConfig:
    return SecurityConfig(
        redis_url=REDIS_URL,
        redis_prefix=REDIS_PREFIX,
        whitelist=["127.0.0.1"],
        blacklist=["192.168.1.1"],
        blocked_user_agents=[r"badbot"],
        auto_ban_threshold=3,
        auto_ban_duration=300,
        custom_log_file="test_log.log",
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests",
        },
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
        cors_allow_credentials=True,
        cors_expose_headers=["X-Custom-Header"],
        cors_max_age=600,
    )


@pytest.fixture(autouse=True)
async def redis_cleanup() -> AsyncGenerator[None, None]:
    config = SecurityConfig(
        redis_url=REDIS_URL,
        redis_prefix=REDIS_PREFIX,
    )
    redis_handler = RedisManager(config)
    await redis_handler.initialize()
    try:
        await redis_handler.delete_pattern("*")
    except Exception:
        pass
    finally:
        await redis_handler.close()
    yield
    redis_handler = RedisManager(config)
    await redis_handler.initialize()
    try:
        await redis_handler.delete_pattern("*")
    except Exception:
        pass
    finally:
        await redis_handler.close()


@pytest.fixture(autouse=True)
def _collect_garbage_after_test() -> Any:
    yield
    if GUARD_TESTS_GC_PER_TEST:
        gc.collect()


@pytest.fixture
def mock_guard_agent() -> Generator[Any, Any, Any]:
    import sys
    import types

    mock_guard_agent_module = types.ModuleType("guard_agent")
    guard_agent_ns = cast(Any, mock_guard_agent_module)
    guard_agent_ns.SecurityEvent = SecurityEvent
    guard_agent_ns.SecurityMetric = SecurityMetric
    guard_agent_ns.AgentConfig = AgentConfig

    mock_models_module = types.ModuleType("guard_agent.models")
    guard_agent_models_ns = cast(Any, mock_models_module)
    guard_agent_models_ns.SecurityEvent = SecurityEvent
    guard_agent_models_ns.SecurityMetric = SecurityMetric
    guard_agent_models_ns.AgentConfig = AgentConfig
    guard_agent_ns.models = mock_models_module

    mock_agent_handler = AsyncMock()
    mock_guard_agent_func = MagicMock(return_value=mock_agent_handler)
    guard_agent_ns.guard_agent = mock_guard_agent_func

    original_modules = {}
    modules_to_mock = [
        "guard_agent",
        "guard_agent.models",
    ]

    for module_name in modules_to_mock:
        if module_name in sys.modules:
            original_modules[module_name] = sys.modules[module_name]

    sys.modules["guard_agent"] = mock_guard_agent_module
    sys.modules["guard_agent.models"] = mock_models_module

    with (
        patch(
            "guard_core.handlers.behavior_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.handlers.cloud_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.handlers.dynamic_rule_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.decorators.base.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.handlers.ipban_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.handlers.ipinfo_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.handlers.ratelimit_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.handlers.redis_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.handlers.suspatterns_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.utils.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "guard_core.models.AgentConfig",
            AgentConfig,
            create=True,
        ),
    ):
        try:
            yield mock_guard_agent_module
        finally:
            for module_name in modules_to_mock:
                if module_name in original_modules:
                    sys.modules[module_name] = original_modules[module_name]
                elif module_name in sys.modules:  # pragma: no cover
                    del sys.modules[module_name]


@pytest.fixture(autouse=True)
def mock_dependencies(request: pytest.FixtureRequest) -> Generator[Any, Any, Any]:
    if not request.path.is_relative_to(_TEST_AGENT_DIR):
        yield
        return

    request.getfixturevalue("mock_guard_agent")
    with (
        patch(
            "guard_core.handlers.redis_handler.RedisManager.initialize",
            new_callable=AsyncMock,
        ),
        patch(
            "guard_core.handlers.ipinfo_handler.IPInfoManager.__new__"
        ) as mock_ipinfo,
        patch("guard_core.handlers.cloud_handler.CloudManager.__new__") as mock_cloud,
    ):
        mock_ipinfo_instance = MagicMock()
        mock_ipinfo.return_value = mock_ipinfo_instance

        mock_cloud_instance = MagicMock()
        mock_cloud.return_value = mock_cloud_instance
        yield


@pytest.fixture
def config() -> SecurityConfig:
    return SecurityConfig(
        enable_agent=True,
        agent_api_key="test-api-key",
        agent_endpoint="http://test.example.com",
        enable_dynamic_rules=True,
        dynamic_rule_interval=60,
        enable_penetration_detection=True,
        enable_ip_banning=True,
        enable_rate_limiting=True,
        rate_limit=100,
        rate_limit_window=60,
        auto_ban_threshold=5,
    )


@pytest.fixture
def mock_agent_handler() -> AsyncMock:
    handler = AsyncMock()
    handler.get_dynamic_rules = AsyncMock(return_value=None)
    handler.send_event = AsyncMock()
    return handler


@pytest.fixture
def mock_redis_handler() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def security_config_with_detection() -> SecurityConfig:
    return SecurityConfig(
        detection_compiler_timeout=2.0,
        detection_max_content_length=10000,
        detection_preserve_attack_patterns=True,
        detection_semantic_threshold=0.7,
        detection_anomaly_threshold=3.0,
        detection_slow_pattern_threshold=0.1,
        detection_monitor_history_size=1000,
        detection_max_tracked_patterns=1000,
    )


@pytest.fixture
async def sus_patterns_manager_with_detection(
    security_config_with_detection: SecurityConfig,
) -> AsyncGenerator[SusPatternsManager, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    SusPatternsManager._instance = None
    SusPatternsManager._config = None

    manager = SusPatternsManager(security_config_with_detection)

    yield manager

    await manager.reset()

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


@pytest.fixture(autouse=True)
async def reset_sus_patterns(
    request: pytest.FixtureRequest,
) -> AsyncGenerator[None, None]:
    if not request.path.is_relative_to(_TEST_SUS_PATTERNS_DIR):
        yield
        return

    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    original_patterns = None
    original_custom_patterns: set[str] = set()
    if original_instance:
        original_patterns = original_instance.patterns.copy()
        original_custom_patterns = original_instance.custom_patterns.copy()

    yield

    if SusPatternsManager._instance:
        await SusPatternsManager._instance.reset()

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config

    if original_instance and original_patterns:
        original_instance.patterns = original_patterns
        original_instance.custom_patterns = original_custom_patterns


@pytest.fixture
def security_config_redis_isolated_prefix(ipinfo_db_path: Path) -> SecurityConfig:
    return SecurityConfig(
        redis_url=REDIS_URL,
        redis_prefix=_CLOUD_IP_REDIS_PREFIX,
        whitelist=["127.0.0.1"],
        blacklist=["192.168.1.1"],
        blocked_user_agents=[r"badbot"],
        auto_ban_threshold=3,
        auto_ban_duration=300,
        custom_log_file="test_log.log",
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests",
        },
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
        cors_allow_credentials=True,
        cors_expose_headers=["X-Custom-Header"],
        cors_max_age=600,
    )


async def _flush_cloud_ip_redis_namespace() -> None:
    config = SecurityConfig(redis_url=REDIS_URL, redis_prefix=_CLOUD_IP_REDIS_PREFIX)
    redis_handler = RedisManager(config)
    await redis_handler.initialize()
    try:
        await redis_handler.delete_pattern("*")
    except Exception:
        pass
    finally:
        await redis_handler.close()


@pytest.fixture(autouse=True)
async def cloud_ip_redis_isolation(
    request: pytest.FixtureRequest,
) -> AsyncGenerator[None, None]:
    if not request.path.is_relative_to(_TEST_CLOUD_IPS_DIR):
        yield
        return
    await _flush_cloud_ip_redis_namespace()
    yield
    await _flush_cloud_ip_redis_namespace()


@pytest.fixture(autouse=True)
def _zero_straddle_overlap_by_default(
    request: pytest.FixtureRequest,
) -> Generator[Any, Any, Any]:
    if not request.path.is_relative_to(_TEST_UTILS_DIR):
        yield
        return

    async def _zero_overlap() -> int:
        return 0

    with patch.object(body_reader, "_straddle_overlap_bytes", _zero_overlap):
        yield


def _check_live_smoke_preconditions(stack_dir: Path) -> None:
    baseline = os.environ.get("LIVE_SMOKE_BASELINE")
    wheels = list((stack_dir / "wheels").glob("*.whl"))
    if not baseline and not wheels:
        pytest.fail(
            "no guard-core wheel in tests/live_smoke/stack/wheels/; run "
            "`uv build --wheel --out-dir tests/live_smoke/stack/wheels` first, "
            "or set LIVE_SMOKE_BASELINE=guard-core==X.Y.Z to test a released "
            "version instead. See `make live-smoke`.",
            pytrace=False,
        )
    if not (stack_dir / "app" / "security.py").is_file():
        pytest.fail(
            "tests/live_smoke/stack/app/ is missing; run "
            "`python tests/live_smoke/fetch_example_app.py` then "
            "`python tests/live_smoke/patch_example_config.py` first. "
            "See `make live-smoke`.",
            pytrace=False,
        )


@pytest.fixture(scope="session")
def stack() -> "Iterator[Stack]":
    from tests.live_smoke.driver import STACK_DIR, Stack

    _check_live_smoke_preconditions(STACK_DIR)
    instance = Stack()
    instance.up()
    try:
        yield instance
    finally:
        instance.down()


@pytest.fixture(scope="session")
def scenario_context(stack: "Stack") -> "Iterator[ScenarioContext]":
    from tests.live_smoke.driver import (
        ScenarioContext,
        make_agent_client,
        make_http_client,
        make_otlp_client,
        make_redis_client,
    )

    client = make_http_client()
    agent = make_agent_client()
    redis_client = make_redis_client()
    otlp = make_otlp_client()
    try:
        yield ScenarioContext(
            stack=stack, client=client, agent=agent, redis=redis_client, otlp=otlp
        )
    finally:
        client.close()
        agent.close()
        redis_client.close()
        otlp.close()


_GUARD_AGENT_FINDER_ATTR = "_guard_core_agent_import_finder"


def _calling_module_name(frame: FrameType | None) -> str | None:
    while frame is not None:
        filename = frame.f_code.co_filename
        if "importlib" not in filename and not filename.startswith("<frozen"):
            name: str | None = frame.f_globals.get("__name__")
            return name
        frame = frame.f_back
    return None


def _is_guard_core_module(name: str | None) -> bool:
    return name is not None and (name == "guard_core" or name.startswith("guard_core."))


def _guard_agent_import_is_allowed(caller: str, fullname: str) -> bool:
    if caller == "guard_core._pydantic_plugin_mute":
        return True
    return caller == "guard_core.models" and fullname == "guard_agent"


class _GuardAgentImportFinder:
    def __init__(self) -> None:
        self.violations: list[str] = []

    def find_spec(
        self, fullname: str, path: Any, target: Any = None
    ) -> ModuleSpec | None:
        if fullname == "guard_agent" or fullname.startswith("guard_agent."):
            caller = _calling_module_name(sys._getframe(1))
            if (
                caller is not None
                and _is_guard_core_module(caller)
                and not _guard_agent_import_is_allowed(caller, fullname)
            ):
                self.violations.append(f"{caller} imports {fullname}")
        return None


_MUTED_PLUGIN_SETTINGS = {"logfire": {"record": "off"}}
_TELEMETRY_MODEL_NAMES = ("SecurityEvent", "SecurityMetric", "EventBatch")


def _unmuted_guard_agent_telemetry_models() -> list[str]:
    guard_agent_module = sys.modules.get("guard_agent")
    if guard_agent_module is None:
        return []
    return [
        name
        for name in _TELEMETRY_MODEL_NAMES
        if getattr(guard_agent_module, name).model_config.get("plugin_settings")
        != _MUTED_PLUGIN_SETTINGS
    ]


def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> None:
    _TEST_NODE_DURATIONS[item.nodeid] = (
        _TEST_NODE_DURATIONS.get(item.nodeid, 0.0) + call.duration
    )


def _test_duration_offenders(ceiling: float) -> list[tuple[float, str]]:
    return sorted(
        (
            (duration, nodeid)
            for nodeid, duration in _TEST_NODE_DURATIONS.items()
            if duration > ceiling
        ),
        key=lambda offender: (-offender[0], offender[1]),
    )


def _enforce_test_duration_ceiling(session: pytest.Session) -> None:
    ceiling_raw = os.getenv(_MAX_TEST_SECONDS_ENV)
    if ceiling_raw is None:
        return
    ceiling = float(ceiling_raw)
    offenders = _test_duration_offenders(ceiling)
    if not offenders:
        return
    session.exitstatus = pytest.ExitCode.TESTS_FAILED
    print(
        f"\n{len(offenders)} test(s) exceeded the {ceiling:g}s "
        f"{_MAX_TEST_SECONDS_ENV} ceiling:"
    )
    for duration, nodeid in offenders:
        print(f"  {duration:.2f}s  {nodeid}")


def pytest_configure(config: pytest.Config) -> None:
    if getattr(sys, _GUARD_AGENT_FINDER_ATTR, None) is not None:
        return
    finder = _GuardAgentImportFinder()
    sys.meta_path.insert(0, finder)
    setattr(sys, _GUARD_AGENT_FINDER_ATTR, finder)
    from guard_core._pydantic_plugin_mute import (
        _mute_pydantic_plugin_instrumentation,
    )

    _mute_pydantic_plugin_instrumentation()


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    finder = getattr(sys, _GUARD_AGENT_FINDER_ATTR, None)
    if finder is not None:
        delattr(sys, _GUARD_AGENT_FINDER_ATTR)
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
        assert not finder.violations, (
            "guard_agent imported outside the pydantic-plugin-mute allowlist: "
            + "; ".join(finder.violations)
        )
    unmuted = _unmuted_guard_agent_telemetry_models()
    assert not unmuted, (
        "guard_agent is in sys.modules at session end but these telemetry "
        "models were never muted: " + ", ".join(unmuted)
    )
    _enforce_test_duration_ceiling(session)
