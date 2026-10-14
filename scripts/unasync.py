#!/usr/bin/env python3
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT / "guard_core"
SYNC_DIR = ROOT / "guard_core" / "sync"
TEST_DIR = ROOT / "tests"
TEST_SYNC_DIR = ROOT / "tests" / "test_sync"

CHECK_TMP_PREFIX = ".unasync_check_tmp_"

SKIP_SRC = {
    "models.py",
    "exceptions.py",
    "_pydantic_plugin_mute.py",
    "_security_config_validators.py",
    "_security_config_field_validators.py",
    "_security_config_typed_validators.py",
    "_security_config_geo_validators.py",
    "_config_capabilities.py",
    "_config_field_revalidators.py",
    "_security_config_fields.py",
    "_dynamic_rules.py",
}

SKIP_TESTS = {
    "test_scan_event_loop_yield.py",
    "test_module_imports_standalone.py",
    "test_suspatterns_handler_module_surface.py",
    "test_gc_per_test_opt_in.py",
    "test_maintainability_rank.py",
    "test_config_docs_parity.py",
    "test_nested_conftest_defines_no_fixtures.py",
}

SKIP_DIRS = {"__pycache__", "sync"}

TEMPLATE_FILES = {
    SYNC_DIR / "__init__.py",
    SYNC_DIR / "protocols" / "__init__.py",
    SYNC_DIR / "protocols" / "response_protocol.py",
    SYNC_DIR / "protocols" / "middleware_protocol.py",
    SYNC_DIR / "protocols" / "request_protocol.py",
    SYNC_DIR / "protocols" / "agent_protocol.py",
    SYNC_DIR / "protocols" / "geo_ip_protocol.py",
    SYNC_DIR / "protocols" / "redis_protocol.py",
    SYNC_DIR / "py.typed",
}

HAND_MAINTAINED = {
    SYNC_DIR / "handlers" / "ratelimit_handler.py",
    SYNC_DIR / "handlers" / "_dynamic_rule_persistence.py",
    TEST_SYNC_DIR / "test_core" / "test_check_rate_limit_by_ip_autoban.py",
    TEST_SYNC_DIR / "test_agent" / "test_ratelimit_agent_integration.py",
    TEST_SYNC_DIR / "test_dynamic_rule_atomicity.py",
    TEST_SYNC_DIR / "test_dynamic_rule_persistence.py",
    TEST_SYNC_DIR / "test_cloud_ips" / "test_nonblocking_refresh.py",
    TEST_SYNC_DIR / "test_detection" / "test_builtin_pattern_safety.py",
    TEST_SYNC_DIR / "test_detection" / "test_builtin_redos_protection.py",
    TEST_SYNC_DIR / "test_core" / "test_suspicious_counts_concurrency.py",
    TEST_SYNC_DIR / "test_cloud_ips" / "test_azure_redirect_real_sockets.py",
    TEST_SYNC_DIR / "test_sus_patterns" / "test_concurrent_redos_throughput.py",
    TEST_SYNC_DIR / "test_sus_patterns" / "test_monitor_concurrency.py",
    TEST_SYNC_DIR
    / "test_sus_patterns"
    / "test_file_upload_decoded_truncation_body_scan.py",
    TEST_SYNC_DIR / "test_utils" / "test_bounded_thread_body_read.py",
    SYNC_DIR / "core" / "checks" / "_verifier.py",
    SYNC_DIR / "_utils" / "block_events.py",
    TEST_SYNC_DIR / "test_core" / "test_verifier_sync_rejection.py",
    TEST_SYNC_DIR / "test_utils" / "test_block_events_sync_rejection.py",
    TEST_SYNC_DIR / "test_core" / "test_auth_verifier_sync_async_rejection.py",
    TEST_SYNC_DIR / "conftest.py",
    TEST_SYNC_DIR / "test_sus_patterns" / "test_sus_patterns.py",
    TEST_SYNC_DIR / "test_otel_handler_provider_lifecycle.py",
    TEST_SYNC_DIR / "test_logfire_handler_provider_lifecycle.py",
    TEST_SYNC_DIR / "test_isolation_hooks_ordering.py",
    TEST_SYNC_DIR / "test_ratelimit_concurrency.py",
    TEST_SYNC_DIR / "test_behavior_tracker_concurrency.py",
    TEST_SYNC_DIR / "test_sync_bypass_and_threads.py",
    TEST_SYNC_DIR / "test_core" / "test_check_rate_limit_by_ip_concurrency.py",
}

_ASYNC_SAFE_READ_SRC = (
    "async def _safe_read(\n"
    "    reader: Callable[[], Awaitable[bytes]],\n"
    "    timeout: float,\n"
    "    max_concurrent: int = _DEFAULT_BODY_READ_MAX_CONCURRENT,\n"
    ") -> bytes | None:\n"
    "    try:\n"
    "        return await asyncio.wait_for(reader(), timeout=timeout)\n"
    "    except Exception:\n"
    "        return None\n"
)

_SYNC_SAFE_READ_REPLACEMENT = (
    "_sync_body_read_semaphores: dict[int, threading.Semaphore] = {}\n"
    "_sync_body_read_semaphores_lock = threading.Lock()\n"
    "\n"
    "\n"
    "def _sync_body_read_semaphore(max_concurrent: int) -> threading.Semaphore:\n"
    "    with _sync_body_read_semaphores_lock:\n"
    "        semaphore = _sync_body_read_semaphores.get(max_concurrent)\n"
    "        if semaphore is None:\n"
    "            semaphore = threading.Semaphore(max_concurrent)\n"
    "            _sync_body_read_semaphores[max_concurrent] = semaphore\n"
    "        return semaphore\n"
    "\n"
    "\n"
    "def _safe_read(\n"
    "    reader: Callable[[], bytes],\n"
    "    timeout: float,\n"
    "    max_concurrent: int = _DEFAULT_BODY_READ_MAX_CONCURRENT,\n"
    ") -> bytes | None:\n"
    "    deadline = time.monotonic() + timeout\n"
    "    semaphore = _sync_body_read_semaphore(max_concurrent)\n"
    "\n"
    "    if not semaphore.acquire(timeout=max(deadline - time.monotonic(), 0.0)):\n"
    "        logger.warning(\n"
    '            "Sync body read concurrency limit reached (max_concurrent=%d); "\n'
    '            "treating the body as unavailable for detection",\n'
    "            max_concurrent,\n"
    "        )\n"
    "        return None\n"
    "\n"
    "    result: bytes | None = None\n"
    "    failed = False\n"
    "\n"
    "    def _run() -> None:\n"
    "        nonlocal result, failed\n"
    "        try:\n"
    "            result = reader()\n"
    "        except Exception:\n"
    "            failed = True\n"
    "        finally:\n"
    "            semaphore.release()\n"
    "\n"
    '    thread = threading.Thread(target=_run, name="guard-body-read", daemon=True)\n'
    "    thread.start()\n"
    "    thread.join(timeout=max(deadline - time.monotonic(), 0.0))\n"
    "\n"
    "    if thread.is_alive() or failed:\n"
    "        return None\n"
    "    return result\n"
)

_ASYNC_AWAIT_REGEX_FUTURE_SRC = (
    "async def _await_regex_future(\n"
    "    future: concurrent.futures.Future[Any], timeout: float\n"
    ") -> Any:\n"
    "    try:\n"
    "        return await asyncio.wait_for("
    "asyncio.wrap_future(future), timeout=timeout)\n"
    "    except asyncio.TimeoutError as exc:\n"
    "        raise concurrent.futures.TimeoutError() from exc\n"
)

_SYNC_AWAIT_REGEX_FUTURE_REPLACEMENT = (
    "def _await_regex_future(\n"
    "    future: concurrent.futures.Future[Any], timeout: float\n"
    ") -> Any:\n"
    "    return future.result(timeout=timeout)\n"
)

_ASYNC_YIELD_SRC = (
    "async def _yield_to_event_loop() -> None:\n    await asyncio.sleep(0)\n"
)

_SYNC_YIELD_REPLACEMENT = "def _yield_to_event_loop() -> None:\n    return None\n"

SUBS: list[tuple[str, str]] = [
    (re.escape(_ASYNC_YIELD_SRC), _SYNC_YIELD_REPLACEMENT),
    (
        re.escape(_ASYNC_AWAIT_REGEX_FUTURE_SRC),
        _SYNC_AWAIT_REGEX_FUTURE_REPLACEMENT.replace("\\", "\\\\"),
    ),
    (
        re.escape(_ASYNC_SAFE_READ_SRC),
        _SYNC_SAFE_READ_REPLACEMENT.replace("\\", "\\\\"),
    ),
    (
        r"from guard_core\.protocols\.request_protocol import GuardRequest",
        "from guard_core.sync.protocols.request_protocol import SyncGuardRequest",
    ),
    (
        r"from guard_core\.protocols\.middleware_protocol import GuardMiddlewareProtocol",  # noqa: E501
        "from guard_core.sync.protocols.middleware_protocol import SyncGuardMiddlewareProtocol",  # noqa: E501
    ),  # noqa: E501
    (
        r"from guard_core\.protocols\.agent_protocol import AgentHandlerProtocol",
        "from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol",
    ),
    (
        r"from guard_core\.protocols\.redis_protocol import RedisHandlerProtocol",
        "from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol",
    ),
    (
        r"from guard_core\.protocols\.geo_ip_protocol import GeoIPHandler",
        "from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler",
    ),
    (
        r"from guard_core\.protocols\.cloud_ip_store_protocol "
        r"import CloudIpStoreProtocol",
        "from guard_core.sync.protocols.cloud_ip_store_protocol "
        "import SyncCloudIpStoreProtocol",
    ),
    (
        r"from guard_core\.protocols\.cloud_ip_store_protocol "
        r"import CloudIpStoreFactory",
        "from guard_core.sync.protocols.cloud_ip_store_protocol "
        "import SyncCloudIpStoreFactory",
    ),
    (r"from guard_core\.handlers", "from guard_core.sync.handlers"),
    (r"from guard_core\._utils\.", "from guard_core.sync._utils."),
    (r"from guard_core\._utils import", "from guard_core.sync._utils import"),
    (r"from guard_core\.utils", "from guard_core.sync.utils"),
    (r"from guard_core import utils\b", "from guard_core.sync import utils"),
    (r"from guard_core\.core\.", "from guard_core.sync.core."),
    (r"from guard_core\.detection_engine\b", "from guard_core.sync.detection_engine"),
    (r"from guard_core\.detection_result\b", "from guard_core.sync.detection_result"),
    (r"from guard_core\.decorators\b", "from guard_core.sync.decorators"),
    (r"(?<!Sync)(?<!\w)GuardMiddlewareProtocol\b", "SyncGuardMiddlewareProtocol"),
    (r"(?<!Sync)(?<!\w)AgentHandlerProtocol\b", "SyncAgentHandlerProtocol"),
    (r"(?<!Sync)(?<!\w)RedisHandlerProtocol\b", "SyncRedisHandlerProtocol"),
    (r"(?<!Sync)(?<!\w)GuardRequest\b", "SyncGuardRequest"),
    (r"(?<!Sync)(?<!\w)GeoIPHandler\b", "SyncGeoIPHandler"),
    (r"(?<!Sync)(?<!\w)CloudIpStoreProtocol\b", "SyncCloudIpStoreProtocol"),
    (r"(?<!Sync)(?<!\w)CloudIpStoreFactory\b", "SyncCloudIpStoreFactory"),
    (r"from redis\.asyncio import Redis", "from redis import Redis"),
    (r"redis\.asyncio", "redis"),
    (r"import aiohttp", "import requests"),
    (r"aiohttp\.ClientSession\(\)", "requests.Session()"),
    (r"aiohttp\.ClientSession", "requests.Session"),
    (r"aiohttp\.ClientTimeout\(total=(\w+)\)", r"\1"),
    (r"await response\.read\(\)", "response.content"),
    (r"await response\.text\(\)", "response.text"),
    (r"await response\.json\(content_type=None\)", "response.json()"),
    (r"await response\.json\(\)", "response.json()"),
    (r"response\.status(?!_code)", "response.status_code"),
    (r"async def ", "def "),
    (r"async with ", "with "),
    (r"async for ", "for "),
    (r"await ", ""),
    (r"AsyncIterator", "Iterator"),
    (r"AsyncGenerator", "Generator"),
    (r"from collections\.abc import Awaitable, ", "from collections.abc import "),
    (r"from collections\.abc import Awaitable\n", ""),
    (r"Awaitable\[([^\]]+)\]", r"\1"),
    (r",\s*Awaitable\b", ""),
    (r"asynccontextmanager", "contextmanager"),
    (r"AsyncContextManager", "ContextManager"),
    (r"^import asyncio$", "import threading\nimport time"),
    (r"(\s+)import asyncio$", r"\1pass"),
    (r"asyncio\.Lock\b", "threading.Lock"),
    (r"asyncio\.Event\b", "threading.Event"),
    (r"asyncio\.sleep", "time.sleep"),
    (
        r"asyncio\.to_thread\(\s*([^,\n]+),\s*([^)\n]+?)\s*\)",
        r"\1(\2)",
    ),
    (
        r"asyncio\.create_task\(self\.(\w+)\(",
        r"threading.Thread(target=self.\1, args=(",
    ),  # noqa: E501
    (
        r"(\s+)([\w.]+) = asyncio\.create_task\((\w+)\.(\w+)\(\)\)",
        r"\1\2 = threading.Thread(target=\3.\4, daemon=True)\n\1\2.start()",
    ),
    (
        r"(\s+)([\w.]+) = asyncio\.create_task\((\w+)\(\)\)",
        r"\1\2 = threading.Thread(target=\3, daemon=True)\n\1\2.start()",
    ),
    (r"asyncio\.create_task\((\w+)\)", r"\1"),
    (r"asyncio\.Task\[[^\]]+\]", "threading.Thread"),
    (r"asyncio\.Task", "threading.Thread"),
    (r"asyncio\.CancelledError", "Exception"),
    (r"asyncio\.gather\(\*(\w+)\)", r"[t() for t in \1]"),
    (r"asyncio\.gather\(", "list(("),
    (
        r"await asyncio\.wait_for\(([^,]+),\s*timeout=([^\)]+)\)",
        r"\1.join(timeout=\2)",
    ),
    (
        r"asyncio\.wait_for\(([^,]+),\s*timeout=([^\)]+)\)",
        r"\1.join(timeout=\2)",
    ),
    (r"__aenter__", "__enter__"),
    (r"__aexit__", "__exit__"),
    (r"__aiter__", "__iter__"),
    (r"\.aclose\b", ".close"),
    (r'"guard_core\.handlers\.', '"guard_core.sync.handlers.'),
    (r'"guard_core\.core\.', '"guard_core.sync.core.'),
    (r'"guard_core\._utils\.', '"guard_core.sync._utils.'),
    (r'"guard_core\.utils', '"guard_core.sync.utils'),
    (r'"guard_core\.detection_engine', '"guard_core.sync.detection_engine'),
    (r'"guard_core\.decorators"', '"guard_core.sync.decorators"'),
]

TEST_SUBS: list[tuple[str, str]] = [
    (
        r"from tests\.conftest import \(([^)]+)\)",
        r"from tests.test_sync.conftest import (\1)",
    ),
    (
        r"from tests\.conftest import MockGuardRequest",
        "from tests.test_sync.conftest import SyncMockGuardRequest",
    ),
    (
        r"from tests\.conftest import MockGuardResponse",
        "from tests.test_sync.conftest import MockGuardResponse",
    ),
    (
        r"from tests\.conftest import MockGuardResponseFactory",
        "from tests.test_sync.conftest import MockGuardResponseFactory",
    ),
    (
        r"from tests\.conftest import (\w+(?:,\s*\w+)*)",
        r"from tests.test_sync.conftest import \1",
    ),
    (
        r"from tests\.(?!test_sync\b)(\w+)\.conftest import \(([^)]+)\)",
        r"from tests.test_sync.\1.conftest import (\2)",
    ),
    (
        r"from tests\.(?!test_sync\b)(\w+)\.conftest import (\w+(?:,\s*\w+)*)",
        r"from tests.test_sync.\1.conftest import \2",
    ),
    (r"\bMockGuardRequest\b", "SyncMockGuardRequest"),
    (r"AsyncMock, MagicMock", "MagicMock"),
    (r"MagicMock, AsyncMock", "MagicMock"),
    (r"AsyncMock", "MagicMock"),
    (r", new_callable=MagicMock", ""),
    (r"(mock_\w+)\.text = MagicMock\(return_value=(.+)\)", r"\1.text = \2"),
    (r"(mock_\w+)\.read = MagicMock\(return_value=(.+)\)", r"\1.content = \2"),
    (r"new_callable=MagicMock,\s*", ""),
    (r"@pytest\.mark\.asyncio\n", ""),
    (r"\.assert_awaited_once_with\(", ".assert_called_once_with("),
    (r"\.assert_awaited_once\(\)", ".assert_called_once()"),
    (r"\.assert_awaited\(\)", ".assert_called()"),
    (r"\.assert_not_awaited\(\)", ".assert_not_called()"),
    (r"\.assert_awaited_with\(", ".assert_called_with("),
    (r"\.await_count\b", ".call_count"),
    (r"\.await_args\b", ".call_args"),
    (r"AsyncGenerator", "Generator"),
    (r"\.cancel\(\)", ".join(timeout=1)"),
    (r"\s+try:\n\s+loop_task\n\s+except Exception:\n\s+pass", ""),
    (r"\s+try:\n\s+manager\.update_task\n\s+except Exception:\n\s+pass", ""),
    (r"\n[ \t]+with contextlib\.suppress\(Exception\):\n[ \t]+task\n", "\n"),
    (r"^\s+loop_task\s*$", ""),
]

TEST_SKIP_DIRS = {
    "__pycache__",
    "test_sync",
    "attack_simulation",
    "detection_gate",
    "live_smoke",
    "redaction_gate",
}


def apply_subs(content: str, subs: list[tuple[str, str]]) -> str:
    for pattern, replacement in subs:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
    return content


POST_FIXUPS: list[tuple[str, str]] = [
    (
        r"            except Exception:\n                self\.logger\.info\(\"Dynamic rule update loop cancelled\"\)\n                break\n            except Exception as e:",  # noqa: E501
        r"            except Exception as e:",
    ),
    (
        r"                pass\n\n                coro = self\._send_geo_event\(\n"
        r"                    event_type=\"geo_lookup_failed\",\n"
        r"                    ip_address=ip,\n"
        r"                    action_taken=\"lookup_failed\",\n"
        r"                    reason=f\"Geographic lookup failed: \{str\(e\)\}\",\n"
        r"                \)\n                pass",
        "                self._send_geo_event(\n"
        '                    event_type="geo_lookup_failed",\n'
        "                    ip_address=ip,\n"
        '                    action_taken="lookup_failed",\n'
        '                    reason=f"Geographic lookup failed: {str(e)}",\n'
        "                )",
    ),
    (
        r"(\s+)list\(\(([^,]+\(\)),\s*([^,]+\(\)),\s*return_exceptions=True\)",
        r"\1\2\n\1\3",
    ),
    (
        r"            try:\n                self\.update_task\n            except Exception:\n                pass",  # noqa: E501
        "            pass",
    ),
]

DOTALL_FIXUPS: list[tuple[str, str]] = [
    (
        r"pass\n\n(\s+)coro = (self\._send_geo_event\(.+?\))\n\s+try:\n\s+coro\n\s+except Exception:\n\s+coro\.close\(\)",  # noqa: E501
        r"\2",
    ),
    (
        r"([ \t]+)self\.update_task = threading\.Thread\(target=self\._rule_update_loop, args=\(\)\)\n\1self\.logger\.info",  # noqa: E501
        "\\1self.update_task = threading.Thread(\n"
        "\\1    target=self._rule_update_loop, daemon=True\n"
        "\\1)\n"
        "\\1self.update_task.start()\n"
        "\\1self.logger.info",
    ),
    (
        r"self\._lazy_init_task = threading\.Thread\("
        r"target=self\._run_lazy_init, args=\(\)\)",
        "self._lazy_init_task = threading.Thread(\n"
        "                target=self._run_lazy_init, daemon=True\n"
        "            )\n"
        "            self._lazy_init_task.start()",
    ),
    (
        r"def handle_security_bypass\(\n\s+self,\n\s+request: SyncGuardRequest,\n\s+call_next: Callable\[\[SyncGuardRequest\], GuardResponse\],\n\s+route_config: RouteConfig \| None,",  # noqa: E501
        "def handle_security_bypass(\n"
        "        self,\n"
        "        request: SyncGuardRequest,\n"
        "        call_next: Callable[[SyncGuardRequest], GuardResponse] | None = None,\n"  # noqa: E501
        "        route_config: RouteConfig | None = None,",
    ),
    (
        r"if not self\.context\.config\.passive_mode:\n\s+response = call_next\(request\)\n\s+return self\.context\.response_factory\.apply_modifier\(response\)\n\n\s+return None",  # noqa: E501
        "if not self.context.config.passive_mode:\n"
        "            if call_next:\n"
        "                response = call_next(request)\n"
        "                return self.context.response_factory.apply_modifier(response)\n"  # noqa: E501
        "            return None\n"
        "\n"
        "        return None",
    ),
    (
        r"def stop\(self\) -> None:\n\s+if self\.update_task:\n"
        r"\s+self\._stop_event\.set\(\)\n"
        r"\s+self\.update_task\.cancel\(\)\n"
        r"\s+pass\n"
        r"\s+self\.update_task = None\n"
        r"\s+self\.logger\.info\(\"Stopped dynamic rule update loop\"\)",
        "def stop(self) -> None:\n"
        "        if self.update_task:\n"
        "            self._stop_event.set()\n"
        "            self.update_task.join(timeout=5)\n"
        "            self.update_task = None\n"
        '            self.logger.info("Stopped dynamic rule update loop")',
    ),
    (
        r"    def _interruptible_sleep\(self, timeout: float\) -> None:\n"
        r"        try:\n"
        r"            self\._stop_event\.wait\(\)\.join\(timeout=timeout\)\n"
        r"        except asyncio\.TimeoutError:\n"
        r"            pass",
        "    def _interruptible_sleep(self, timeout: float) -> None:\n"
        "        self._stop_event.wait(timeout=timeout)",
    ),
]


def transform_source(content: str) -> str:
    content = apply_subs(content, SUBS)
    for pattern, replacement in POST_FIXUPS:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
    for pattern, replacement in DOTALL_FIXUPS:
        content = re.sub(pattern, replacement, content, flags=re.DOTALL)
    return content


def _skip_async_only_tests(content: str) -> str:
    lines = content.split("\n")
    result: list[str] = []
    pending_decorators: list[str] = []
    skipping = False

    for line in lines:
        stripped = line.lstrip()

        if not skipping and stripped.startswith("@"):
            pending_decorators.append(line)
            continue

        if "# async-only" in line:
            match = re.match(r"^(\s*)(?:async )?def (test_\w+)\(", line)
            if match:
                skipping = True
                pending_decorators = []
                continue

        if skipping:
            is_next_def = re.match(
                r"^(?:async )?def test_|^@pytest\.mark|^class ", line
            )
            if is_next_def:
                skipping = False
                result.append(line)
            continue

        if pending_decorators:
            result.extend(pending_decorators)
            pending_decorators = []
        result.append(line)

    return "\n".join(result)


def _dedupe_redundant_local_unittest_mock_imports(content: str) -> str:
    module_import_match = re.search(
        r"^from unittest\.mock import (.+)$", content, flags=re.MULTILINE
    )
    if module_import_match is None:
        return content
    module_names = {name.strip() for name in module_import_match.group(1).split(",")}

    def _strip_if_redundant(match: re.Match[str]) -> str:
        local_names = {name.strip() for name in match.group(1).split(",")}
        if local_names <= module_names:
            return ""
        return match.group(0)

    return re.sub(
        r"^[ \t]+from unittest\.mock import ([^\n]+)\n\n?",
        _strip_if_redundant,
        content,
        flags=re.MULTILINE,
    )


def transform_test(content: str) -> str:
    content = _skip_async_only_tests(content)
    content = apply_subs(content, SUBS)
    content = apply_subs(content, TEST_SUBS)
    content = _dedupe_redundant_local_unittest_mock_imports(content)
    for pattern, replacement in POST_FIXUPS:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
    return content


def collect_source_files() -> list[tuple[Path, Path]]:
    pairs = []
    for root, dirs, files in os.walk(SRC_DIR):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        rel = root_path.relative_to(SRC_DIR)

        for f in sorted(files):
            if not f.endswith(".py"):
                continue
            if rel == Path(".") and f in SKIP_SRC:
                continue
            if rel == Path(".") and f == "__init__.py":
                continue

            src = root_path / f
            dst = SYNC_DIR / rel / f

            if dst.resolve() in TEMPLATE_FILES:
                continue
            if dst.resolve() in HAND_MAINTAINED:
                continue

            pairs.append((src, dst))
    return pairs


def collect_test_files() -> list[tuple[Path, Path]]:
    pairs = []
    for root, dirs, files in os.walk(TEST_DIR):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if d not in TEST_SKIP_DIRS]

        rel = root_path.relative_to(TEST_DIR)

        for f in sorted(files):
            if not f.endswith(".py"):
                continue
            if rel == Path(".") and f in SKIP_TESTS:
                continue

            src = root_path / f
            dst = TEST_SYNC_DIR / rel / f
            if dst.resolve() in HAND_MAINTAINED:
                continue
            pairs.append((src, dst))
    return pairs


def collect_orphaned_sync_source_files() -> list[Path]:
    orphans = []
    for root, dirs, files in os.walk(SYNC_DIR):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        rel = root_path.relative_to(SYNC_DIR)

        for f in sorted(files):
            if not f.endswith(".py"):
                continue

            dst = root_path / f
            if dst.resolve() in TEMPLATE_FILES:
                continue
            if dst.resolve() in HAND_MAINTAINED:
                continue

            src = SRC_DIR / rel / f
            if not src.is_file():
                orphans.append(dst)
    return orphans


def collect_orphaned_sync_test_files() -> list[Path]:
    orphans = []
    for root, dirs, files in os.walk(TEST_SYNC_DIR):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if d not in TEST_SKIP_DIRS]

        rel = root_path.relative_to(TEST_SYNC_DIR)

        for f in sorted(files):
            if not f.endswith(".py"):
                continue

            dst = root_path / f
            if dst.resolve() in HAND_MAINTAINED:
                continue

            src = TEST_DIR / rel / f
            if not src.is_file():
                orphans.append(dst)
    return orphans


def generate(check: bool = False) -> bool:
    all_match = True

    for src, dst in collect_source_files():
        content = src.read_text()
        transformed = transform_source(content)

        if check:
            if dst.exists():
                existing = dst.read_text()
                if existing != transformed:
                    print(f"MISMATCH: {dst}")
                    all_match = False
            else:
                print(f"MISSING: {dst}")
                all_match = False
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(transformed)

    for src, dst in collect_test_files():
        content = src.read_text()
        transformed = transform_test(content)

        if check:
            if dst.exists():
                existing = dst.read_text()
                if existing != transformed:
                    print(f"MISMATCH: {dst}")
                    all_match = False
            else:
                print(f"MISSING: {dst}")
                all_match = False
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(transformed)

    return all_match


def format_generated(
    sync_dir: Path = SYNC_DIR, test_sync_dir: Path = TEST_SYNC_DIR
) -> None:
    import subprocess

    subprocess.run(
        [
            "uv",
            "run",
            "ruff",
            "check",
            "--fix-only",
            "--quiet",
            str(sync_dir),
            str(test_sync_dir),
        ],
        cwd=ROOT,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["uv", "run", "ruff", "format", "--quiet", str(sync_dir), str(test_sync_dir)],
        cwd=ROOT,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["uv", "run", "ruff", "check", "--quiet", str(sync_dir), str(test_sync_dir)],
        cwd=ROOT,
        capture_output=True,
        check=True,
    )


def _write_generated_tree(
    tmp_sync: Path, tmp_test: Path
) -> tuple[list[Path], list[Path]]:
    source_dsts = []
    for src, dst in collect_source_files():
        transformed = transform_source(src.read_text())
        tmp_dst = tmp_sync / dst.relative_to(SYNC_DIR)
        tmp_dst.parent.mkdir(parents=True, exist_ok=True)
        tmp_dst.write_text(transformed)
        source_dsts.append(dst)

    test_dsts = []
    for src, dst in collect_test_files():
        transformed = transform_test(src.read_text())
        tmp_dst = tmp_test / dst.relative_to(TEST_SYNC_DIR)
        tmp_dst.parent.mkdir(parents=True, exist_ok=True)
        tmp_dst.write_text(transformed)
        test_dsts.append(dst)

    return source_dsts, test_dsts


def _compare_against_generated(
    dsts: list[Path], real_root: Path, tmp_root: Path
) -> bool:
    ok = True
    for dst in dsts:
        tmp_dst = tmp_root / dst.relative_to(real_root)
        if not dst.exists():
            print(f"MISSING: {dst}")
            ok = False
        elif dst.read_text() != tmp_dst.read_text():
            print(f"CHANGED: {dst}")
            ok = False
    return ok


def _sweep_stale_check_tmp_dirs() -> None:
    import shutil

    for stale in ROOT.glob(f"{CHECK_TMP_PREFIX}*"):
        if stale.is_dir():
            shutil.rmtree(stale, ignore_errors=True)


def _make_check_tmp_dir() -> Path:
    import tempfile

    try:
        return Path(tempfile.mkdtemp(prefix=CHECK_TMP_PREFIX, dir=ROOT))
    except OSError as e:
        print(f"FAIL: cannot create a temporary directory under {ROOT}: {e}")
        sys.exit(1)


def _report_orphans() -> bool:
    ok = True
    for dst in collect_orphaned_sync_source_files():
        print(f"ORPHAN: {dst}")
        ok = False
    for dst in collect_orphaned_sync_test_files():
        print(f"ORPHAN: {dst}")
        ok = False
    return ok


def run_check() -> bool:
    import shutil

    _sweep_stale_check_tmp_dirs()
    tmpdir = _make_check_tmp_dir()
    try:
        tmp_sync = tmpdir / "sync"
        tmp_test = tmpdir / "test_sync"
        tmp_sync.mkdir(parents=True)
        tmp_test.mkdir(parents=True)

        source_dsts, test_dsts = _write_generated_tree(tmp_sync, tmp_test)
        format_generated(sync_dir=tmp_sync, test_sync_dir=tmp_test)

        source_ok = _compare_against_generated(source_dsts, SYNC_DIR, tmp_sync)
        test_ok = _compare_against_generated(test_dsts, TEST_SYNC_DIR, tmp_test)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    orphans_ok = _report_orphans()

    return source_ok and test_ok and orphans_ok


def main() -> None:
    check = "--check" in sys.argv

    if check:
        if run_check():
            print("OK: sync code is up to date")
            sys.exit(0)
        else:
            print("FAIL: sync code is outdated")
            print("Run 'make sync' to regenerate")
            sys.exit(1)
    else:
        generate(check=False)
        format_generated()
        print("Generated sync code in guard_core/sync/ and tests/test_sync/")


if __name__ == "__main__":
    main()
