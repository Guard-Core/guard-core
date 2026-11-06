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
    "_redis_abandoned_client.py",
    "_redis_client_loop.py",
    "models.py",
    "_misconfiguration.py",
    "exceptions.py",
    "_pydantic_plugin_mute.py",
    "_security_config_validators.py",
    "_security_config_field_validators.py",
    "_security_config_batch.py",
    "_security_config_typed_validators.py",
    "_security_config_geo_validators.py",
    "_security_config_name_set_validators.py",
    "_geo_handler_for_tree.py",
    "_geo_source.py",
    "_security_config_cloud_store_validators.py",
    "_security_config_exempt_purge_validators.py",
    "_security_config_blocked_user_agents.py",
    "_config_capabilities.py",
    "_config_field_revalidators.py",
    "_security_config_fields.py",
    "_security_config_json.py",
    "_dynamic_rules.py",
    "_staged_defaults.py",
    "_tracking_caps.py",
    "_redis_enablement.py",
    "_redis_exceptions.py",
    "_security_headers_defaults.py",
    "_security_headers_override.py",
    "_security_headers_value_checks.py",
    "_security_config_assignment_checks.py",
    "_emergency_exemptions.py",
    "_callable_shape.py",
    "_security_headers_record_validation.py",
    "_builtin_import_rows.py",
    "_lazy_patterns.py",
    "_detection_constants.py",
    "_builtin_import_table.py",
    "_parked_records.py",
}

SKIP_TESTS = {
    "test_redis_close_stops_background_tasks.py",
    "test_redis_close_stops_geo_load.py",
    "test_redis_abandoned_client.py",
    "test_redis_loop_change.py",
    "redis_outage_standins.py",
    "test_redis_outage_loops.py",
    "test_fork_safety.py",
    "test_import_rows.py",
    "test_lazy_patterns.py",
    "test_models_lazy_sync_config.py",
    "test_import_surface_preserved.py",
    "mock_download.py",
    "test_field_validator_user_agent_cap.py",
    "test_geo_awaited_load_concurrency.py",
    "test_geo_handler_for_tree.py",
    "test_geo_sync_handler_in_async_engine.py",
    "test_modifier_body_replay.py",
    "test_modifier_body_pins.py",
    "test_response_path_cost.py",
    "test_scan_event_loop_yield.py",
    "test_scan_event_loop_segments.py",
    "test_async_body_read_slots.py",
    "test_dynamic_rule_user_agent_offloop.py",
    "test_dynamic_rule_atomic_swap.py",
    "test_dynamic_rule_swap_atomicity.py",
    "test_redis_prefix_isolation.py",
    "test_rate_limit_fallback_atomic.py",
    "test_cloud_fetch_one_bad_prefix.py",
    "test_enable_dynamic_rules_description.py",
    "ecosystem_gate_scripts.py",
    "test_ecosystem_gate_cap_proof.py",
    "test_ecosystem_gate_judge.py",
    "test_redis_fast_pool.py",
    "test_close_sync_client_pool.py",
    "redis_py_internals.py",
    "test_redis_fast_pool_stand_in_internals.py",
    "test_redis_lean.py",
    "test_redis_fast_path_shape.py",
    "test_per_app_sharing_by_event_loop.py",
    "test_redis_open_connection_cleanup_pins.py",
    "test_split_connection_warning_event_loop.py",
    "test_ipban_unban_inside_async.py",
    "test_ipban_atomic_version.py",
    "test_module_imports_standalone.py",
    "test_optional_extras_base_install.py",
    "test_cold_path_imports.py",
    "test_import_footprint.py",
    "test_deferred_imports.py",
    "test_suspatterns_handler_module_surface.py",
    "test_gc_per_test_opt_in.py",
    "test_maintainability_rank.py",
    "test_markdown_python_blocks.py",
    "test_any_ratchet.py",
    "test_config_docs_parity.py",
    "test_release_notes_parity.py",
    "test_readme_extras.py",
    "test_no_merge_conflict_markers.py",
    "test_modifier_replay_shape_error.py",
    "test_custom_callables_follow_the_type.py",
    "test_callables_follow_the_type_typing.py",
    "test_security_config_generic_request.py",
    "test_decorated_signature_typing.py",
    "test_request_headers_protocol_typing.py",
    "test_dynamic_rule_two_processes.py",
    "test_dynamic_rule_revoke_second_worker.py",
    "test_behavior_cap_constants.py",
    "test_nested_conftest_defines_no_fixtures.py",
    "test_event_correlation_parallel.py",
    "test_ban_attribution_cross_worker.py",
    "network_guard.py",
    "thread_guard.py",
    "test_thread_guard.py",
    "async_is_connected.py",
    "test_network_guard.py",
    "test_ruff_pin.py",
    "test_sync_fixture_guard.py",
    "test_safety_gates_corpus_consistency.py",
    "test_conformance_corpus_replay.py",
    "test_conformance_safety_replay.py",
    "test_conformance_safety_before_timing_replay.py",
    "test_fixture_generator_determinism.py",
    "test_perf_gate_rules.py",
    "test_perf_detection_components.py",
    "test_compiler_cache_loop_and_threads.py",
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
    SYNC_DIR / "handlers" / "_ipinfo_download_cut.py",
    SYNC_DIR / "py.typed",
}

HAND_MAINTAINED = {
    TEST_SYNC_DIR / "test_geo_download_cut.py",
    TEST_SYNC_DIR / "test_geo_download_setup.py",
    TEST_SYNC_DIR / "test_geo_awaited_load_threads.py",
    SYNC_DIR / "handlers" / "ratelimit_handler.py",
    SYNC_DIR / "handlers" / "_redis_fast_pool.py",
    SYNC_DIR / "handlers" / "_redis_attempt.py",
    SYNC_DIR / "handlers" / "_dynamic_rule_persistence.py",
    TEST_SYNC_DIR / "test_core" / "test_check_rate_limit_by_ip_autoban.py",
    TEST_SYNC_DIR / "test_redis_pool_timeout_threads.py",
    TEST_SYNC_DIR / "test_redis_fast_pool_threads.py",
    TEST_SYNC_DIR / "test_redis_lean_threads.py",
    TEST_SYNC_DIR / "test_redis_fast_pool_fork.py",
    TEST_SYNC_DIR / "test_redis_outage_threads.py",
    TEST_SYNC_DIR / "test_agent" / "test_ratelimit_agent_integration.py",
    TEST_SYNC_DIR / "test_rate_limit_fallback_atomic.py",
    TEST_SYNC_DIR / "test_cloud_fetch_one_bad_prefix_sync.py",
    TEST_SYNC_DIR / "test_dynamic_rule_atomicity.py",
    TEST_SYNC_DIR / "test_dynamic_rule_persistence.py",
    TEST_SYNC_DIR / "test_dynamic_rule_two_processes.py",
    TEST_SYNC_DIR / "test_dynamic_rule_revoke_second_worker.py",
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
    SYNC_DIR / "_utils" / "geo_member_call.py",
    SYNC_DIR / "core" / "callable_slot.py",
    TEST_SYNC_DIR / "test_core" / "test_custom_callables_follow_the_type.py",
    SYNC_DIR / "core" / "responses" / "modifier_body.py",
    TEST_SYNC_DIR / "test_modifier_body_lazy.py",
    TEST_SYNC_DIR / "test_response_path_cost.py",
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
    TEST_SYNC_DIR / "test_rate_limit_shared_state_threads.py",
    TEST_SYNC_DIR / "test_behavior_tracker_concurrency.py",
    TEST_SYNC_DIR / "test_sync_bypass_and_threads.py",
    TEST_SYNC_DIR / "test_core" / "test_check_rate_limit_by_ip_concurrency.py",
}

_ASYNC_SAFE_READ_SRC = (
    "_BODY_READ_SLOT_POLL_SECONDS = 0.005\n"
    "_NO_CONFIG_MAX_CONCURRENT: int | None = None\n"
    "_body_read_slots: dict[int, list[None]] = {}\n"
    "\n"
    "\n"
    "@asynccontextmanager\n"
    "async def _body_read_slot(\n"
    "    max_concurrent: int | None, timeout: float\n"
    ") -> AsyncIterator[None]:\n"
    "    if max_concurrent is None:\n"
    "        yield\n"
    "        return\n"
    "    deadline = asyncio.get_running_loop().time() + timeout\n"
    "    slots = _body_read_slots.setdefault(max_concurrent, [])\n"
    "    while len(slots) >= max_concurrent:\n"
    "        if asyncio.get_running_loop().time() >= deadline:\n"
    "            logger.warning(\n"
    '                "Body read concurrency limit reached (max_concurrent=%d); "\n'
    '                "treating the body as unavailable for detection",\n'
    "                max_concurrent,\n"
    "            )\n"
    "            raise BodyReadSlotsExhaustedError(max_concurrent)\n"
    "        await asyncio.sleep(_BODY_READ_SLOT_POLL_SECONDS)\n"
    "    slots.append(None)\n"
    "    try:\n"
    "        yield\n"
    "    finally:\n"
    "        slots.pop()\n"
    "\n"
    "\n"
    "@types.coroutine\n"
    "def _continue_started(\n"
    "    started: Generator[object, object, bytes], pending: object\n"
    ") -> Generator[object, object, bytes]:\n"
    "    while True:\n"
    "        try:\n"
    "            sent = yield pending\n"
    "        except GeneratorExit:\n"
    "            started.close()\n"
    "            raise\n"
    "        except BaseException as error:\n"
    "            try:\n"
    "                pending = started.throw(error)\n"
    "            except StopIteration as done:\n"
    "                result: bytes = done.value\n"
    "                return result\n"
    "        else:\n"
    "            try:\n"
    "                pending = started.send(sent)\n"
    "            except StopIteration as done:\n"
    "                result = done.value\n"
    "                return result\n"
    "\n"
    "\n"
    "async def _finish_started(\n"
    "    started: Generator[object, object, bytes], pending: object\n"
    ") -> bytes:\n"
    "    return await _continue_started(started, pending)\n"
    "\n"
    "\n"
    "async def _safe_read(\n"
    "    reader: Callable[[], Awaitable[bytes]],\n"
    "    timeout: float,\n"
    "    max_concurrent: int | None = None,\n"
    ") -> bytes | None:\n"
    "    if max_concurrent is None:\n"
    "        try:\n"
    "            if timeout > 0:\n"
    "                started = reader().__await__()\n"
    "                try:\n"
    "                    pending = started.send(None)\n"
    "                except StopIteration as done:\n"
    "                    # Done without waiting: no task, no timer, no loop turn.\n"
    "                    result: bytes = done.value\n"
    "                    return result\n"
    "                finish = _finish_started(started, pending)\n"
    "                return await asyncio.wait_for(finish, timeout)\n"
    "            return await asyncio.wait_for(reader(), timeout=0.0)\n"
    "        except Exception:\n"
    "            return None\n"
    "    deadline = asyncio.get_running_loop().time() + timeout\n"
    "    try:\n"
    "        async with _body_read_slot(max_concurrent, timeout):\n"
    "            remaining = max(deadline - asyncio.get_running_loop().time(), 0.0)\n"
    "            return await asyncio.wait_for(reader(), timeout=remaining)\n"
    "    except Exception:\n"
    "        return None\n"
    "\n"
)

_SYNC_SAFE_READ_REPLACEMENT = (
    "_sync_body_read_semaphores: dict[int, threading.Semaphore] = {}\n"
    "_sync_body_read_semaphores_lock = threading.Lock()\n"
    "_NO_CONFIG_MAX_CONCURRENT: int | None = _DEFAULT_BODY_READ_MAX_CONCURRENT\n"
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
    "@contextmanager\n"
    "def _body_read_slot(\n"
    "    max_concurrent: int | None, timeout: float\n"
    ") -> Iterator[None]:\n"
    "    if max_concurrent is None:\n"
    "        yield\n"
    "        return\n"
    "    semaphore = _sync_body_read_semaphore(max_concurrent)\n"
    "    if not semaphore.acquire(timeout=max(timeout, 0.0)):\n"
    "        logger.warning(\n"
    '            "Sync body read concurrency limit reached (max_concurrent=%d); "\n'
    '            "treating the body as unavailable for detection",\n'
    "            max_concurrent,\n"
    "        )\n"
    "        raise BodyReadSlotsExhaustedError(max_concurrent)\n"
    "    try:\n"
    "        yield\n"
    "    finally:\n"
    "        semaphore.release()\n"
    "\n"
    "\n"
    "def _safe_read(\n"
    "    reader: Callable[[], bytes],\n"
    "    timeout: float,\n"
    "    max_concurrent: int | None = None,\n"
    ") -> bytes | None:\n"
    "    try:\n"
    "        if max_concurrent is None:\n"
    "            return reader()\n"
    "        with _body_read_slot(max_concurrent, timeout):\n"
    "            return reader()\n"
    "    except Exception:\n"
    "        return None\n"
)

_ASYNC_AWAIT_REGEX_FUTURE_SRC = (
    "async def _await_regex_future(\n"
    "    future: concurrent.futures.Future[_Result],\n"
    "    started: list[float],\n"
    "    timeout: float,\n"
    "    backstop: float | None = None,\n"
    ") -> _Result:\n"
    "    try:\n"
    "        return await asyncio.wait_for("
    "asyncio.wrap_future(future), timeout=timeout)\n"
    "    except asyncio.TimeoutError as exc:\n"
    "        # 3.10 wrap_future turns a future's own concurrent TimeoutError into\n"
    "        # asyncio.TimeoutError, so read a finished future for its own outcome.\n"
    "        if future.done() and not future.cancelled():\n"
    "            return future.result()\n"
    "        left = _run_budget_left(future, started, timeout, exc, backstop)\n"
    "    try:\n"
    "        return await asyncio.wait_for("
    "asyncio.wrap_future(future), timeout=left)\n"
    "    except asyncio.TimeoutError as exc:\n"
    "        raise concurrent.futures.TimeoutError() from exc\n"
)

_SYNC_AWAIT_REGEX_FUTURE_REPLACEMENT = (
    "def _await_regex_future(\n"
    "    future: concurrent.futures.Future[_Result],\n"
    "    started: list[float],\n"
    "    timeout: float,\n"
    "    backstop: float | None = None,\n"
    ") -> _Result:\n"
    "    return wait_for_regex_run(future, started, timeout, backstop)\n"
)

_ASYNC_CURRENT_SCOPE_SRC = (
    "def current_scope() -> object:\n"
    "    import asyncio\n"
    "\n"
    "    return asyncio.get_running_loop()\n"
    "\n"
    "\n"
    "def current_scope_or_none() -> object | None:\n"
    "    import asyncio\n"
    "\n"
    "    try:\n"
    "        return asyncio.get_running_loop()\n"
    "    except RuntimeError:\n"
    "        return None\n"
)

_SYNC_CURRENT_SCOPE_REPLACEMENT = (
    "class _ProcessScope:\n"
    "    pass\n"
    "\n"
    "\n"
    "_PROCESS_SCOPE = _ProcessScope()\n"
    "\n"
    "\n"
    "def current_scope() -> object:\n"
    "    return _PROCESS_SCOPE\n"
    "\n"
    "\n"
    "def current_scope_or_none() -> object | None:\n"
    "    return _PROCESS_SCOPE\n"
)

_ASYNC_STOP_TASK_SRC = (
    "async def stop_task_on_its_own_loop(task: asyncio.Task[None] | None) -> None:\n"
    "    if task is None or task.done() or task.get_loop() is not "
    "asyncio.get_running_loop():\n"
    "        return\n"
    "    task.cancel()\n"
    "    await asyncio.gather(task, return_exceptions=True)\n"
)

_SYNC_STOP_TASK_REPLACEMENT = (
    "def stop_task_on_its_own_loop(task: threading.Thread | None) -> None:\n"
    "    return None\n"
)

_ASYNC_YIELD_SRC = (
    "async def _yield_to_event_loop() -> None:\n    await asyncio.sleep(0)\n"
)

_SYNC_YIELD_REPLACEMENT = "def _yield_to_event_loop() -> None:\n    return None\n"

_ASYNC_START_OR_JOIN_LOAD_SRC = (
    "    _load_loop: asyncio.AbstractEventLoop | None = None\n"
    "\n"
    "    def _start_or_join_load(\n"
    "        self, work: Callable[[], Awaitable[None]]\n"
    "    ) -> asyncio.Task[None]:\n"
    "        loop = asyncio.get_running_loop()\n"
    "        task = self._background_task\n"
    "        if task is not None and not task.done() and self._load_loop is loop:\n"
    "            return task\n"
    "        self._load_loop = loop\n"
    "        self._background_in_flight = True\n"
    "        self._background_task = asyncio.create_task("
    "self._load_in_background(work))\n"
    "        return self._background_task\n"
    "\n"
    "    async def _stop_background_load(self) -> None:\n"
    "        task = self._background_task\n"
    "        if (\n"
    "            task is None\n"
    "            or task.done()\n"
    "            or self._load_loop is not asyncio.get_running_loop()\n"
    "        ):\n"
    "            return\n"
    "        self._load_stopped_by_close = task\n"
    "        task.cancel()\n"
    "        await asyncio.gather(task, return_exceptions=True)\n"
    "\n"
    '    _load_stopped_by_close: "asyncio.Task[None] | None" = None\n'
    "\n"
    '    async def _wait_for_load(self, load: "asyncio.Task[None]") -> None:\n'
    "        try:\n"
    "            await asyncio.shield(load)\n"
    "        except asyncio.CancelledError:\n"
    "            # shield cancels its outer future with the inner task; a\n"
    "            # waiter whose own task is not being cancelled sees a failed load.\n"
    "            if load is not self._load_stopped_by_close or not load.cancelled():\n"
    "                raise\n"
    '            self._last_load_error = "GeoIP load stopped because Redis closed"\n'
)

_SYNC_START_OR_JOIN_LOAD_REPLACEMENT = (
    "    _load_lock = threading.Lock()\n"
    "\n"
    "    def _start_or_join_load(self, work: Callable[[], None]) -> threading.Thread:\n"
    "        with self._load_lock:\n"
    "            running = self._background_task\n"
    "            if running is not None and running.is_alive():\n"
    "                return running\n"
    "            self._background_in_flight = True\n"
    "            self._background_task = threading.Thread(\n"
    "                target=self._load_in_background, args=(work,), daemon=True\n"
    "            )\n"
    "            self._background_task.start()\n"
    "            return self._background_task\n"
    "\n"
    "    def _stop_background_load(self) -> None:\n"
    "        return None\n"
    "\n"
    "    def _wait_for_load(self, load: threading.Thread) -> None:\n"
    "        load.join()\n"
)

_ASYNC_DOWNLOAD_BODY_SRC = (
    "    async def _download_body(\n"
    "        self,\n"
    "        session: aiohttp.ClientSession,\n"
    "        headers: dict[str, str],\n"
    "        sink: BinaryIO,\n"
    "    ) -> None:\n"
    "        import aiohttp\n"
    "\n"
    "        timeout = aiohttp.ClientTimeout(\n"
    "            sock_connect=self._download_connect_timeout,\n"
    "            sock_read=self._download_read_timeout,\n"
    "            total=self._download_total_timeout,\n"
    "        )\n"
    "        response = await session.get(\n"
    "            self._download_url, headers=headers, timeout=timeout\n"
    "        )\n"
    "        try:\n"
    "            response.raise_for_status()\n"
    "            cap = self._download_max_bytes\n"
    "            reject_declared_size(response.content_length, cap, self.logger)\n"
    "            received = 0\n"
    "            async for chunk in response.content.iter_chunked(65536):\n"
    "                received += len(chunk)\n"
    "                reject_received_size(received, cap, self.logger)\n"
    "                sink.write(chunk)\n"
    "        finally:\n"
    "            response.close()\n"
)

_SYNC_DOWNLOAD_BODY_REPLACEMENT = (
    "    def _download_body(\n"
    "        self,\n"
    "        session: requests.Session,\n"
    "        headers: dict[str, str],\n"
    "        sink: BinaryIO,\n"
    "    ) -> None:\n"
    "        from guard_core.sync.handlers._ipinfo_download_cut import (\n"
    "            DownloadCut,\n"
    "            RecordingAdapter,\n"
    "        )\n"
    "\n"
    "        cut = DownloadCut(self._download_total_timeout)\n"
    "        adapter = RecordingAdapter(cut)\n"
    '        session.mount("http://", adapter)\n'
    '        session.mount("https://", adapter)\n'
    "        deadline = time.monotonic() + self._download_total_timeout\n"
    "        cut.arm()\n"
    "        try:\n"
    "            self._read_body(session, headers, deadline, sink)\n"
    "        except Exception as error:\n"
    "            if cut.stop() or time.monotonic() >= deadline:\n"
    "                raise TimeoutError(_TOTAL_BOUND_EXCEEDED) from error\n"
    "            raise\n"
    "        if cut.stop():\n"
    "            raise TimeoutError(_TOTAL_BOUND_EXCEEDED)\n"
    "\n"
    "    def _read_body(\n"
    "        self,\n"
    "        session: requests.Session,\n"
    "        headers: dict[str, str],\n"
    "        deadline: float,\n"
    "        sink: BinaryIO,\n"
    "    ) -> None:\n"
    "        timeout = (\n"
    "            self._download_connect_timeout,\n"
    "            self._download_read_timeout,\n"
    "        )\n"
    "        with session.get(\n"
    "            self._download_url, headers=headers, timeout=timeout, stream=True\n"
    "        ) as response:\n"
    "            response.raise_for_status()\n"
    "            cap = self._download_max_bytes\n"
    '            declared = response.headers.get("Content-Length", "")\n'
    "            reject_declared_size(\n"
    "                int(declared) if declared.isdigit() else None, cap, self.logger\n"
    "            )\n"
    "            raw: HTTPResponse = response.raw\n"
    "            received = 0\n"
    "            while time.monotonic() < deadline:\n"
    "                if not (chunk := raw.read1(65536, decode_content=True)):\n"
    "                    return\n"
    "                received += len(chunk)\n"
    "                reject_received_size(received, cap, self.logger)\n"
    "                sink.write(chunk)\n"
    "        raise TimeoutError(_TOTAL_BOUND_EXCEEDED)\n"
)

SUBS: list[tuple[str, str]] = [
    (
        re.escape(_ASYNC_CURRENT_SCOPE_SRC),
        _SYNC_CURRENT_SCOPE_REPLACEMENT.replace("\\", "\\\\"),
    ),
    (
        re.escape(_ASYNC_DOWNLOAD_BODY_SRC),
        _SYNC_DOWNLOAD_BODY_REPLACEMENT.replace("\\", "\\\\"),
    ),
    (
        re.escape(_ASYNC_START_OR_JOIN_LOAD_SRC),
        _SYNC_START_OR_JOIN_LOAD_REPLACEMENT.replace("\\", "\\\\"),
    ),
    (re.escape(_ASYNC_STOP_TASK_SRC), _SYNC_STOP_TASK_REPLACEMENT),
    (r"await asyncio\.shield\((.+)\)$", r"\1.join()"),
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
        r"config\.async_body_read_max_concurrent",
        "config.sync_body_read_max_concurrent",
    ),
    (
        r"from guard_core\.protocols\.request_protocol import "
        r"GuardRequest, GuardRequestHeaders",
        "from guard_core.protocols.request_protocol import GuardRequestHeaders\n"
        "from guard_core.sync.protocols.request_protocol import SyncGuardRequest",
    ),
    (
        r"from guard_core\.protocols\.request_protocol import GuardRequest\b",
        "from guard_core.sync.protocols.request_protocol import SyncGuardRequest",
    ),
    (
        r"from guard_core\.protocols\.middleware_protocol import "
        r"GuardMiddlewareProtocol",
        "from guard_core.sync.protocols.middleware_protocol import "
        "SyncGuardMiddlewareProtocol",
    ),
    (
        r"from guard_core\.protocols\.middleware_protocol import "
        r"SecurityEventBusProtocol",
        "from guard_core.sync.protocols.middleware_protocol import "
        "SecurityEventBusProtocol",
    ),
    (
        r"from guard_core\.protocols\.agent_protocol import AgentHandlerProtocol",
        "from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol",
    ),
    (
        r"from guard_core\.protocols\.agent_protocol import "
        r"\(\n(\s+)AgentHandlerProtocol,",
        "from guard_core.sync.protocols.agent_protocol import (\n"
        r"\1SyncAgentHandlerProtocol,",
    ),
    (
        r"from guard_core\.protocols\.agent_protocol import DynamicRulesProtocol",
        "from guard_core.sync.protocols.agent_protocol import DynamicRulesProtocol",
    ),
    (
        r"from guard_core\.protocols\.redis_protocol import RedisHandlerProtocol",
        "from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol",
    ),
    (
        r"from guard_core\.protocols\.redis_protocol import "
        r"SecurityHeadersRedisHandler",
        "from guard_core.sync.protocols.redis_protocol import "
        "SyncSecurityHeadersRedisHandler",
    ),
    (
        r"from guard_core\._geo_handler_for_tree import GeoIPHandlerOfThisTree",
        "from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler",
    ),
    (r"(?<!\w)GeoIPHandlerOfThisTree\b", "SyncGeoIPHandler"),
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
    (
        r"^(\s*from guard_core\.models import .*\bSecurityConfig\b.*)$",
        r"\1, SyncSecurityConfig",
    ),
    (r"^    SecurityConfig,$", "    SecurityConfig,\n    SyncSecurityConfig,"),
    (r'"SecurityConfig"', '"SyncSecurityConfig"'),
    (r'"SecurityConfig \| ', '"SyncSecurityConfig | '),
    (r"(?<=: )SecurityConfig(?![\w\[(.])", "SyncSecurityConfig"),
    (r"(?<=-> )SecurityConfig(?![\w\[(.])", "SyncSecurityConfig"),
    (r"(?<=\| )SecurityConfig(?![\w\[(.])", "SyncSecurityConfig"),
    (r"(?<=\[)SecurityConfig(?=[\],])", "SyncSecurityConfig"),
    (r"^(?!.*\bimport\b)(.*?, )SecurityConfig(?=[\],])", r"\1SyncSecurityConfig"),
    (r"^(?!.*\bimport\b)(.*?, )SecurityConfig(?=[\],])", r"\1SyncSecurityConfig"),
    (r"(?<=cast\()SecurityConfig(?=,)", "SyncSecurityConfig"),
    (r"(_?cast\(\n\s+)SecurityConfig,", r"\1SyncSecurityConfig,"),
    (r"(class \w+\()SecurityConfig\)", r"\1SyncSecurityConfig)"),
    (r"(?<!Sync)(?<!\w)GuardMiddlewareProtocol\b", "SyncGuardMiddlewareProtocol"),
    (r"(?<!Sync)(?<!\w)AgentHandlerProtocol\b", "SyncAgentHandlerProtocol"),
    (r"(?<!Sync)(?<!\w)RedisHandlerProtocol\b", "SyncRedisHandlerProtocol"),
    (
        r"(?<!Sync)(?<!\w)SecurityHeadersRedisHandler\b",
        "SyncSecurityHeadersRedisHandler",
    ),
    (r"(?<!Sync)(?<!\w)GuardRequest\b", "SyncGuardRequest"),
    (r"(?<!Sync)(?<!\w)GeoIPHandler\b", "SyncGeoIPHandler"),
    (r"(?<!Sync)(?<!\w)CloudIpStoreProtocol\b", "SyncCloudIpStoreProtocol"),
    (r"(?<!Sync)(?<!\w)CloudIpStoreFactory\b", "SyncCloudIpStoreFactory"),
    (r"from redis\.asyncio import Redis", "from redis import Redis"),
    (r"redis\.asyncio", "redis"),
    (
        r"from __future__ import annotations\n\nimport logging\n"
        r"from typing import TYPE_CHECKING, BinaryIO\n\n"
        r"from guard_core\.sync\.handlers\._ipinfo_download_cap import \(\n"
        r"    reject_declared_size,\n    reject_received_size,\n\)\n\n"
        r"if TYPE_CHECKING:\n    import aiohttp\n\n\n"
        r"class IpInfoDownloadMixin",
        "from __future__ import annotations\n\nimport logging\nimport time\n"
        "from typing import TYPE_CHECKING, BinaryIO\n\n"
        "from guard_core.sync.handlers._ipinfo_download_cap import (\n"
        "    reject_declared_size,\n"
        "    reject_received_size,\n"
        ")\n\n"
        "if TYPE_CHECKING:\n"
        "    import requests\n"
        "    from urllib3.response import HTTPResponse\n\n"
        '_TOTAL_BOUND_EXCEEDED = "GeoIP download exceeded the total time bound"\n\n\n'
        "class IpInfoDownloadMixin",
    ),
    (r"import aiohttp", "import requests"),
    (r'TREE_DOWNLOADER = "aiohttp"', 'TREE_DOWNLOADER = "requests"'),
    (r"TREE_AWAITS: Final = True", "TREE_AWAITS: Final = False"),
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
    (r"asyncio\.run\((main\(.*\))\)$", r"\1"),
    (r"asyncio\.sleep", "time.sleep"),
    (
        r"asyncio\.to_thread\(\s*([^,\n]+),\s*([^)\n]+?)\s*\)",
        r"\1(\2)",
    ),
    (
        r"asyncio\.create_task\(self\.(\w+)\(",
        r"threading.Thread(target=self.\1, args=(",
    ),
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
    (r"\babandon_client\b", "close_sync_client"),
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
    (
        r"from tests\.test_dynamic_rule_revoke_owned_only import",
        "from tests.test_sync.test_dynamic_rule_revoke_owned_only import",
    ),
    (
        r"from tests\.test_event_attribution import",
        "from tests.test_sync.test_event_attribution import",
    ),
    (
        r"from tests\.fake_agent import",
        "from tests.test_sync.fake_agent import",
    ),
    (
        r"from tests\.ipban_redis_fake import",
        "from tests.test_sync.ipban_redis_fake import",
    ),
    (
        r"from tests\.protocol_only_redis import",
        "from tests.test_sync.protocol_only_redis import",
    ),
    (
        r'"from guard_core\.models import SecurityConfig\\n"',
        r'"from guard_core.models import SecurityConfig, SyncSecurityConfig\\n"',
    ),
    (r"(?<!\w)SecurityConfig\(", "SyncSecurityConfig("),
    (
        r"(?<!\w)SecurityConfig\.model_construct\(",
        "SyncSecurityConfig.model_construct(",
    ),
    (
        r"from tests\.engine_redis_commands import",
        "from tests.test_sync.engine_redis_commands import",
    ),
    (r"\bMockGuardRequest\b", "SyncMockGuardRequest"),
    (r"AsyncMock, MagicMock", "MagicMock"),
    (r"MagicMock, AsyncMock", "MagicMock"),
    (r"AsyncMock", "MagicMock"),
    (r", new_callable=MagicMock", ""),
    (r"(mock_\w+)\.text = MagicMock\(return_value=(.+)\)", r"\1.text = \2"),
    (r"from tests\.mock_download import streamed\n", ""),
    (r"^TWO_LAYER_OUTCOME = ValueError$", "TWO_LAYER_OUTCOME = TimeoutError"),
    (
        r"^(\s*)(mock_\w+)\.content_length = None\n"
        r"\s*\2\.content\.iter_chunked = streamed\((.+)\)$",
        r"\1\2.headers = {}\n"
        r"\1\2.__enter__ = MagicMock(return_value=\2)\n"
        r"\1\2.__exit__ = MagicMock(return_value=None)\n"
        r"\1\2.raw.read1 = MagicMock(side_effect=[\3, bytes()])",
    ),
    (
        r"^(\s*)(mock_\w+)\.read = MagicMock\(return_value=(.+)\)$",
        r"\1\2.content = \3\n"
        r"\1\2.__enter__ = MagicMock(return_value=\2)\n"
        r"\1\2.__exit__ = MagicMock(return_value=None)\n"
        r"\1\2.raw.read1 = MagicMock(side_effect=[\3, bytes()])",
    ),
    (r"new_callable=MagicMock,\s*", ""),
    (r"@pytest\.mark\.asyncio\n", ""),
    (r"\.assert_awaited_once_with\(", ".assert_called_once_with("),
    (r"\.assert_awaited_once\(\)", ".assert_called_once()"),
    (r"\.assert_awaited\(\)", ".assert_called()"),
    (r"\.assert_not_awaited\(\)", ".assert_not_called()"),
    (r"\.assert_awaited_with\(", ".assert_called_with("),
    (r"\.assert_any_await\(", ".assert_any_call("),
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
    "typing_fixtures",
    "wordlists",
}


def apply_subs(content: str, subs: list[tuple[str, str]]) -> str:
    for pattern, replacement in subs:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
    return content


POST_FIXUPS: list[tuple[str, str]] = [
    (
        r"            except Exception:\n                self\.logger\.info"
        r"\(\"Dynamic rule update loop cancelled\"\)\n                break\n         "
        r"   except Exception as e:",
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
        r"            try:\n                self\.update_task\n            except "
        r"Exception:\n                pass",
        "            pass",
    ),
]

DOTALL_FIXUPS: list[tuple[str, str]] = [
    (
        r"pass\n\n(\s+)coro = (self\._send_geo_event\(.+?\))\n\s+try:\n\s+coro\n"
        r"\s+except Exception:\n\s+coro\.close\(\)",
        r"\2",
    ),
    (
        r"([ \t]+)self\.update_task = threading\.Thread"
        r"\(target=self\._rule_update_loop, args=\(\)\)\n\1self\.logger\.info",
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
        r"def handle_security_bypass\(\n\s+self,\n\s+request: SyncGuardRequest,\n"
        r"\s+call_next: Callable\[\[SyncGuardRequest\], GuardResponse\],\n"
        r"\s+route_config: RouteConfig \| None,",
        "def handle_security_bypass(\n"
        "        self,\n"
        "        request: SyncGuardRequest,\n"
        "        call_next: Callable[[SyncGuardRequest], GuardResponse] | None = None,"
        "\n"
        "        route_config: RouteConfig | None = None,",
    ),
    (
        r"response = call_next\(request\)\n\s+response = "
        r"self\.context\.response_factory\.apply_security_headers\(\n\s+response, str"
        r"\(request\.url_path\)\n\s+\)\n\s+return "
        r"self\.context\.response_factory\.apply_modifier\(response, request\)",
        "if call_next is None:\n"
        "            return None\n"
        "        response = call_next(request)\n"
        "        response = self.context.response_factory.apply_security_headers(\n"
        "            response, str(request.url_path)\n"
        "        )\n"
        "        return self.context.response_factory.apply_modifier(\n"
        "            response, request\n"
        "        )",
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


RUFF_PIN_PATTERN = re.compile(r'"ruff==([0-9][^"]*)"')


def pinned_ruff_version() -> str:
    match = RUFF_PIN_PATTERN.search((ROOT / "pyproject.toml").read_text())
    if match is None:
        raise SystemExit('pyproject.toml has no exact "ruff==<version>" pin')
    return match.group(1)


# The interpreter's own ruff, not `uv run ruff`: a `uv run` here re-syncs (and,
# with another Python than the project's, recreates) the environment the caller
# is running in, which broke the tests that run this script (WP23 r6).
def run_ruff(*args: str) -> str:
    import subprocess

    completed = subprocess.run(
        [sys.executable, "-m", "ruff", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(
            f"ruff {' '.join(args)} failed with exit code {completed.returncode}"
            " (install the pinned ruff with: uv sync --extra dev)\n"
            f"{completed.stdout}{completed.stderr}"
        )
    return completed.stdout


def format_generated(
    sync_dir: Path = SYNC_DIR, test_sync_dir: Path = TEST_SYNC_DIR
) -> None:
    pinned = pinned_ruff_version()
    version = run_ruff("--version").strip()
    if version != f"ruff {pinned}":
        raise SystemExit(
            f"pyproject.toml pins ruff=={pinned} but this interpreter has '{version}'"
            " (install the pinned ruff with: uv sync --extra dev)"
        )
    targets = [str(sync_dir), str(test_sync_dir)]
    run_ruff("check", "--fix-only", "--quiet", *targets)
    run_ruff("format", "--quiet", *targets)
    run_ruff("check", "--quiet", *targets)


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
