import json
import logging
import re
import threading
import time
from collections.abc import Callable, Generator, Iterator
from contextlib import AbstractContextManager, contextmanager
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.agent_protocol import JsonValue
from guard_core.sync._utils import detection_scan, scan_remainder
from guard_core.sync._utils.detection_scan import (
    _scan_time_budget_exhausted,
    _scan_value_budget,
)
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.core.events.event_types import EVENT_SUSPICIOUS_REQUEST
from guard_core.sync.detection_engine.binary_prefix import BinaryPrefix
from guard_core.sync.handlers import (
    _suspatterns_inline_matches,
    _suspatterns_lazy_rows,
    _suspatterns_literals,
    _suspatterns_regex,
)
from guard_core.sync.handlers._suspatterns_lazy_rows import PatternRow, PatternSource
from guard_core.sync.handlers._suspatterns_state import _DetectionState
from guard_core.sync.handlers.suspatterns_handler import (
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest


@pytest.fixture(autouse=True)
def _reset_suspatterns_singleton() -> Generator[None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    SusPatternsManager._instance = None
    SusPatternsManager._config = None

    yield

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


class _FakeClock:
    def __init__(self, step: float) -> None:
        self.now = 0.0
        self.step = step

    def cpu_seconds(self) -> float:
        self.now += self.step
        return self.now


@pytest.fixture
def fake_regex_clock() -> Iterator[_FakeClock]:
    clock = _FakeClock(step=1.0)
    with patch.object(detection_scan, "_thread_cpu_seconds", clock.cpu_seconds):
        yield clock


def test_field_default_and_bounds() -> None:
    assert SyncSecurityConfig().detection_max_scan_seconds == 10.0
    assert SyncSecurityConfig(detection_max_scan_seconds=0.1)
    assert SyncSecurityConfig(detection_max_scan_seconds=60.0)
    for bad in (0.0, 0.09, 60.1):
        with pytest.raises(ValidationError):
            SyncSecurityConfig(detection_max_scan_seconds=bad)


def test_budget_is_unbounded_outside_a_request() -> None:
    assert _scan_time_budget_exhausted() is False


def test_budget_tracks_recorded_time_and_resets() -> None:
    with _scan_value_budget(512, max_scan_seconds=1.0):
        assert _scan_time_budget_exhausted() is False
        detection_scan._record_scan_time(0.4)
        assert _scan_time_budget_exhausted() is False
        detection_scan._record_scan_time(0.6)
        assert _scan_time_budget_exhausted() is True
    assert _scan_time_budget_exhausted() is False
    with _scan_value_budget(512, max_scan_seconds=1.0):
        assert _scan_time_budget_exhausted() is False


def test_default_budget_does_not_flag_benign_request() -> None:
    request = SyncMockGuardRequest(
        path="/items?page=2", headers={"accept-language": "en-US,en;q=0.9"}
    )

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is False


def test_exhausted_budget_stops_scan_and_flags_request(
    fake_regex_clock: _FakeClock,
) -> None:
    request = SyncMockGuardRequest(
        path="/items", headers={"x-pad": "benign filler value"}
    )
    manager = SusPatternsManager()
    seen: list[str] = []
    real: Callable[..., tuple[dict | None, bool]] = manager._check_regex_pattern

    def counting(
        pattern: PatternSource, *args: object, **kwargs: object
    ) -> tuple[dict | None, bool]:
        seen.append(pattern.pattern)
        return real(pattern, *args, **kwargs)

    with patch.object(manager, "_check_regex_pattern", counting):
        result = detect_penetration_attempt(
            request, SyncSecurityConfig(detection_max_scan_seconds=0.1)
        )

    all_patterns = manager.get_all_compiled_patterns()
    assert result.is_threat is True
    assert "Pattern exceeded scan time budget" in result.trigger_info
    assert len(seen) < len(all_patterns)
    assert fake_regex_clock.now > 0


def test_budget_threat_is_weighted_and_reported_as_timeout(
    fake_regex_clock: _FakeClock,
) -> None:
    config = SyncSecurityConfig(detection_max_scan_seconds=0.1)
    manager = SusPatternsManager()
    manager.configure(config)

    with _scan_value_budget(512, max_scan_seconds=0.1):
        result = manager.detect("hello world", "127.0.0.1", "query_param:q")

    budget_threats = [
        t for t in result["threats"] if t["pattern"] == "scan_time_budget_exhausted"
    ]
    assert budget_threats
    assert budget_threats[0]["type"] == "pattern_timeout"
    weight = budget_threats[0]["weight"]
    assert isinstance(weight, (int, float))
    assert weight >= config.detection_threat_score_threshold
    assert "scan_time_budget_exhausted" in result["timeouts"]
    assert result["is_threat"] is True


def test_budget_is_shared_across_fields_of_one_request(
    fake_regex_clock: _FakeClock,
) -> None:
    manager = SusPatternsManager()
    manager.configure(SyncSecurityConfig(detection_max_scan_seconds=2.5))

    with _scan_value_budget(512, max_scan_seconds=2.5):
        first = manager.detect("hello", "127.0.0.1", "query_param:a")
        second = manager.detect("world", "127.0.0.1", "query_param:b")

    names = [t["pattern"] for t in first["threats"] + second["threats"]]
    assert "scan_time_budget_exhausted" in names
    assert second["is_threat"] is True


def test_fallback_check_honours_budget() -> None:
    with _scan_value_budget(512, max_scan_seconds=0.1):
        detection_scan._record_scan_time(1.0)
        detected, trigger = detection_scan._fallback_pattern_check(
            "hello", "127.0.0.1", "query_param:q"
        )

    assert detected is True
    assert "budget" in trigger


def test_fallback_check_charges_its_inline_scan_cpu(
    fake_regex_clock: _FakeClock,
) -> None:
    def inline_only(*_args: object, **_kwargs: object) -> tuple[None, bool]:
        return None, False

    with (
        patch.object(sus_patterns_handler, "_check_regex_pattern", inline_only),
        _scan_value_budget(512, max_scan_seconds=2.5),
    ):
        detected, trigger = detection_scan._fallback_pattern_check(
            "hello", "127.0.0.1", "query_param:q"
        )

    assert detected is True
    assert "budget" in trigger


def test_trigger_names_the_budget_when_it_tips_the_request(
    fake_regex_clock: _FakeClock,
) -> None:
    request = SyncMockGuardRequest(path="/items", headers={"x-pad": "select a from b"})

    result = detect_penetration_attempt(
        request, SyncSecurityConfig(detection_max_scan_seconds=0.1)
    )

    assert result.is_threat is True
    assert "Pattern exceeded scan time budget" in result.trigger_info
    assert "scan_time_budget_exhausted" in result.trigger_info


def test_threats_message_appends_the_first_later_timeout() -> None:
    regex: dict[str, JsonValue] = {"type": "regex", "pattern": "a"}
    timeout: dict[str, JsonValue] = {"type": "pattern_timeout", "pattern": "slow"}
    other: dict[str, JsonValue] = {"type": "pattern_timeout", "pattern": "later"}

    message = detection_scan._build_threats_message([regex, timeout, other])

    assert message == (
        "Value matched pattern 'a'; Pattern exceeded scan time budget: 'slow'"
    )
    assert detection_scan._build_threats_message([regex]) == (
        "Value matched pattern 'a'"
    )
    assert detection_scan._build_threats_message([timeout, regex]) == (
        "Pattern exceeded scan time budget: 'slow'"
    )


def test_wall_slow_but_cpu_cheap_scan_does_not_exhaust_the_budget() -> None:
    manager = SusPatternsManager()
    manager.configure(SyncSecurityConfig())
    real: Callable[..., tuple[dict | None, bool]] = manager._check_regex_pattern

    def slow_wall(*args: object, **kwargs: object) -> tuple[dict | None, bool]:
        time.sleep(0.01)
        return real(*args, **kwargs)

    with (
        patch.object(manager, "_check_regex_pattern", slow_wall),
        _scan_value_budget(512, max_scan_seconds=0.1),
    ):
        result = manager.detect("hello world", "127.0.0.1", "query_param:q")

    assert all(t["pattern"] != "scan_time_budget_exhausted" for t in result["threats"])
    assert result["is_threat"] is False


def test_first_scan_lazy_pattern_builds_are_not_charged_to_the_budget() -> None:
    manager = SusPatternsManager()
    manager.configure(SyncSecurityConfig())
    builtin_sources = {row[0] for row in manager._pattern_definitions}
    clock = _FakeClock(step=0.0)
    real_compile = re.compile
    real_linear_finder = _suspatterns_inline_matches.linear_path_finder

    def costly_compile(source: str, flags: int = 0) -> re.Pattern[str]:
        if source in builtin_sources:
            clock.now += 1000.0
        return real_compile(source, flags)

    def costly_linear_finder(
        pattern: re.Pattern,
    ) -> Callable[[str], Iterator[re.Match]] | None:
        clock.now += 1000.0
        return real_linear_finder(pattern)

    with (
        patch.object(detection_scan, "_thread_cpu_seconds", clock.cpu_seconds),
        patch.object(re, "compile", costly_compile),
        patch.object(
            _suspatterns_inline_matches, "linear_path_finder", costly_linear_finder
        ),
        patch.object(
            _suspatterns_regex,
            "_INLINE_FINDERS",
            _suspatterns_inline_matches._InlineFinders(),
        ),
        patch.dict(_suspatterns_lazy_rows.COMPILED_BUILTIN_PATTERNS, clear=True),
        _scan_value_budget(512, max_scan_seconds=0.1),
    ):
        result = manager.detect("hello world", "127.0.0.1", "query_param:q")

    assert clock.now >= 1000.0
    assert all(t["pattern"] != "scan_time_budget_exhausted" for t in result["threats"])
    assert result["is_threat"] is False


def test_worker_scan_cpu_is_recorded_from_the_worker_thread(
    fake_regex_clock: _FakeClock,
) -> None:
    manager = SusPatternsManager()
    manager.configure(SyncSecurityConfig())
    manager.add_pattern("zzzworker[a-z]+q")

    with _scan_value_budget(512, max_scan_seconds=1000.0):
        manager.detect("hello", "127.0.0.1", "query_param:q")
        remaining = detection_scan._scan_time_remaining()

    assert remaining is not None
    assert remaining < 1000.0


def test_inline_cpu_is_accounted_per_pass_not_per_pattern() -> None:
    manager = SusPatternsManager()
    manager.configure(SyncSecurityConfig())
    calls = {"clock": 0, "patterns": 0}
    real: Callable[..., tuple[dict | None, bool]] = manager._check_regex_pattern

    scan_thread = threading.get_ident()

    def counting_clock() -> float:
        if threading.get_ident() == scan_thread:
            calls["clock"] += 1
        return 0.0

    def counting(*args: object, **kwargs: object) -> tuple[dict | None, bool]:
        calls["patterns"] += 1
        return real(*args, **kwargs)

    # The 2 ms event-loop slice yields on wall time, and each yield reads the
    # clock, so a loaded machine adds reads; switch slicing off to count passes only.
    with (
        patch.object(detection_scan, "_thread_cpu_seconds", counting_clock),
        patch.object(manager, "_check_regex_pattern", counting),
        patch.object(_suspatterns_regex, "_EVENT_LOOP_SLICE_SECONDS", float("inf")),
        patch.object(
            _suspatterns_regex,
            "rows_with_required_literal",
            lambda rows, *_args: iter(rows),
        ),
        _scan_value_budget(512, max_scan_seconds=1000.0),
    ):
        # Steady state only: the one-time lazy compile of each built-in row reads
        # the clock twice (to exclude its CPU from the budget), so scan once to
        # warm every row, then count the second scan.
        manager.detect("hello world", "127.0.0.1", "query_param:q")
        calls["clock"] = calls["patterns"] = 0
        manager.detect("hello world", "127.0.0.1", "query_param:q")

    assert calls["patterns"] > 50
    assert 0 < calls["clock"] < calls["patterns"] * 0.2


def test_no_cpu_clock_reads_outside_a_request_scope() -> None:
    manager = SusPatternsManager()
    manager.configure(SyncSecurityConfig())
    calls = {"clock": 0}

    scan_thread = threading.get_ident()

    def counting_clock() -> float:
        if threading.get_ident() == scan_thread:
            calls["clock"] += 1
        return 0.0

    with patch.object(detection_scan, "_thread_cpu_seconds", counting_clock):
        manager.detect("hello world", "127.0.0.1", "query_param:q")

    assert calls["clock"] == 0


def test_attack_region_extraction_charges_its_cpu_to_the_budget(
    fake_regex_clock: _FakeClock,
) -> None:
    from guard_core.sync.detection_engine.preprocessor import ContentPreprocessor
    from guard_core.sync.detection_engine.truncation import _collect_regions

    preprocessor = ContentPreprocessor()
    with _scan_value_budget(512, max_scan_seconds=100.0):
        before = detection_scan._scan_time_remaining()
        _collect_regions(preprocessor, "quiet text " * 50, 10)
        after = detection_scan._scan_time_remaining()

    assert before is not None
    assert after is not None
    assert after < before


class _RaisedRouteBodyRequest(SyncMockGuardRequest):
    def read_body_prefix(self, max_bytes: int) -> bytes:
        return self._body[:max_bytes]


def test_clean_route_raised_json_ends_in_the_budget_outcome() -> None:
    import json

    from guard_core.sync.decorators.base import RouteConfig

    words = "quarterly onboarding metrics for the regional sales team include revenue "
    size = 20_000_000
    data = json.dumps({"k": (words * (size // len(words) + 1))[:size]}).encode()
    route = RouteConfig()
    route.max_request_size = 2 * size
    request = _RaisedRouteBodyRequest(
        method="POST",
        body_content=data,
        headers={
            "content-type": "application/json",
            "content-length": str(len(data)),
        },
    )
    cap = 1.0
    charged = [0.0]
    longest_pass = [0.0]
    real_record = detection_scan._record_scan_time

    def recording(elapsed: float) -> None:
        charged[0] += elapsed
        longest_pass[0] = max(longest_pass[0], elapsed)
        real_record(elapsed)

    with (
        patch.object(detection_scan, "_record_scan_time", recording),
        patch.object(_suspatterns_regex, "_record_scan_time", recording),
        patch.object(detection_scan.LazyPreview, "resolve", lambda self: None),
    ):
        result = detect_penetration_attempt(
            request, SyncSecurityConfig(detection_max_scan_seconds=cap), route
        )

    assert result.is_threat is True
    assert "Pattern exceeded scan time budget" in result.trigger_info
    assert charged[0] <= cap + longest_pass[0]


def test_a_pass_that_starts_with_the_budget_spent_charges_no_cpu() -> None:
    # LEDGER 6.694: such a pass folded its whole content for the literal prefilter
    # inside the charged window, so each late pass added milliseconds past the cap.
    manager = SusPatternsManager()
    manager.configure(SyncSecurityConfig(detection_max_scan_seconds=1.0))
    charged = [0.0]
    real_record = detection_scan._record_scan_time

    def recording(elapsed: float) -> None:
        charged[0] += elapsed
        real_record(elapsed)

    with (
        _scan_value_budget(512, max_scan_seconds=1.0),
        patch.object(detection_scan, "_record_scan_time", recording),
    ):
        real_record(1.5)
        threats, matched, timeouts = manager._check_regex_patterns(
            "quarterly onboarding metrics " * 100_000, "127.0.0.1", None
        )

    assert charged[0] == 0.0
    assert matched == timeouts == ["scan_time_budget_exhausted"]
    assert [threat["pattern"] for threat in threats] == matched


def test_a_budget_spent_by_the_last_scanned_row_is_reported_beside_a_tail() -> None:
    manager = SusPatternsManager()
    manager.configure(SyncSecurityConfig(detection_max_scan_seconds=1.0))
    rows = manager._rows_to_scan()

    def spends_the_budget(*args: object, **kwargs: object) -> tuple[None, bool]:
        detection_scan._record_scan_time(2.0)
        return None, False

    with (
        _scan_value_budget(512, max_scan_seconds=1.0),
        patch.object(
            _suspatterns_regex, "_applicable_patterns", lambda *a, **k: (rows[:1], True)
        ),
        patch.object(
            _suspatterns_regex,
            "rows_with_required_literal",
            lambda found, *a: iter(found),
        ),
        patch.object(manager, "_check_regex_pattern", spends_the_budget),
    ):
        threats, matched, timeouts = manager._check_regex_patterns(
            "benign text", "127.0.0.1", None
        )

    assert matched == timeouts == ["scan_time_budget_exhausted"]
    assert [threat["pattern"] for threat in threats] == matched


def test_a_spent_pass_with_every_row_prefiltered_still_reports_the_budget() -> None:
    row: PatternRow = (re.compile(r"zzneedle\d"), frozenset(), "xss")
    content = "quarterly onboarding metrics " * 1000
    folded = _suspatterns_literals.fold_for_literals(content)
    assert (
        list(
            _suspatterns_literals.rows_with_required_literal([row], folded, frozenset())
        )
        == []
    )
    manager = SusPatternsManager()
    manager.configure(SyncSecurityConfig(detection_max_scan_seconds=1.0))

    with (
        _scan_value_budget(512, max_scan_seconds=1.0),
        patch.object(
            _suspatterns_regex, "_applicable_patterns", lambda *a, **k: ([row], False)
        ),
    ):
        detection_scan._record_scan_time(1.5)
        threats, matched, timeouts = manager._check_regex_patterns(
            content, "127.0.0.1", None
        )

    assert matched == timeouts == ["scan_time_budget_exhausted"]
    assert [threat["pattern"] for threat in threats] == matched


def test_a_spent_pass_with_every_row_filtered_out_reports_the_budget() -> None:
    # LEDGER 6.701: v4.4.0 recorded the budget outcome on its first loop check, before
    # any per-row skip, so a pass with zero applicable rows still reported it.
    manager = SusPatternsManager()
    manager.configure(SyncSecurityConfig(detection_max_scan_seconds=1.0))
    rows = manager._rows_to_scan()
    applicable, skipped_tail = _suspatterns_regex._applicable_patterns(
        rows,
        raw_view_only=None,
        url_decoded_view_only=None,
        skip_filter=False,
        normalized_context="query_param",
        enabled_categories={"no_such_category"},
    )
    assert rows
    assert applicable == []
    assert skipped_tail is True

    with _scan_value_budget(512, max_scan_seconds=1.0):
        detection_scan._record_scan_time(1.5)
        threats, matched, timeouts = manager._check_regex_patterns(
            "hello", "127.0.0.1", None, "query_param", {"no_such_category"}
        )

    assert matched == timeouts == ["scan_time_budget_exhausted"]
    assert [threat["pattern"] for threat in threats] == matched


def test_a_spent_pass_over_an_empty_row_table_stays_clean() -> None:
    manager = SusPatternsManager()
    manager.configure(SyncSecurityConfig(detection_max_scan_seconds=1.0))

    def no_rows() -> list[object]:
        return []

    with (
        _scan_value_budget(512, max_scan_seconds=1.0),
        patch.object(manager, "_rows_to_scan", no_rows),
    ):
        detection_scan._record_scan_time(1.5)
        threats, matched, timeouts = manager._check_regex_patterns(
            "hello", "127.0.0.1", None
        )

    assert threats == matched == timeouts == []


_UNIT_TEXT = "caf\u00e9 zzmark"
_PAST_THE_VALUE_CAP = 512
_CATEGORIES_THE_UNIT_PASS_EMPTIES = [
    "code_injection",
    "sqli",
    "xss",
    "template",
    "ldap",
    "http_split",
]


def _is_the_unit_text(content: str) -> bool:
    return content.strip().lower().replace("\u00e9", "e") == "cafe zzmark"


@contextmanager
def _spending_the_budget(point: str) -> Iterator[None]:
    """Patches that record 2.0 s of scan time at ``point`` of the unit text's scan:
    ``pre`` in its preprocessing, ``after_pass_N`` once its Nth regex pass returned."""
    real_preprocess = SusPatternsManager._preprocess_content
    real_pass = SusPatternsManager._check_regex_patterns
    passes: list[str] = []

    def preprocess(
        self: SusPatternsManager,
        content: str,
        correlation_id: str | None,
        *,
        state: _DetectionState | None = None,
    ) -> tuple[str, bool, str | None]:
        if point == "pre" and content == _UNIT_TEXT:
            detection_scan._record_scan_time(2.0)
        return real_preprocess(self, content, correlation_id, state=state)

    def one_pass(
        self: SusPatternsManager,
        content: str,
        ip_address: str,
        correlation_id: str | None,
        context: str = "unknown",
        enabled_categories: set[str] | None = None,
        *,
        state: _DetectionState | None = None,
        raw_view_only: bool | None = None,
        url_decoded_view_only: bool | None = None,
        nul_tail_rows: bool = False,
    ) -> tuple[list[dict], list[str], list[str]]:
        out = real_pass(
            self,
            content,
            ip_address,
            correlation_id,
            context,
            enabled_categories,
            state=state,
            raw_view_only=raw_view_only,
            url_decoded_view_only=url_decoded_view_only,
            nul_tail_rows=nul_tail_rows,
        )
        if _is_the_unit_text(content):
            passes.append(content)
            if point == f"after_pass_{len(passes)}":
                detection_scan._record_scan_time(2.0)
        return out

    with (
        patch.object(SusPatternsManager, "_preprocess_content", preprocess),
        patch.object(SusPatternsManager, "_check_regex_patterns", one_pass),
    ):
        yield


def _json_request(values: dict[str, str], content_type: str) -> SyncMockGuardRequest:
    body = json.dumps(values).encode()
    return SyncMockGuardRequest(
        method="POST",
        headers={"content-type": content_type, "content-length": str(len(body))},
        body_content=body,
    )


def _unit_past_the_value_cap() -> SyncMockGuardRequest:
    values = {f"a{i}": "x" for i in range(_PAST_THE_VALUE_CAP)}
    return _json_request({**values, "u": _UNIT_TEXT}, "application/json")


def _config_for(category: str) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False,
        enable_penetration_detection=True,
        detection_max_scan_seconds=1.0,
        enabled_detection_categories={category},
    )


@pytest.mark.parametrize("point", ["pre", "after_pass_1", "after_pass_2"])
@pytest.mark.parametrize("category", _CATEGORIES_THE_UNIT_PASS_EMPTIES)
def test_a_unit_pass_the_budget_ended_before_is_an_incomplete_scan(
    category: str, point: str
) -> None:
    # LEDGER 6.701: the unit's whole-value passes drop rows after the tail was judged.
    # Every pass that follows a spent budget still records it (rows or a skipped tail),
    # so the request ends in the budget outcome, never clean, as v4.4.0 would.
    with _spending_the_budget(point):
        result = detect_penetration_attempt(
            _unit_past_the_value_cap(), _config_for(category)
        )

    assert result.body_read_error
    assert result.is_threat is False


def test_a_unit_pass_the_budget_ended_after_its_last_pass_stays_clean() -> None:
    with _spending_the_budget("after_pass_3"):
        result = detect_penetration_attempt(
            _unit_past_the_value_cap(), _config_for("sqli")
        )

    assert result.body_read_error is None
    assert result.is_threat is False


@pytest.mark.parametrize("category", _CATEGORIES_THE_UNIT_PASS_EMPTIES)
def test_a_unit_pass_with_budget_left_stays_clean(category: str) -> None:
    result = detect_penetration_attempt(
        _unit_past_the_value_cap(), _config_for(category)
    )

    assert result.body_read_error is None
    assert result.is_threat is False


@pytest.mark.parametrize("category", ["code_injection", "sqli", "xss"])
def test_the_same_unit_inside_the_value_cap_reports_the_budget(
    category: str,
) -> None:
    request = _json_request({"u": _UNIT_TEXT, "a": "x"}, "application/json")

    with _spending_the_budget("pre"):
        result = detect_penetration_attempt(request, _config_for(category))

    assert result.is_threat is True
    assert "scan_time_budget_exhausted" in result.trigger_info


@pytest.mark.parametrize("category", ["dir_traversal", "sensitive_file"])
def test_a_blob_leaf_pass_the_budget_ended_before_reports_the_budget(
    category: str,
) -> None:
    request = _json_request({"k": _UNIT_TEXT}, "text/plain")

    with _spending_the_budget("pre"):
        result = detect_penetration_attempt(request, _config_for(category))

    assert result.is_threat is True
    assert "scan_time_budget_exhausted" in result.trigger_info


def test_a_budget_spent_by_the_last_row_the_prefilter_yields_is_reported() -> None:
    # LEDGER 6.714: v4.4.0 budget-checked every table row, so a budget spent inside
    # the last row the literal prefilter yields was recorded at the next row's check.
    manager = SusPatternsManager()
    manager.configure(SyncSecurityConfig(detection_max_scan_seconds=1.0))
    rows = manager._rows_to_scan()
    applicable, skipped_tail = _suspatterns_regex._applicable_patterns(
        rows,
        raw_view_only=None,
        url_decoded_view_only=None,
        skip_filter=True,
        normalized_context="request_body",
        enabled_categories=None,
    )
    yielded = list(
        _suspatterns_literals.rows_with_required_literal(
            applicable,
            _suspatterns_literals.fold_for_literals("hello"),
            _suspatterns_regex._LITERAL_EXCLUDED_SOURCES,
        )
    )
    assert skipped_tail is False
    assert yielded[-1] is not applicable[-1]
    last_yielded = yielded[-1][0]
    scan_row = manager._check_regex_pattern

    def spends_after_the_last_yielded_row(
        pattern: PatternSource,
        content: str,
        ip_address: str,
        pattern_start: float,
        category: str,
        *,
        state: _DetectionState | None = None,
        context: str = "unknown",
        binary_prefix: BinaryPrefix | None = None,
    ) -> tuple[dict | None, bool]:
        out = scan_row(
            pattern,
            content,
            ip_address,
            pattern_start,
            category,
            state=state,
            context=context,
            binary_prefix=binary_prefix,
        )
        if pattern is last_yielded:
            detection_scan._record_scan_time(1.5)
        return out

    with (
        _scan_value_budget(512, max_scan_seconds=1.0),
        patch.object(
            manager, "_check_regex_pattern", spends_after_the_last_yielded_row
        ),
    ):
        threats, matched, timeouts = manager._check_regex_patterns(
            "hello", "127.0.0.1", None, "request_body", None
        )

    assert matched == timeouts == ["scan_time_budget_exhausted"]
    assert [threat["pattern"] for threat in threats] == matched


@pytest.mark.parametrize(
    ("flag", "source"),
    [
        (scan_remainder._scanning_whole_value_rows_only, r"zzzcustom\d"),
        (detection_scan._skipping_whole_value_path_rows, r"\A[/\\]zzzcustom\d"),
    ],
    ids=["rows_only", "path_rows_skipped"],
)
def test_a_spent_pass_whose_whole_value_filter_dropped_the_tail_reports_it(
    flag: Callable[[], AbstractContextManager[None]], source: str
) -> None:
    # LEDGER 6.701: the whole-value filter emptied a table whose tail was applicable,
    # and the tail was judged before the filter, so the spent budget was not recorded.
    manager = SusPatternsManager()
    manager.configure(SyncSecurityConfig(detection_max_scan_seconds=1.0))
    manager.add_pattern(source)

    with _scan_value_budget(512, max_scan_seconds=1.0), flag():
        detection_scan._record_scan_time(1.5)
        threats, matched, timeouts = manager._check_regex_patterns(
            "hello", "127.0.0.1", None, "query_param", {"custom"}
        )

    assert matched == timeouts == ["scan_time_budget_exhausted"]
    assert [threat["pattern"] for threat in threats] == matched


def test_a_spent_pass_with_budget_left_and_filtered_tail_stays_clean() -> None:
    manager = SusPatternsManager()
    manager.configure(SyncSecurityConfig(detection_max_scan_seconds=1.0))
    manager.add_pattern(r"zzzcustom\d")

    with (
        _scan_value_budget(512, max_scan_seconds=1.0),
        scan_remainder._scanning_whole_value_rows_only(),
    ):
        threats, matched, timeouts = manager._check_regex_patterns(
            "hello", "127.0.0.1", None, "query_param", {"custom"}
        )

    assert threats == matched == timeouts == []


def _status_check(
    config: SyncSecurityConfig,
) -> tuple[SuspiciousActivityCheck, MagicMock]:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_scan_time_budget")
    middleware.suspicious_request_counts = {}
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MagicMock(
            status_code=status_code
        )
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    return SuspiciousActivityCheck(middleware), middleware


def _with_client(request: SyncMockGuardRequest) -> SyncMockGuardRequest:
    request.state.client_ip = "203.0.113.9"
    request.state.route_config = None
    return request


@contextmanager
def _spending_in_the_nth_scanned_row(
    nth: int | None, counted: list[int]
) -> Iterator[None]:
    """Records 2.0 s of scan time as the ``nth`` regex row of the request returns."""
    real_row = SusPatternsManager._check_regex_pattern

    def one_row(
        self: SusPatternsManager,
        pattern: PatternSource,
        content: str,
        ip_address: str,
        pattern_start: float,
        category: str,
        *,
        state: _DetectionState | None = None,
        context: str = "unknown",
        binary_prefix: BinaryPrefix | None = None,
    ) -> tuple[dict | None, bool]:
        out = real_row(
            self,
            pattern,
            content,
            ip_address,
            pattern_start,
            category,
            state=state,
            context=context,
            binary_prefix=binary_prefix,
        )
        counted[0] += 1
        if counted[0] == nth:
            detection_scan._record_scan_time(2.0)
        return out

    with patch.object(SusPatternsManager, "_check_regex_pattern", one_row):
        yield


def test_a_default_request_spent_in_its_last_scanned_row_answers_400() -> None:
    # LEDGER 6.714, request level: the budget is spent inside the last regex row the
    # default-config request (all categories) scans. v4.4.0 and head both answer 400
    # with the budget outcome (WP502 raw/request-*.txt); the last pass of a real
    # request always has a skipped tail, so the pass-level pins above carry the RED.
    config = SyncSecurityConfig(
        enable_redis=False, detection_max_scan_seconds=1.0, fail_secure=True
    )
    sus_patterns_handler.configure(config)
    counted = [0]
    with _spending_in_the_nth_scanned_row(None, counted):
        detect_penetration_attempt(
            _with_client(
                SyncMockGuardRequest(path="/api", query_params={"q": "hello"})
            ),
            config,
        )
    last_row = counted[0]
    check, middleware = _status_check(config)

    with _spending_in_the_nth_scanned_row(last_row, [0]):
        response = check.check(
            _with_client(SyncMockGuardRequest(path="/api", query_params={"q": "hello"}))
        )

    assert response is not None
    assert response.status_code == 400
    assert "scan_time_budget_exhausted" in str(
        middleware.event_bus.send_middleware_event.call_args.kwargs
    )


def test_a_unit_pass_after_a_custom_tail_row_answers_400_with_no_strike() -> None:
    # LEDGER 6.701 + D-88 item 1: the table ends in an unanchored custom row, the
    # remainder unit pass drops it, the budget is spent after the unit's first pass:
    # D-17's flag (400, one event, no strike), never a pass.
    config = SyncSecurityConfig(
        enable_redis=False,
        enable_penetration_detection=True,
        detection_max_scan_seconds=1.0,
        fail_secure=True,
    )
    sus_patterns_handler.configure(config)
    sus_patterns_handler.add_pattern(r"zzzcustom\d")
    check, middleware = _status_check(config)

    with _spending_the_budget("after_pass_1"):
        response = check.check(_with_client(_unit_past_the_value_cap()))

    assert response is not None
    assert response.status_code == 400
    event = middleware.event_bus.send_middleware_event.call_args.kwargs
    assert event["event_type"] == EVENT_SUSPICIOUS_REQUEST
    assert event["action_taken"] == "request_blocked"
    assert middleware.suspicious_request_counts == {}
