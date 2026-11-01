import random
import re
import tracemalloc

import pytest

from guard_core.detection_engine.binary_prefix import (
    build_binary_prefix,
    span_is_binary_dense,
)
from guard_core.detection_engine.encoding_decoders import repair_lost_overlong_bytes
from guard_core.handlers._suspatterns_sources import (
    _PATH_TRAVERSAL_DECODED_SHAPE_RE,
    _count_path_traversal_shapes,
)
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig

_ONE_MIB = 1048576
_PEAK_BUDGET_BYTES = 8 * 1024 * 1024


def test_the_traversal_shape_count_is_the_number_of_regex_matches() -> None:
    rng = random.Random(355)
    tokens = ["..", "../", "..\\", ".", "/", "\\", "a", "...", "%2e", "./.."]
    for _ in range(5000):
        text = "".join(rng.choice(tokens) for _ in range(rng.randrange(0, 14)))
        assert _count_path_traversal_shapes(text) == len(
            _PATH_TRAVERSAL_DECODED_SHAPE_RE.findall(text)
        )


@pytest.fixture
def manager() -> SusPatternsManager:
    SusPatternsManager._instance = None
    instance = SusPatternsManager()
    instance.configure(SecurityConfig())
    return instance


async def _check(manager: SusPatternsManager, raw: str, decoded: str) -> object:
    return await manager._check_decoded_view_path_traversal(
        decoded, raw, "test", None, manager._detection_state
    )


async def test_a_megabyte_of_traversal_shapes_costs_a_few_megabytes(
    manager: SusPatternsManager,
) -> None:
    text = "../" * (_ONE_MIB // 3)
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        await _check(manager, text, text)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < _PEAK_BUDGET_BYTES


async def test_a_megabyte_of_traversal_shapes_after_a_lost_byte_costs_a_few_megabytes(
    manager: SusPatternsManager,
) -> None:
    text = "�" + "../" * (_ONE_MIB // 3)
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        await _check(manager, "x", text)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < _PEAK_BUDGET_BYTES


def _reference_decoded_view_match(raw: str, decoded: str) -> re.Match[str] | None:
    if any(marker in decoded for marker in ("�", "\udcc0")):
        decoded = repair_lost_overlong_bytes(decoded)
        prefix = build_binary_prefix(decoded)
        found = [
            match
            for match in _PATH_TRAVERSAL_DECODED_SHAPE_RE.finditer(decoded)
            if not span_is_binary_dense(prefix, match.start(), match.end())
        ]
    else:
        found = list(_PATH_TRAVERSAL_DECODED_SHAPE_RE.finditer(decoded))
    if len(found) <= len(_PATH_TRAVERSAL_DECODED_SHAPE_RE.findall(raw)):
        return None
    return found[0]


async def test_the_decoded_view_check_flags_what_the_list_based_check_flagged(
    manager: SusPatternsManager,
) -> None:
    rng = random.Random(356)
    tokens = ["../", "..\\", "..", "a", "/", "�", "\x01\x02\x03\x04\x05", "%2e"]
    for _ in range(1500):
        raw = "".join(rng.choice(tokens) for _ in range(rng.randrange(0, 8)))
        decoded = "".join(rng.choice(tokens) for _ in range(rng.randrange(0, 10)))
        expected = _reference_decoded_view_match(raw, decoded)
        threat = await _check(manager, raw, decoded)
        if expected is None:
            assert threat is None
        else:
            assert isinstance(threat, dict)
            assert threat["position"] == expected.start()


def _reference_repair_lost_dot_runs(content: str) -> str:
    lost = "[�\udc80-\udcff]"
    pair = re.compile(f"{lost}{{2}}")
    dot_run = re.compile(rf"(?<![^/\\])(?:\.|{lost}{{2}}){{2}}(?=[\\/])")
    return dot_run.sub(lambda match: pair.sub(".", match.group()), content)


def test_a_lost_byte_dot_run_is_repaired_as_the_callback_repair_did() -> None:
    from guard_core.detection_engine import encoding_decoders as decoders

    rng = random.Random(357)
    tokens = ["�", "\udcc0", ".", "/", "\\", "a", "..", "��", "-"]
    for _ in range(6000):
        text = "".join(rng.choice(tokens) for _ in range(rng.randrange(0, 12)))
        assert decoders._LOST_DOT_RUN_RE.sub("..", text) == (
            _reference_repair_lost_dot_runs(text)
        )
