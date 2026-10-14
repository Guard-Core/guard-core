import concurrent.futures
import multiprocessing as mp
import re
import time
from collections.abc import Iterator
from unittest.mock import patch

import pytest

from guard_core.handlers.suspatterns_handler import (
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_COMPILED_RE,
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
    _cmd_injection_shell_dash_c_finditer,
    sus_patterns_handler,
)
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

_CONFIG = SecurityConfig()


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _text_body_request(body: str) -> MockGuardRequest:
    encoded = body.encode()
    headers = {
        "content-length": str(len(encoded)),
        "content-type": "text/plain",
    }
    return MockGuardRequest(body_content=encoded, headers=headers)


async def _assert_body_fires_cmd_injection(body: str) -> None:
    request = _text_body_request(body)
    result = await detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
    assert "cmd_injection" in result.threat_categories


async def _assert_body_does_not_fire(body: str) -> None:
    request = _text_body_request(body)
    result = await detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is False


def _var_assignment_prefix(count: int) -> str:
    return "".join(f"V{i}=x%20" for i in range(count))


VAR_ASSIGNMENT_PREFIX_BODIES = [
    pytest.param("x%0AFOO=bar%20/bin/sh%20-c%20id", id="one_assignment"),
    pytest.param("x%0AA=1%20B=2%20/bin/sh%20-c%20id", id="two_assignments"),
    pytest.param(
        "x%0AA=1%20B=2%20C=3%20D=4%20E=5%20F=6%20G=7%20H=8%20/bin/sh%20-c%20id",
        id="eight_assignments",
    ),
    pytest.param(
        "x%0A" + _var_assignment_prefix(9) + "/bin/sh%20-c%20id",
        id="nine_assignments",
    ),
    pytest.param(
        "x%0A" + _var_assignment_prefix(200) + "/bin/sh%20-c%20id",
        id="two_hundred_assignments",
    ),
    pytest.param(
        "x%0A" + _var_assignment_prefix(4096) + "/bin/sh%20-c%20id",
        id="four_thousand_ninety_six_assignments",
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("body", VAR_ASSIGNMENT_PREFIX_BODIES)
async def test_var_assignment_newline_prefix_fires_cmd_injection(body: str) -> None:
    await _assert_body_fires_cmd_injection(body)


EXISTING_B7_STILL_FIRES_BODIES = [
    pytest.param("x%0A/bin/sh%20-c%20id", id="arbitrary_prefix_bin_sh"),
    pytest.param("x" + chr(10) + "/bin/sh -c id", id="literal_newline_bin_sh"),
    pytest.param("x%0Aenv%20bash%20-c%20id", id="env_prefix_bash"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("body", EXISTING_B7_STILL_FIRES_BODIES)
async def test_b7_regression_bodies_still_fire(body: str) -> None:
    await _assert_body_fires_cmd_injection(body)


VAR_ASSIGNMENT_PREFIX_BENIGN_COUNTS = [7, 8, 9, 200, 4096]


@pytest.mark.asyncio
@pytest.mark.parametrize("count", VAR_ASSIGNMENT_PREFIX_BENIGN_COUNTS)
async def test_var_assignment_newline_prefix_benign_mirror_does_not_fire(
    count: int,
) -> None:
    body = "x%0A" + _var_assignment_prefix(count) + "echo%20hi"
    await _assert_body_does_not_fire(body)


@pytest.mark.asyncio
async def test_benign_mirror_and_attack_share_prefix_up_to_the_shell_tail() -> None:
    assignments = _var_assignment_prefix(9)
    await _assert_body_does_not_fire("x%0A" + assignments + "echo%20hi")
    await _assert_body_fires_cmd_injection("x%0A" + assignments + "/bin/sh%20-c%20id")


def test_cmd_injection_finder_skips_newline_already_covered_by_prior_match() -> None:
    text = "\nA=B \nC=D sh -c 'id'"
    matches = list(
        _cmd_injection_shell_dash_c_finditer(
            text, _CMD_INJECTION_NEWLINE_SHELL_DASH_C_COMPILED_RE
        )
    )
    assert len(matches) == 1
    assert matches[0].start() == 0


def test_cmd_injection_finder_yields_nothing_when_chain_has_no_shell_tail() -> None:
    text = "\nA=B C=D echo hi"
    matches = list(
        _cmd_injection_shell_dash_c_finditer(
            text, _CMD_INJECTION_NEWLINE_SHELL_DASH_C_COMPILED_RE
        )
    )
    assert matches == []


@pytest.mark.asyncio
async def test_check_windowed_pattern_timeout_returns_none_and_logs() -> None:
    def _finder(_content: str) -> Iterator[re.Match[str]]:
        yield from ()

    with patch(
        "guard_core.handlers._suspatterns_regex.shared_regex_executor"
    ) as mock_shared_executor:
        mock_future: concurrent.futures.Future[None] = concurrent.futures.Future()
        mock_future.set_exception(concurrent.futures.TimeoutError())
        mock_shared_executor.return_value.submit.return_value = mock_future

        with patch("guard_core.handlers._suspatterns_regex.logger") as mock_logger:
            threat, timed_out = await sus_patterns_handler._check_windowed_pattern(
                _CMD_INJECTION_NEWLINE_SHELL_DASH_C_COMPILED_RE,
                _finder,
                "\nA=B sh -c id",
                time.monotonic(),
                "cmd_injection",
                "unknown",
            )

    assert threat is None
    assert timed_out is True
    mock_logger.warning.assert_called()


@pytest.mark.asyncio
async def test_check_windowed_pattern_exception_returns_none_and_logs() -> None:
    def _finder(_content: str) -> Iterator[re.Match[str]]:
        yield from ()

    with patch(
        "guard_core.handlers._suspatterns_regex.shared_regex_executor"
    ) as mock_shared_executor:
        mock_future: concurrent.futures.Future[None] = concurrent.futures.Future()
        mock_future.set_exception(RuntimeError("boom"))
        mock_shared_executor.return_value.submit.return_value = mock_future

        with patch("guard_core.handlers._suspatterns_regex.logger") as mock_logger:
            threat, timed_out = await sus_patterns_handler._check_windowed_pattern(
                _CMD_INJECTION_NEWLINE_SHELL_DASH_C_COMPILED_RE,
                _finder,
                "\nA=B sh -c id",
                time.monotonic(),
                "cmd_injection",
                "unknown",
            )

    assert threat is None
    assert timed_out is False
    mock_logger.error.assert_called()


def _timed_finder(pat: str, s: str, q: "mp.Queue[float]") -> None:
    compiled = re.compile(pat, re.IGNORECASE)
    samples: list[float] = []
    for _ in range(5):
        t0 = time.process_time()
        list(_cmd_injection_shell_dash_c_finditer(s, compiled))
        samples.append(time.process_time() - t0)
    q.put(min(samples))


def _finder_elapsed_seconds(pat: str, s: str, timeout: float) -> float | None:
    ctx = mp.get_context("forkserver")
    q: mp.Queue[float] = ctx.Queue()
    p = ctx.Process(target=_timed_finder, args=(pat, s, q))
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate()
        p.join()
        return None
    return q.get() if not q.empty() else None


_ADVERSARIAL_VAR_ASSIGNMENT_NEWLINE_INPUT = "\nA=A " * 2000
_WINDOWED_FINDER_LINEAR_TIME_CEILING_SECONDS = 0.2


def test_var_assignment_prefix_windowed_finder_stays_under_linear_time_ceiling() -> (
    None
):
    elapsed = _finder_elapsed_seconds(
        _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
        _ADVERSARIAL_VAR_ASSIGNMENT_NEWLINE_INPUT,
        timeout=5.0,
    )
    assert elapsed is not None, "windowed finder did not finish within the 5s timeout"
    assert elapsed < _WINDOWED_FINDER_LINEAR_TIME_CEILING_SECONDS, (
        f"windowed finder took {elapsed:.3f}s (CPU time) on a 10000-char "
        f'adversarial "\\nA=A " * 2000 body with no shell -c terminator, '
        f"exceeding the {_WINDOWED_FINDER_LINEAR_TIME_CEILING_SECONDS}s "
        "ceiling; unanchored search() on the same unbounded pattern without "
        "the finder's last_end skip takes roughly 4x longer on this input "
        "because it re-attempts the full scan at every newline"
    )
