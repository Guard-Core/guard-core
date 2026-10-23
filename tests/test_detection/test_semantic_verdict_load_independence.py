import ast
import time
from typing import Literal
from unittest.mock import patch

import pytest

from guard_core.detection_engine.semantic import SemanticAnalyzer
from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

_CONTENT_TYPE = "multipart/form-data; boundary=B0"
_REAL_PARSE = ast.parse


@pytest.fixture(autouse=True)
def _configured_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _benign_binary_upload() -> MockGuardRequest:
    blob = (bytes(range(256)) * 3).decode("latin-1")
    body = (
        '--B0\r\nContent-Disposition: form-data; name="file"; filename="photo.jpg"'
        f"\r\nContent-Type: application/octet-stream\r\n\r\n{blob}\r\n--B0--\r\n"
    ).encode()
    return MockGuardRequest(
        body_content=body,
        headers={"content-length": str(len(body)), "content-type": _CONTENT_TYPE},
    )


def _parse_that_waits_without_working(
    source: str, mode: Literal["eval"] = "eval"
) -> ast.Expression:
    time.sleep(0.12)
    return _REAL_PARSE(source, mode=mode)


async def test_benign_binary_upload_verdict_does_not_depend_on_scheduling_latency() -> (
    None
):
    alone = await detect_penetration_attempt(
        _benign_binary_upload(), SecurityConfig(enable_redis=False)
    )

    with patch("ast.parse", _parse_that_waits_without_working):
        on_a_loaded_host = await detect_penetration_attempt(
            _benign_binary_upload(), SecurityConfig(enable_redis=False)
        )

    assert alone.is_threat is False
    assert on_a_loaded_host.is_threat is alone.is_threat
    assert on_a_loaded_host.trigger_info == alone.trigger_info


def test_a_parse_that_waits_without_working_scores_the_same_as_a_fast_one() -> None:
    analyzer = SemanticAnalyzer()
    fast = analyzer.analyze_code_injection_risk("alpha + beta")

    with patch("ast.parse", _parse_that_waits_without_working):
        slow = analyzer.analyze_code_injection_risk("alpha + beta")

    assert slow == fast


def test_a_parse_that_burns_cpu_past_the_100ms_budget_scores_the_timeout_risk() -> None:
    analyzer = SemanticAnalyzer()

    with patch(
        "guard_core.detection_engine.semantic.thread_time", side_effect=[0.0, 0.5]
    ):
        risk = analyzer._check_ast_parsing_risk("alpha + beta")

    assert risk == 0.2


def test_a_parse_within_the_cpu_budget_scores_the_parseable_risk() -> None:
    analyzer = SemanticAnalyzer()

    with patch(
        "guard_core.detection_engine.semantic.thread_time", side_effect=[0.0, 0.01]
    ):
        risk = analyzer._check_ast_parsing_risk("alpha + beta")

    assert risk == 0.3


def test_a_text_that_does_not_parse_scores_no_parse_risk() -> None:
    analyzer = SemanticAnalyzer()

    assert analyzer._check_ast_parsing_risk("alpha + + +(") == 0.0
