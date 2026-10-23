from collections.abc import Generator

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import (
    DETECTION_RAW_VIEW_PATTERN_SOURCES,
    DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES,
    SusPatternsManager,
    sus_patterns_handler,
)

_MID_VALUE_ENV_ASSIGNMENT_SHELL_DASH_C_PATTERN = (
    r"(?:\A|[;|&])\s*[^=\s;|&]+=[^\s;|&]+\s+(?:/?(?:[\w.-]+/)*env\s+)?/?(?:[\w.-]+/)*"
    r"(?:bash|sh|ksh|csh|tsch|zsh|ash)\s+-[a-zA-Z]+"
)


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


@pytest.fixture
def manager() -> Generator[SusPatternsManager, None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    new_instance = SusPatternsManager(SyncSecurityConfig())

    yield new_instance

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


MID_VALUE_ENV_ASSIGNMENT_GAP_BODIES = [
    pytest.param("foo=bar /bin/sh -c id", id="mid_value_path_sh"),
    pytest.param("x=1 sh -c id", id="mid_value_bare_sh"),
    pytest.param("A=B /bin/bash -c id", id="mid_value_path_bash"),
    pytest.param("VAR=val env bash -c id", id="mid_value_env_bare_bash"),
    pytest.param("VAR=val env /bin/sh -c id", id="mid_value_env_path_sh"),
    pytest.param("PATH=/usr/bin /bin/sh -c id", id="mid_value_path_value_sh"),
]


@pytest.mark.parametrize("body", MID_VALUE_ENV_ASSIGNMENT_GAP_BODIES)
def test_env_assignment_prefixed_shell_dash_c_fires_cmd_injection(
    body: str,
) -> None:
    result = sus_patterns_handler.detect(
        content=body, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


REGRESSION_BODIES = [
    pytest.param("x | /bin/sh -c id", id="pipe_path_sh"),
    pytest.param("x;/bin/sh -c id", id="semicolon_path_sh"),
    pytest.param("/bin/sh -c id", id="start_path_sh"),
    pytest.param("x | sh -c id", id="pipe_bare_sh"),
]


@pytest.mark.parametrize("body", REGRESSION_BODIES)
def test_prior_shell_dash_c_coverage_still_fires(body: str) -> None:
    result = sus_patterns_handler.detect(
        content=body, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


SEPARATOR_PREFIXED_ENV_ASSIGNMENT_BODIES = [
    pytest.param("x | foo=bar /bin/sh -c id", id="pipe_env_assignment_path_sh"),
    pytest.param(
        "\nfoo=bar /bin/sh -c id", id="leading_newline_env_assignment_path_sh"
    ),
]


@pytest.mark.parametrize("body", SEPARATOR_PREFIXED_ENV_ASSIGNMENT_BODIES)
def test_separator_prefixed_env_assignment_shell_dash_c_fires(
    body: str,
) -> None:
    result = sus_patterns_handler.detect(
        content=body, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


FP_BODIES = [
    pytest.param("see path=/bin/sh -c for the shell", id="path_directly_after_eq"),
    pytest.param("a=b bash", id="assignment_no_dash_c_flag"),
    pytest.param("key=val python -c", id="assignment_non_shell"),
    pytest.param("the result was x=y", id="eq_in_prose_no_shell"),
    pytest.param("version=1.0 is the latest", id="assignment_value_no_shell"),
    pytest.param("foo=bar; echo hi", id="assignment_semicolon_no_shell_dash_c"),
]


@pytest.mark.parametrize("body", FP_BODIES)
def test_benign_bodies_do_not_fire_cmd_injection(body: str) -> None:
    result = sus_patterns_handler.detect(
        content=body, ip_address="203.0.113.9", context="request_body"
    )
    assert not any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


def test_new_pattern_not_in_view_sets() -> None:
    assert (
        _MID_VALUE_ENV_ASSIGNMENT_SHELL_DASH_C_PATTERN
        not in DETECTION_RAW_VIEW_PATTERN_SOURCES
    )
    assert (
        _MID_VALUE_ENV_ASSIGNMENT_SHELL_DASH_C_PATTERN
        not in DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES
    )


def test_manager_detects_mid_value_gap_payload(
    manager: SusPatternsManager,
) -> None:
    result = manager.detect(
        "foo=bar /bin/sh -c id", "203.0.113.9", context="request_body"
    )
    assert any(
        threat.get("category") == "cmd_injection"
        and threat.get("pattern") == _MID_VALUE_ENV_ASSIGNMENT_SHELL_DASH_C_PATTERN
        for threat in result["threats"]
    )


def test_pipe_form_not_caught_by_mid_value_pattern(
    manager: SusPatternsManager,
) -> None:
    result = manager.detect("x | /bin/sh -c id", "203.0.113.9", context="request_body")
    assert result["is_threat"] is True
    assert not any(
        threat.get("pattern") == _MID_VALUE_ENV_ASSIGNMENT_SHELL_DASH_C_PATTERN
        for threat in result["threats"]
    )
