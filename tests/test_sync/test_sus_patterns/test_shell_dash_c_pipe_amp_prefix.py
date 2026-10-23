import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


SHELL_DASH_C_GAP_BODIES = [
    pytest.param("x | /bin/sh -c id", id="pipe_bin_sh"),
    pytest.param("x | /bin/bash -c id", id="pipe_bin_bash"),
    pytest.param("x && /usr/bin/sh -c id", id="ampamp_usr_bin_sh"),
    pytest.param("x | env bash -c id", id="pipe_env_bash"),
    pytest.param("x | env /bin/sh -c id", id="pipe_env_bin_sh"),
    pytest.param("x && /bin/sh -c id", id="ampamp_bin_sh"),
    pytest.param("x || /bin/sh -c id", id="pipeor_bin_sh"),
]


@pytest.mark.parametrize("body", SHELL_DASH_C_GAP_BODIES)
def test_separator_prefixed_shell_dash_c_fires_cmd_injection(
    body: str,
) -> None:
    result = sus_patterns_handler.detect(
        content=body, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


SHELL_DASH_C_REGRESSION_BODIES = [
    pytest.param("x;/bin/sh -c id", id="semicolon_bin_sh"),
    pytest.param("/bin/sh -c id", id="start_bin_sh"),
    pytest.param("x" + chr(10) + "/bin/sh -c id", id="newline_bin_sh"),
    pytest.param("x | sh -c id", id="pipe_bare_sh"),
    pytest.param("\n\n\nbash -c id", id="blankline_bash"),
    pytest.param("\n\tbash -c id", id="newline_tab_bash"),
    pytest.param("\nenv bash -c id", id="newline_env_bash"),
    pytest.param("\n/bin/sh -c id", id="newline_bin_sh"),
]


@pytest.mark.parametrize("body", SHELL_DASH_C_REGRESSION_BODIES)
def test_prior_shell_dash_c_coverage_still_fires(body: str) -> None:
    result = sus_patterns_handler.detect(
        content=body, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )


SHELL_DASH_C_FP_BODIES = [
    pytest.param("please review the report -c draft", id="prose_bare_dash_c"),
    pytest.param("see /bin/sh -c docs for reference", id="prose_path_dash_c"),
    pytest.param("the bash and sh shells are common", id="prose_shell_names"),
    pytest.param("a || b", id="pipeor_no_shell"),
    pytest.param("run | grep foo", id="pipe_to_non_shell"),
    pytest.param("env PATH=/usr/bin", id="env_without_shell"),
]


@pytest.mark.parametrize("body", SHELL_DASH_C_FP_BODIES)
def test_benign_bodies_do_not_fire_cmd_injection(body: str) -> None:
    result = sus_patterns_handler.detect(
        content=body, ip_address="203.0.113.9", context="request_body"
    )
    assert not any(
        threat.get("category") == "cmd_injection" for threat in result["threats"]
    )
