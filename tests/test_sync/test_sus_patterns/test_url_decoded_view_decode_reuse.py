import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

_CONFIG = SyncSecurityConfig()


def _drop_execution_time(
    result: tuple[list[dict], list[str], list[str], bool],
) -> tuple[list[dict], list[str], list[str], bool]:
    threats, matched, timeouts, budget_exhausted = result
    stripped = [
        {k: v for k, v in threat.items() if k != "execution_time"} for threat in threats
    ]
    return stripped, matched, timeouts, budget_exhausted


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


@pytest.mark.parametrize(
    "content",
    [
        "x%0A/bin/sh%20-c%20id",
        "the quick brown fox",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "' OR 1=1--",
        "",
    ],
)
def test_precomputed_decoded_matches_recomputed_decode(content: str) -> None:
    state = sus_patterns_handler._detection_state
    (
        processed,
        decode_budget_exhausted,
        decoded,
    ) = sus_patterns_handler._preprocess_content(content, "corr-1", state=state)

    via_precomputed = sus_patterns_handler._check_url_decoded_view_patterns(
        content,
        "127.0.0.1",
        "request_body",
        "corr-1",
        None,
        state,
        precomputed_decoded=decoded,
        precomputed_decode_budget_exhausted=decode_budget_exhausted,
    )
    via_recomputed = sus_patterns_handler._check_url_decoded_view_patterns(
        content, "127.0.0.1", "request_body", "corr-1", None, state
    )

    assert _drop_execution_time(via_precomputed) == _drop_execution_time(via_recomputed)


def test_check_url_decoded_view_patterns_without_precomputed_still_detects() -> None:
    state = sus_patterns_handler._detection_state

    (
        threats,
        matched,
        timeouts,
        budget_exhausted,
    ) = sus_patterns_handler._check_url_decoded_view_patterns(
        "x%0A/bin/sh%20-c%20id",
        "127.0.0.1",
        "request_body",
        "corr-1",
        None,
        state,
    )

    assert matched
    assert budget_exhausted is False
