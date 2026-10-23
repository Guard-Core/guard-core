import multiprocessing as mp
import re
import time
from urllib.parse import urlencode

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import (
    _SQLI_TAUTOLOGY_RE,
    sus_patterns_handler,
)
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_CONFIG = SyncSecurityConfig()

_SIBLING_QUOTE_OR_BIND_RE = (
    r"(?i)('\s*(?:OR|AND)\s*[\(\s]*'?(?:[@:$][A-Za-z_]\w*|[\d\w]+)\s*"
    r"(?:=|LIKE|<|>|<=|>=)\s*[\(\s]*'?(?:[@:$][A-Za-z_]\w*|[\d\w]+))"
)
_SIBLING_QUOTED_EQUALS_RE = (
    r"(?i)(?:OR|AND)\s+(?:'[\w\d]*'='[\w\d]*'?|"
    r"[@:$][A-Za-z_]\w*\s*=\s*[@:$][A-Za-z_]\w*)"
)


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


def _text_body_request(body: bytes) -> SyncMockGuardRequest:
    headers = {"content-length": str(len(body)), "content-type": "text/plain"}
    return SyncMockGuardRequest(body_content=body, headers=headers)


def _form_body_request(body: bytes) -> SyncMockGuardRequest:
    headers = {
        "content-length": str(len(body)),
        "content-type": "application/x-www-form-urlencoded",
    }
    return SyncMockGuardRequest(body_content=body, headers=headers)


_BIND_TAUTOLOGY_DETECTED_BODIES = [
    pytest.param(_text_body_request(b"' OR :x=:x --"), id="colon_bind_tautology"),
    pytest.param(_text_body_request(b"' OR @x=@x --"), id="at_bind_tautology"),
    pytest.param(
        _form_body_request(
            urlencode(
                {"username": "admin' OR :id=:id-- ", "password": "whatever"}
            ).encode()
        ),
        id="colon_bind_tautology_form_field",
    ),
]


@pytest.mark.parametrize("request_obj", _BIND_TAUTOLOGY_DETECTED_BODIES)
def test_bind_token_tautology_detected(request_obj: SyncMockGuardRequest) -> None:
    result = detect_penetration_attempt(request_obj, _CONFIG)
    assert result.is_threat is True
    assert "sqli" in result.threat_categories


_CONTROL_TAUTOLOGY_DETECTED_BODIES = [
    pytest.param(_text_body_request(b"1 OR 1=1--"), id="numeric_tautology_control"),
    pytest.param(_text_body_request(b"' OR '1'='1"), id="quoted_tautology_control"),
]


@pytest.mark.parametrize("request_obj", _CONTROL_TAUTOLOGY_DETECTED_BODIES)
def test_existing_tautology_controls_still_detected(
    request_obj: SyncMockGuardRequest,
) -> None:
    result = detect_penetration_attempt(request_obj, _CONFIG)
    assert result.is_threat is True
    assert "sqli" in result.threat_categories


_BIND_PLACEHOLDER_ALONE_NOT_DETECTED_BODIES = [
    pytest.param(
        _text_body_request(b"SELECT id FROM users WHERE id = :id"),
        id="colon_placeholder_no_or",
    ),
    pytest.param(
        _text_body_request(b"SELECT id FROM users WHERE id = @id"),
        id="at_placeholder_no_or",
    ),
    pytest.param(
        _text_body_request(b"SELECT id FROM users WHERE id = $1"),
        id="dollar_numbered_placeholder_no_or",
    ),
    pytest.param(
        _text_body_request(b'{"price":"$25","name":"coffee"}'),
        id="dollar_digit_price_not_bind_token",
    ),
    pytest.param(
        _text_body_request(b"export PATH=${HOME}/bin"),
        id="dollar_brace_shell_var_not_bind_token",
    ),
    pytest.param(
        _text_body_request(
            b"MongoDB operators like $gt and $lt let you build range queries."
        ),
        id="dollar_mongo_operator_prose_no_equals",
    ),
]


@pytest.mark.parametrize("request_obj", _BIND_PLACEHOLDER_ALONE_NOT_DETECTED_BODIES)
def test_bind_placeholder_without_tautology_shape_not_detected(
    request_obj: SyncMockGuardRequest,
) -> None:
    result = detect_penetration_attempt(request_obj, _CONFIG)
    assert result.is_threat is False


def _timed_search(pattern: str, text: str, q: "mp.Queue[float]") -> None:
    compiled = re.compile(pattern, re.IGNORECASE)
    samples: list[float] = []
    for _ in range(5):
        t0 = time.process_time()
        compiled.search(text)
        samples.append(time.process_time() - t0)
    q.put(min(samples))


def _search_elapsed_seconds(pattern: str, text: str, timeout: float) -> float | None:
    ctx = mp.get_context("forkserver")
    q: mp.Queue[float] = ctx.Queue()
    p = ctx.Process(target=_timed_search, args=(pattern, text, q))
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate()
        p.join()
        return None
    return q.get() if not q.empty() else None


_ADVERSARIAL_BIND_TOKEN_NO_EQUALS_INPUT = " OR :" + "a" * 20000
_ADVERSARIAL_REPEATED_BIND_TOKEN_INPUT = " OR :a" * 4000
_BIND_TOKEN_LINEAR_TIME_CEILING_SECONDS = 0.2

_TIMED_PATTERNS = [
    pytest.param(_SQLI_TAUTOLOGY_RE, id="tautology_pattern"),
    pytest.param(_SIBLING_QUOTE_OR_BIND_RE, id="sibling_quote_or_bind_pattern"),
    pytest.param(_SIBLING_QUOTED_EQUALS_RE, id="sibling_quoted_equals_pattern"),
]


@pytest.mark.parametrize("pattern", _TIMED_PATTERNS)
@pytest.mark.parametrize(
    "adversarial_input",
    [
        _ADVERSARIAL_BIND_TOKEN_NO_EQUALS_INPUT,
        _ADVERSARIAL_REPEATED_BIND_TOKEN_INPUT,
    ],
)
def test_bind_token_widened_patterns_stay_linear_time(
    pattern: str, adversarial_input: str
) -> None:
    elapsed = _search_elapsed_seconds(pattern, adversarial_input, timeout=5.0)
    assert elapsed is not None, "regex search did not finish within the 5s timeout"
    assert elapsed < _BIND_TOKEN_LINEAR_TIME_CEILING_SECONDS, (
        f"search took {elapsed:.3f}s on a {len(adversarial_input)}-char "
        "adversarial bind-token input, exceeding the "
        f"{_BIND_TOKEN_LINEAR_TIME_CEILING_SECONDS}s ceiling"
    )
