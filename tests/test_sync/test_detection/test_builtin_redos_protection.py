import multiprocessing as mp
import time
from typing import Any

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

_REDOS_PAYLOAD = "{{" * 10000
_DETECT_DEADLINE_SECONDS = 2.0
_HANG_GUARD_SECONDS = 60.0
_COMPILER_TIMEOUT_SECONDS = 0.3
_MAX_CONTENT_LENGTH = 20000

_LDAP_EXTENSIBLE_MATCH_REDOS_PAYLOAD = "*)(a" + ":dn" * 30 + "X"


def _child_detect(
    compiler_timeout: float,
    max_content_length: int,
    payload: str,
    q: "mp.Queue[dict[str, Any]]",
) -> None:
    config = SecurityConfig(
        detection_compiler_timeout=compiler_timeout,
        detection_max_content_length=max_content_length,
    )
    manager = SusPatternsManager()
    manager.configure(config)
    t0 = time.process_time()
    result = manager.detect(payload, "127.0.0.1", context="request_body")
    cpu = time.process_time() - t0
    q.put(
        {
            "cpu": cpu,
            "is_threat": bool(result["is_threat"]),
            "timeout_count": len(result["timeouts"]),
            "detection_method": result["detection_method"],
        }
    )


def _run_detect_under_deadline(
    config: SecurityConfig, payload: str
) -> dict[str, Any] | None:
    ctx = mp.get_context("forkserver")
    q: mp.Queue[dict[str, Any]] = ctx.Queue()
    proc = ctx.Process(
        target=_child_detect,
        args=(
            config.detection_compiler_timeout,
            config.detection_max_content_length,
            payload,
            q,
        ),
    )
    proc.start()
    # Wall clock only guards against a hang: forkserver start-up and imports
    # alone outrun a 2s wall budget on a loaded runner. The deadline itself is
    # the child's CPU time around detect(), which load does not inflate.
    proc.join(_HANG_GUARD_SECONDS)
    if proc.is_alive():
        proc.terminate()
        proc.join()
        return None
    return q.get() if not q.empty() else None


def _enhanced_config() -> SecurityConfig:
    return SecurityConfig(
        detection_compiler_timeout=_COMPILER_TIMEOUT_SECONDS,
        detection_max_content_length=_MAX_CONTENT_LENGTH,
    )


def test_builtin_template_redos_protected_in_enhanced_mode() -> None:
    result = _run_detect_under_deadline(_enhanced_config(), _REDOS_PAYLOAD)
    assert result is not None, (
        "detect did not return within the hang guard; the built-in template "
        "pattern ran an unguarded re.search and ReDoSed the worker"
    )
    assert result["cpu"] < _DETECT_DEADLINE_SECONDS, (
        f"detect used {result['cpu']:.3f}s of CPU, exceeding the "
        f"{_DETECT_DEADLINE_SECONDS}s deadline"
    )
    assert result["detection_method"] == "enhanced"
    assert result["is_threat"] is False


def test_builtin_ldap_extensible_match_redos_protected_in_enhanced_mode() -> None:
    result = _run_detect_under_deadline(
        _enhanced_config(), _LDAP_EXTENSIBLE_MATCH_REDOS_PAYLOAD
    )
    assert result is not None, (
        "detect did not return within the hang guard; the ldap extensible-match "
        "attribute pattern's ambiguous ':dn' alternation ReDoSed the worker"
    )
    assert result["cpu"] < _DETECT_DEADLINE_SECONDS, (
        f"detect used {result['cpu']:.3f}s of CPU, exceeding the "
        f"{_DETECT_DEADLINE_SECONDS}s deadline"
    )
    assert result["detection_method"] == "enhanced"
    assert result["is_threat"] is False
