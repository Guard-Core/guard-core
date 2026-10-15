from collections.abc import AsyncGenerator
from typing import Any

import pytest

from guard_core.decorators.base import RouteConfig
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

_JWT_COOKIE = (
    "session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


@pytest.fixture(autouse=True)
async def _reset_suspatterns_singleton() -> AsyncGenerator[None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    SusPatternsManager._instance = None
    SusPatternsManager._config = None

    yield

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


def _config(**kwargs: Any) -> SecurityConfig:
    return SecurityConfig(detection_semantic_threshold=0.3, **kwargs)


def test_field_defaults_to_empty() -> None:
    assert SecurityConfig().excluded_semantic_detection_headers == set()


async def test_jwt_cookie_is_flagged_semantically_by_default() -> None:
    request = MockGuardRequest(headers={"cookie": _JWT_COOKIE})

    result = await detect_penetration_attempt(request, _config())

    assert result.is_threat is True
    assert "Semantic attack" in result.trigger_info


async def test_listed_header_skips_semantic_analysis_case_insensitively() -> None:
    request = MockGuardRequest(headers={"cookie": _JWT_COOKIE})

    result = await detect_penetration_attempt(
        request, _config(excluded_semantic_detection_headers={" Cookie "})
    )

    assert result.is_threat is False


async def test_unlisted_header_still_gets_semantic_analysis() -> None:
    request = MockGuardRequest(headers={"x-session": _JWT_COOKIE})

    result = await detect_penetration_attempt(
        request, _config(excluded_semantic_detection_headers={"cookie"})
    )

    assert result.is_threat is True


async def test_listed_header_is_still_scanned_by_regex() -> None:
    request = MockGuardRequest(headers={"cookie": "id=1' OR '1'='1' UNION SELECT 1--"})

    result = await detect_penetration_attempt(
        request, _config(excluded_semantic_detection_headers={"cookie"})
    )

    assert result.is_threat is True
    assert "Semantic attack" not in result.trigger_info


async def test_listed_header_opt_out_applies_to_every_cookie_pair() -> None:
    cookie = f"theme=dark; {_JWT_COOKIE}; lang=en"
    request = MockGuardRequest(headers={"cookie": cookie})

    flagged = await detect_penetration_attempt(request, _config())
    exempt = await detect_penetration_attempt(
        request, _config(excluded_semantic_detection_headers={"cookie"})
    )

    assert flagged.is_threat is True
    assert exempt.is_threat is False


async def test_route_config_set_is_merged() -> None:
    request = MockGuardRequest(headers={"cookie": _JWT_COOKIE})
    route_config = RouteConfig()
    route_config.excluded_semantic_detection_headers = {"cookie"}

    result = await detect_penetration_attempt(request, _config(), route_config)

    assert result.is_threat is False


async def test_exclusion_does_not_leak_to_the_next_request() -> None:
    request = MockGuardRequest(headers={"cookie": _JWT_COOKIE})
    config = _config(excluded_semantic_detection_headers={"cookie"})

    assert (await detect_penetration_attempt(request, config)).is_threat is False
    assert (await detect_penetration_attempt(request, _config())).is_threat is True


def test_reassignment_rejects_bare_string() -> None:
    config = SecurityConfig()

    with pytest.raises(ValueError, match="excluded_semantic_detection_headers"):
        config.excluded_semantic_detection_headers = "cookie"  # type: ignore[assignment]
