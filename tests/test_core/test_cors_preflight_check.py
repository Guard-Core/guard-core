from typing import Any

from guard_core.core.checks.factory import build_default_pipeline
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.decorators import SecurityDecorator
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest
from tests.test_core.conftest import build_middleware

ORIGIN = "https://new.example"
PREFLIGHT = {"Origin": ORIGIN, "Access-Control-Request-Method": "POST"}


def _pipeline(**settings: Any) -> SecurityCheckPipeline:
    defaults: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": True,
        "rate_limit": 1,
        "rate_limit_window": 60,
    }
    config = SecurityConfig(**{**defaults, **settings})
    return build_default_pipeline(build_middleware(config, SecurityDecorator(config)))


async def _send(
    pipeline: SecurityCheckPipeline,
    method: str = "OPTIONS",
    headers: dict[str, str] | None = None,
    path: str = "/api",
) -> Any:
    request = MockGuardRequest(
        path=path,
        method=method,
        headers=headers or PREFLIGHT,
        client_host="198.51.100.9",
    )
    return await pipeline.execute(request)


def test_an_app_built_without_cors_has_the_check_before_rate_limiting() -> None:
    names = _pipeline().get_check_names()

    assert names.index("cors_preflight") == names.index("rate_limit") - 1
    assert names.index("cors_preflight") > names.index("ip_security")


def test_an_app_built_with_cors_answers_in_its_adapter_not_in_the_pipeline() -> None:
    names = _pipeline(
        enable_cors=True, cors_allow_origins=["https://app.example"]
    ).get_check_names()

    assert "cors_preflight" not in names


async def test_without_an_override_a_preflight_is_not_answered_by_the_pipeline() -> (
    None
):
    assert await _send(_pipeline()) is None


async def test_a_flagged_enable_cors_makes_the_pipeline_answer_the_preflight() -> None:
    pipeline = _pipeline()
    security_headers_manager.configure(
        enable_cors=True,
        cors_origins=[ORIGIN],
        cors_allow_methods=["POST"],
        override_apps=True,
    )

    response = await _send(pipeline)

    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == ORIGIN
    assert response.headers["Access-Control-Allow-Methods"] == "POST"


async def test_a_disallowed_origin_gets_the_400_of_an_app_built_with_cors() -> None:
    pipeline = _pipeline()
    security_headers_manager.configure(
        enable_cors=True, cors_origins=["https://other.example"], override_apps=True
    )

    response = await _send(pipeline)

    assert response.status_code == 400
    assert "origin" in response.headers or response.status_code == 400


async def test_the_answer_comes_before_rate_limiting_and_auth_checks() -> None:
    pipeline = _pipeline(
        rate_limit=1,
        enable_rate_limiting=True,
    )
    security_headers_manager.configure(
        enable_cors=True, cors_origins=[ORIGIN], override_apps=True
    )

    statuses = [(await _send(pipeline)).status_code for _ in range(4)]

    assert statuses == [200, 200, 200, 200]


async def test_a_request_that_is_not_a_preflight_is_left_to_the_pipeline() -> None:
    pipeline = _pipeline(rate_limit=100)
    security_headers_manager.configure(
        enable_cors=True, cors_origins=[ORIGIN], override_apps=True
    )

    assert await _send(pipeline, method="GET", headers={"Origin": ORIGIN}) is None
    assert await _send(pipeline, method="OPTIONS", headers={"Origin": ORIGIN}) is None


async def test_clearing_the_override_ends_the_answer() -> None:
    pipeline = _pipeline()
    security_headers_manager.configure(
        enable_cors=True, cors_origins=[ORIGIN], override_apps=True
    )
    assert (await _send(pipeline)).status_code == 200

    security_headers_manager.configure(override_apps=True)

    assert await _send(pipeline) is None
