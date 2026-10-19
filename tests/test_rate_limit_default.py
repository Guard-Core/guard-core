from typing import Any

import pytest

from guard_core.core.checks.factory import build_default_pipeline
from guard_core.decorators import SecurityDecorator
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest
from tests.test_core.conftest import build_middleware

CLIENT = "203.0.113.30"


def _config(**settings: Any) -> SecurityConfig:
    defaults: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
    }
    return SecurityConfig(**{**defaults, **settings})


async def _statuses(config: SecurityConfig, count: int) -> list[int | None]:
    middleware = build_middleware(config, SecurityDecorator(config))
    pipeline = build_default_pipeline(middleware)
    statuses: list[int | None] = []
    for _ in range(count):
        response = await pipeline.execute(
            MockGuardRequest(path="/x", client_host=CLIENT)
        )
        statuses.append(None if response is None else response.status_code)
    return statuses


def test_the_default_limit_is_120_per_60_seconds() -> None:
    config = _config()

    assert (config.rate_limit, config.rate_limit_window) == (120, 60)
    assert "rate_limit" not in config.model_fields_set


@pytest.mark.parametrize(("limit", "explicit"), [(120, False), (10, True)])
async def test_the_limit_in_force_blocks_the_next_request(
    limit: int, explicit: bool
) -> None:
    config = _config(rate_limit=10) if explicit else _config()

    statuses = await _statuses(config, limit + 1)

    assert statuses[:limit] == [None] * limit
    assert statuses[limit] == 429
