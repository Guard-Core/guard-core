import ipaddress
import json
import logging
from typing import Any, cast
from unittest.mock import AsyncMock, patch

import pytest

from guard_core.handlers.cloud_handler import cloud_handler
from guard_core.handlers.cloud_ip_stores import RedisCloudIpStore

FRESH = ipaddress.ip_network("203.0.113.0/24")
PREVIOUS = ipaddress.ip_network("198.51.100.0/24")
FRESH_PAYLOAD = json.dumps(["203.0.113.0/24"])
FETCH = "guard_core.handlers.cloud_handler._fetch_provider_ranges"
LOGGER = "guard_core.handlers.cloud"
BAD_VALUES = {
    "corrupt element": ["not-a-network"],
    "empty list": [],
    "mixed list": ["10.0.0.0/8", "not-a-network"],
}


class _KeyValueRedis:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], Any] = {}

    async def get_key(self, namespace: str, key: str) -> object:
        return self.values.get((namespace, key))

    async def set_key(
        self, namespace: str, key: str, value: object, ttl: int | None = None
    ) -> bool:
        self.values[(namespace, key)] = value
        return True


def _use_store(redis: _KeyValueRedis) -> None:
    cloud_handler.redis_handler = cast(Any, redis)
    cloud_handler._store = RedisCloudIpStore(cast(Any, redis))


def _use_legacy_key(redis: _KeyValueRedis) -> None:
    cloud_handler.redis_handler = cast(Any, redis)
    cloud_handler._store = None


def _fresh_fetch() -> AsyncMock:
    return AsyncMock(return_value=({FRESH}, {}))


@pytest.mark.parametrize("label", list(BAD_VALUES))
async def test_a_bad_cloud_ip_v2_value_is_fetched_again_and_rewritten(
    label: str,
) -> None:
    redis = _KeyValueRedis()
    redis.values[("cloud_ip_v2", "AWS")] = json.dumps(BAD_VALUES[label])
    _use_store(redis)

    with patch(FETCH, _fresh_fetch()) as fetch:
        await cloud_handler.refresh_async({"AWS"})

    assert fetch.await_count == 1
    assert cloud_handler.is_cloud_ip("203.0.113.5", {"AWS"})
    assert redis.values[("cloud_ip_v2", "AWS")] == FRESH_PAYLOAD


@pytest.mark.parametrize("value", ["not-a-network", ",", "10.0.0.0/8,not-a-network"])
async def test_a_bad_cloud_ranges_v2_value_is_fetched_again_and_rewritten(
    value: str,
) -> None:
    redis = _KeyValueRedis()
    redis.values[("cloud_ranges_v2", "AWS")] = value
    _use_legacy_key(redis)

    with patch(FETCH, _fresh_fetch()) as fetch:
        await cloud_handler.refresh_async({"AWS"})

    assert fetch.await_count == 1
    assert cloud_handler.is_cloud_ip("203.0.113.5", {"AWS"})
    assert redis.values[("cloud_ranges_v2", "AWS")] == "203.0.113.0/24"


async def test_a_bad_value_with_a_failing_fetch_keeps_the_ranges_and_the_key() -> None:
    redis = _KeyValueRedis()
    redis.values[("cloud_ip_v2", "AWS")] = json.dumps(["not-a-network"])
    _use_store(redis)
    cloud_handler.ip_ranges["AWS"] = {PREVIOUS}

    failing_fetch = AsyncMock(side_effect=RuntimeError("provider unreachable"))
    with patch(FETCH, failing_fetch):
        await cloud_handler.refresh_async({"AWS"})

    assert failing_fetch.await_count == 1
    assert cloud_handler.ip_ranges["AWS"] == {PREVIOUS}
    assert redis.values[("cloud_ip_v2", "AWS")] == json.dumps(["not-a-network"])


async def test_a_bad_value_with_an_empty_fetch_writes_nothing() -> None:
    redis = _KeyValueRedis()
    redis.values[("cloud_ip_v2", "AWS")] = json.dumps([])
    _use_store(redis)
    cloud_handler.ip_ranges["AWS"] = {PREVIOUS}

    with patch(FETCH, AsyncMock(return_value=(set(), {}))):
        await cloud_handler.refresh_async({"AWS"})

    assert cloud_handler.ip_ranges["AWS"] == {PREVIOUS}
    assert redis.values[("cloud_ip_v2", "AWS")] == json.dumps([])


async def test_a_valid_cache_is_not_fetched_again() -> None:
    redis = _KeyValueRedis()
    redis.values[("cloud_ip_v2", "AWS")] = json.dumps(["203.0.113.0/24|eu-west-1"])
    _use_store(redis)

    with patch(FETCH, _fresh_fetch()) as fetch:
        await cloud_handler.refresh_async({"AWS"})

    assert fetch.await_count == 0
    assert cloud_handler.is_cloud_ip("203.0.113.5", {"AWS"})
    assert cloud_handler.network_regions["AWS"] == {str(FRESH): "eu-west-1"}


async def test_the_bad_value_is_logged_once_per_provider_with_a_clean_element(
    caplog: pytest.LogCaptureFixture,
) -> None:
    redis = _KeyValueRedis()
    redis.values[("cloud_ip_v2", "AWS")] = json.dumps(["bad\nelement" + "x" * 500])
    _use_store(redis)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        for _ in range(3):
            redis.values[("cloud_ip_v2", "AWS")] = json.dumps(
                ["bad\nelement" + "x" * 500]
            )
            with patch(FETCH, _fresh_fetch()):
                await cloud_handler.refresh_async({"AWS"})

    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "AWS" in warnings[0]
    assert "bad\\nelement" in warnings[0]
    assert "\n" not in warnings[0]
    assert len(warnings[0]) < 300


async def test_an_empty_value_is_logged_as_empty(
    caplog: pytest.LogCaptureFixture,
) -> None:
    redis = _KeyValueRedis()
    redis.values[("cloud_ip_v2", "AWS")] = json.dumps([])
    _use_store(redis)

    with caplog.at_level(logging.WARNING, logger=LOGGER), patch(FETCH, _fresh_fetch()):
        await cloud_handler.refresh_async({"AWS"})

    assert any("empty" in r.getMessage() for r in caplog.records)


async def test_an_empty_legacy_value_is_logged_as_empty(
    caplog: pytest.LogCaptureFixture,
) -> None:
    redis = _KeyValueRedis()
    redis.values[("cloud_ranges_v2", "AWS")] = ""
    _use_legacy_key(redis)

    with (
        caplog.at_level(logging.WARNING, logger=LOGGER),
        patch(FETCH, _fresh_fetch()) as fetch,
    ):
        await cloud_handler.refresh_async({"AWS"})

    assert fetch.await_count == 1
    assert any("empty" in r.getMessage() for r in caplog.records)
    assert redis.values[("cloud_ranges_v2", "AWS")] == "203.0.113.0/24"
