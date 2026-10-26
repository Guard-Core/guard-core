from unittest.mock import MagicMock

import pytest

from guard_core.models import DynamicRules
from guard_core.sync.core.events.composite_handler import CompositeAgentHandler
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol


@pytest.fixture
def handler_a() -> MagicMock:
    handler = MagicMock()
    handler.send_event = MagicMock()
    handler.send_metric = MagicMock()
    handler.start = MagicMock()
    handler.stop = MagicMock()
    handler.flush_buffer = MagicMock()
    handler.health_check = MagicMock(return_value=True)
    handler.get_dynamic_rules = MagicMock(return_value=None)
    handler.initialize_redis = MagicMock()
    return handler


@pytest.fixture
def handler_b() -> MagicMock:
    handler = MagicMock()
    handler.send_event = MagicMock()
    handler.send_metric = MagicMock()
    handler.start = MagicMock()
    handler.stop = MagicMock()
    handler.flush_buffer = MagicMock()
    handler.health_check = MagicMock(return_value=True)
    handler.get_dynamic_rules = MagicMock(return_value=None)
    handler.initialize_redis = MagicMock()
    return handler


def test_start_continues_on_handler_failure(
    handler_a: MagicMock, handler_b: MagicMock
) -> None:
    handler_a.start = MagicMock(side_effect=RuntimeError("start fail"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    composite.start()
    handler_b.start.assert_called_once()


def test_stop_continues_on_handler_failure(
    handler_a: MagicMock, handler_b: MagicMock
) -> None:
    handler_a.stop = MagicMock(side_effect=RuntimeError("stop fail"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    composite.stop()
    handler_b.stop.assert_called_once()


def test_flush_buffer_continues_on_handler_failure(
    handler_a: MagicMock, handler_b: MagicMock
) -> None:
    handler_a.flush_buffer = MagicMock(side_effect=RuntimeError("flush fail"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    composite.flush_buffer()
    handler_b.flush_buffer.assert_called_once()


def test_initialize_redis_continues_on_handler_failure(
    handler_a: MagicMock, handler_b: MagicMock
) -> None:
    handler_a.initialize_redis = MagicMock(side_effect=RuntimeError("redis fail"))
    redis_handler = MagicMock()
    composite = CompositeAgentHandler([handler_a, handler_b])
    composite.initialize_redis(redis_handler)
    handler_b.initialize_redis.assert_called_once_with(redis_handler)


def test_health_check_continues_on_handler_failure(
    handler_a: MagicMock, handler_b: MagicMock
) -> None:
    handler_a.health_check = MagicMock(side_effect=RuntimeError("health fail"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    assert composite.health_check() is False


def test_get_dynamic_rules_continues_on_handler_failure(
    handler_a: MagicMock, handler_b: MagicMock
) -> None:
    handler_a.get_dynamic_rules = MagicMock(side_effect=RuntimeError("rules fail"))
    composite = CompositeAgentHandler([handler_a, handler_b])
    result = composite.get_dynamic_rules()
    assert result is None


def test_get_dynamic_rules_returns_from_second_on_first_failure(
    handler_a: MagicMock, handler_b: MagicMock
) -> None:
    handler_a.get_dynamic_rules = MagicMock(side_effect=RuntimeError("fail"))
    handler_b.get_dynamic_rules = MagicMock(return_value={"rule": "test"})
    composite = CompositeAgentHandler([handler_a, handler_b])
    result = composite.get_dynamic_rules()
    assert result == {"rule": "test"}


def test_health_check_true_with_single_handler() -> None:
    handler = MagicMock()
    handler.health_check = MagicMock(return_value=True)
    composite = CompositeAgentHandler([handler])
    assert composite.health_check() is True


def test_health_check_false_with_single_handler() -> None:
    handler = MagicMock()
    handler.health_check = MagicMock(return_value=False)
    composite = CompositeAgentHandler([handler])
    assert composite.health_check() is False


def test_state_properties_default() -> None:
    composite = CompositeAgentHandler([])
    assert composite.started is False
    assert composite.degraded is False
    assert composite.failed_handlers == []


def test_degraded_true_when_started_with_failed_handlers() -> None:
    composite = CompositeAgentHandler([])
    composite._started = True
    composite._failed_handlers = ["handler_a"]
    assert composite.degraded is True
    assert composite.failed_handlers == ["handler_a"]


class NullAgent:
    def initialize_redis(self, redis_handler: SyncRedisHandlerProtocol) -> None:
        return None

    def send_event(self, event: object) -> None:
        return None

    def send_metric(self, metric: object) -> None:
        return None

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None

    def flush_buffer(self) -> None:
        return None

    def get_dynamic_rules(self) -> DynamicRules | None:
        return None

    def health_check(self) -> bool:
        return True


class _NoStatus(NullAgent):
    pass


def test_get_status_returns_the_first_handler_status(
    handler_a: MagicMock, handler_b: MagicMock
) -> None:
    handler_a.get_status = MagicMock(return_value="status-a")
    handler_b.get_status = MagicMock(return_value="status-b")
    composite = CompositeAgentHandler([_NoStatus(), handler_a, handler_b])

    assert composite.get_status() == "status-a"


def test_get_status_skips_a_failing_handler(
    handler_a: MagicMock, handler_b: MagicMock
) -> None:
    handler_a.get_status = MagicMock(side_effect=RuntimeError("down"))
    handler_b.get_status = MagicMock(return_value="status-b")
    composite = CompositeAgentHandler([handler_a, handler_b])

    assert composite.get_status() == "status-b"


def test_get_status_is_none_when_no_handler_reports_one() -> None:
    assert CompositeAgentHandler([_NoStatus()]).get_status() is None
