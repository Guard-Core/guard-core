import importlib
import sys
from collections.abc import Generator
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


def _fresh_logfire_handler_module() -> ModuleType:
    module_name = "guard_core.sync.core.events.logfire_handler"
    if module_name in sys.modules:
        return importlib.reload(sys.modules[module_name])
    return importlib.import_module(module_name)


@pytest.fixture(autouse=True)
def _reload_logfire_handler_between_tests() -> Generator[None, None, None]:
    _fresh_logfire_handler_module()
    yield
    _fresh_logfire_handler_module()


def test_logfire_handler_does_nothing_when_module_unavailable() -> None:
    module = _fresh_logfire_handler_module()
    with patch.object(module, "_logfire_available", False):
        handler = module.LogfireHandler(
            config=SimpleNamespace(logfire_service_name="svc")
        )
        handler.send_metric(MagicMock())


def test_send_metric_uses_logfire_info_with_tags() -> None:
    module = _fresh_logfire_handler_module()
    fake_logfire = MagicMock()
    metric = SimpleNamespace(
        metric_type="response_time",
        value=0.125,
        endpoint="/x",
        tags={"method": "GET", "status": "200"},
    )
    with (
        patch.object(module, "_logfire_available", True),
        patch.object(module, "logfire", fake_logfire),
    ):
        handler = module.LogfireHandler(
            config=SimpleNamespace(logfire_service_name="svc")
        )
        handler.send_metric(metric)

    fake_logfire.info.assert_called_once()
    args, kwargs = fake_logfire.info.call_args
    assert args[0] == "guard.metric.response_time"
    assert kwargs["value"] == 0.125
    assert kwargs["endpoint"] == "/x"
    assert kwargs["method"] == "GET"
    assert kwargs["status"] == "200"


def test_send_metric_takes_the_endpoint_from_the_tag_when_the_field_is_none() -> None:
    module = _fresh_logfire_handler_module()
    fake_logfire = MagicMock()
    metric = SimpleNamespace(
        metric_type="request_count",
        value=1.0,
        endpoint=None,
        tags={"endpoint": "/api/items", "method": "GET"},
    )
    with (
        patch.object(module, "_logfire_available", True),
        patch.object(module, "logfire", fake_logfire),
    ):
        handler = module.LogfireHandler(
            config=SimpleNamespace(logfire_service_name="svc")
        )
        handler.send_metric(metric)

    _, kwargs = fake_logfire.info.call_args
    assert kwargs["endpoint"] == "/api/items"
    assert kwargs["method"] == "GET"


def test_send_metric_handles_missing_tags() -> None:
    module = _fresh_logfire_handler_module()
    fake_logfire = MagicMock()
    metric = SimpleNamespace(
        metric_type="request_count",
        value=1,
        endpoint="",
        tags=None,
    )
    with (
        patch.object(module, "_logfire_available", True),
        patch.object(module, "logfire", fake_logfire),
    ):
        handler = module.LogfireHandler(
            config=SimpleNamespace(logfire_service_name="svc")
        )
        handler.send_metric(metric)
    fake_logfire.info.assert_called_once_with(
        "guard.metric.request_count", value=1, endpoint=""
    )


def test_send_metric_does_not_call_logfire_metric() -> None:
    module = _fresh_logfire_handler_module()
    fake_logfire = MagicMock(spec=["info", "span", "configure"])
    metric = SimpleNamespace(
        metric_type="response_time",
        value=0.1,
        endpoint="",
        tags={},
    )
    with (
        patch.object(module, "_logfire_available", True),
        patch.object(module, "logfire", fake_logfire),
    ):
        handler = module.LogfireHandler(
            config=SimpleNamespace(logfire_service_name="svc")
        )
        handler.send_metric(metric)

    assert not hasattr(fake_logfire, "metric") or not fake_logfire.metric.called
