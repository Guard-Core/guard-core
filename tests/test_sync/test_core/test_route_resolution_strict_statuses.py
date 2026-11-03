from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.implementations.route_config import RouteConfigCheck
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest

_ROUTE_CONFIG = "guard_core.sync.core.checks.implementations.route_config"
_PREFLIGHT_HEADERS = {
    "origin": "https://app.example.com",
    "access-control-request-method": "POST",
}


def _middleware(
    resolved_paths: set[str] | None,
    allowed: dict[str, tuple[str, ...]] | None = None,
    **config: object,
) -> MagicMock:
    mw = MagicMock()
    mw.config = SyncSecurityConfig(
        enable_redis=False, route_resolution_strict=True, **config
    )
    mw.logger = MagicMock()
    mw.event_bus.send_middleware_event = MagicMock()
    mw.agent_handler = None
    mw.route_resolver.get_route_config = MagicMock(return_value=None)
    mw.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code
        )
    )
    mw.allowed_methods = MagicMock(
        side_effect=lambda path: (allowed or {}).get(path, ())
    )
    if resolved_paths is None:
        del mw.resolve_route
    else:
        mw.resolve_route = MagicMock(
            side_effect=lambda path: (
                (("endpoint", ()),) if path in resolved_paths else ()
            )
        )
    return mw


def _check(mw: MagicMock, request: SyncMockGuardRequest) -> GuardResponse | None:
    request.state.guard_route_unresolved = True
    with (
        patch(f"{_ROUTE_CONFIG}.extract_client_ip", MagicMock(return_value="1.2.3.4")),
        patch(f"{_ROUTE_CONFIG}.log_activity", MagicMock()),
    ):
        return RouteConfigCheck(mw).check(request)


def test_a_path_no_route_serves_is_answered_404() -> None:
    response = _check(_middleware({"/ok"}), SyncMockGuardRequest(path="/nope"))

    assert response is not None
    assert response.status_code == 404


def test_a_wrong_method_on_a_served_path_is_answered_405() -> None:
    response = _check(
        _middleware({"/ok"}), SyncMockGuardRequest(path="/ok", method="POST")
    )

    assert response is not None
    assert response.status_code == 405


def test_a_405_lists_the_methods_the_route_accepts_in_allow() -> None:
    mw = _middleware({"/ok"}, {"/ok": ("POST", "GET", "HEAD")})

    response = _check(mw, SyncMockGuardRequest(path="/ok", method="DELETE"))

    assert response is not None
    assert response.status_code == 405
    assert response.headers["Allow"] == "GET, HEAD, POST"
    mw.allowed_methods.assert_called_once_with("/ok")


def test_a_404_carries_no_allow() -> None:
    mw = _middleware({"/ok"}, {"/ok": ("GET",)})

    response = _check(mw, SyncMockGuardRequest(path="/nope"))

    assert response is not None
    assert "Allow" not in response.headers
    mw.allowed_methods.assert_not_called()


def test_a_405_from_an_adapter_without_method_lookup_has_no_allow() -> None:
    mw = _middleware({"/ok"})
    del mw.allowed_methods

    response = _check(mw, SyncMockGuardRequest(path="/ok", method="POST"))

    assert response is not None
    assert response.status_code == 405
    assert "Allow" not in response.headers


def test_a_failing_method_lookup_keeps_the_405_and_logs_it() -> None:
    mw = _middleware({"/ok"})
    mw.allowed_methods = MagicMock(side_effect=RuntimeError("router gone"))

    response = _check(mw, SyncMockGuardRequest(path="/ok", method="POST"))

    assert response is not None
    assert response.status_code == 405
    assert "Allow" not in response.headers
    mw.logger.error.assert_called_once_with("allowed_methods failed; omitting Allow")


def test_an_adapter_without_route_lookup_gets_404() -> None:
    response = _check(_middleware(None), SyncMockGuardRequest(path="/ok"))

    assert response is not None
    assert response.status_code == 404


def test_a_matched_route_the_decorator_does_not_know_is_a_500() -> None:
    mw = _middleware({"/ok"})
    request = SyncMockGuardRequest(path="/ok")
    request.state.guard_route_id = "app.handler"

    response = _check(mw, request)

    assert response is not None
    assert response.status_code == 500
    mw.resolve_route.assert_not_called()


def test_a_failing_route_lookup_still_blocks_with_500() -> None:
    mw = _middleware({"/ok"})
    mw.resolve_route = MagicMock(side_effect=RuntimeError("router gone"))

    response = _check(mw, SyncMockGuardRequest(path="/ok"))

    assert response is not None
    assert response.status_code == 500


def test_the_route_lookup_receives_the_request_path_and_method_blind() -> None:
    mw = _middleware({"/ok"})

    _check(mw, SyncMockGuardRequest(path="/ok", method="POST"))

    mw.resolve_route.assert_called_once_with("/ok")


def test_the_unresolved_event_and_log_are_kept() -> None:
    mw = _middleware({"/ok"})

    _check(mw, SyncMockGuardRequest(path="/nope"))

    event = mw.event_bus.send_middleware_event.call_args.kwargs
    assert event["event_type"] == "route_unresolved"
    assert event["action_taken"] == "request_blocked"


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_a_resolved_route_is_not_blocked(method: str) -> None:
    mw = _middleware({"/ok"})
    request = SyncMockGuardRequest(path="/ok", method=method)

    with (
        patch(f"{_ROUTE_CONFIG}.extract_client_ip", MagicMock(return_value="1.2.3.4")),
        patch(f"{_ROUTE_CONFIG}.log_activity", MagicMock()),
    ):
        assert RouteConfigCheck(mw).check(request) is None


def test_a_preflight_is_not_blocked_by_the_strict_check() -> None:
    mw = _middleware(
        {"/ok"},
        enable_cors=True,
        cors_allow_origins=["https://app.example.com"],
    )
    request = SyncMockGuardRequest(
        path="/ok", method="OPTIONS", headers=_PREFLIGHT_HEADERS
    )

    assert _check(mw, request) is None
    mw.event_bus.send_middleware_event.assert_not_called()


def test_a_preflight_is_blocked_when_cors_is_off() -> None:
    mw = _middleware({"/ok"})
    request = SyncMockGuardRequest(
        path="/ok", method="OPTIONS", headers=_PREFLIGHT_HEADERS
    )

    response = _check(mw, request)

    assert response is not None
    assert response.status_code == 405


def test_passive_mode_still_only_logs() -> None:
    mw = _middleware({"/ok"}, passive_mode=True)

    assert _check(mw, SyncMockGuardRequest(path="/nope")) is None
    assert (
        mw.event_bus.send_middleware_event.call_args.kwargs["action_taken"]
        == "logged_only"
    )
