from unittest.mock import MagicMock

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.route_gate import (
    declared_path_param_spans,
    isolate_declared_path_params,
    route_knowledge,
)
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.decorators.base import RouteConfig
from tests.test_sync.conftest import SyncMockGuardRequest

CATEGORY = "path_traversal"


def test_a_declared_name_missing_from_the_template_gets_no_span() -> None:
    declared = {"name": frozenset({CATEGORY}), "ghost": frozenset({CATEGORY})}
    with route_knowledge("/files/{name}", declared_path_params=declared):
        spans = declared_path_param_spans("/files/abc", CATEGORY)

    assert set(spans) == {"name"}


def test_a_declared_name_outside_the_asked_category_gets_no_span() -> None:
    declared = {"name": frozenset({"xss"})}
    with route_knowledge("/files/{name}", declared_path_params=declared):
        spans = declared_path_param_spans("/files/abc", CATEGORY)

    assert spans == {}


def test_the_query_string_stays_untouched_when_a_path_param_is_isolated() -> None:
    declared = {"name": frozenset({CATEGORY})}
    with route_knowledge("/files/{name}", declared_path_params=declared):
        isolated = isolate_declared_path_params("/files/abc?x=../etc", CATEGORY)

    assert isolated is not None
    assert isolated[1].endswith("?x=../etc")


def test_a_request_without_a_route_template_reports_no_root_path_param() -> None:
    middleware = MagicMock()
    middleware.config = SyncSecurityConfig(enable_redis=False)
    check = SuspiciousActivityCheck(middleware)
    route_config = RouteConfig()
    route_config.excluded_detection_path_params = {"name"}

    check._report_declared_path_param_problems(
        SyncMockGuardRequest(path="/x"), route_config
    )

    assert check._reported_path_param_problems == set()


def test_a_declared_group_that_did_not_take_part_in_the_match_gets_no_span() -> None:
    declared = {"opt": frozenset({CATEGORY}), "rest": frozenset({CATEGORY})}
    with route_knowledge(
        "/files/(?P<opt>zz)?(?P<rest>[a-z]+)", declared_path_params=declared
    ):
        spans = declared_path_param_spans("/files/abc", CATEGORY)

    assert set(spans) == {"rest"}
