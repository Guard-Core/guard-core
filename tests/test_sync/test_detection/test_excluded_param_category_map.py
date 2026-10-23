from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.decorators.content_filtering import ContentFilteringMixin
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

SQLI = "' OR 1=1 --"
XSS = "<script>alert(1)</script>"


def _flagged(
    params: dict[str, str],
    config: SyncSecurityConfig,
    route_config: RouteConfig | None = None,
) -> bool:
    request = SyncMockGuardRequest(path="/s", query_params=params)
    return (detect_penetration_attempt(request, config, route_config)).is_threat


def test_a_plain_set_still_excludes_every_category() -> None:
    config = SyncSecurityConfig(excluded_detection_params={"q"})

    assert _flagged({"q": SQLI}, config) is False
    assert _flagged({"q": XSS}, config) is False
    assert _flagged({"r": SQLI}, config) is True


def test_a_category_map_excludes_only_the_listed_categories_of_that_param() -> None:
    config = SyncSecurityConfig(excluded_detection_params={"q": {"sqli"}})

    assert _flagged({"q": SQLI}, config) is False
    assert _flagged({"q": XSS}, config) is True
    assert _flagged({"r": SQLI}, config) is True


def test_a_category_map_may_list_several_categories_and_ignores_name_case() -> None:
    config = SyncSecurityConfig(excluded_detection_params={"Q": ["sqli", "xss"]})

    assert _flagged({"q": SQLI}, config) is False
    assert _flagged({"q": XSS}, config) is False
    assert _flagged({"q": "; cat /etc/passwd"}, config) is True


def test_the_name_of_the_param_is_scanned_with_the_same_categories() -> None:
    config = SyncSecurityConfig(excluded_detection_params={SQLI: {"sqli"}})

    assert _flagged({SQLI: "ok"}, config) is False
    assert _flagged({XSS: "ok"}, config) is True


def test_a_route_category_map_replaces_the_global_one() -> None:
    config = SyncSecurityConfig(excluded_detection_params={"q": {"sqli"}})
    route_config = RouteConfig()
    route_config.excluded_detection_params = {"q": {"xss"}}

    assert _flagged({"q": SQLI}, config, route_config) is True
    assert _flagged({"q": XSS}, config, route_config) is False


def test_the_decorator_accepts_a_category_map_and_copies_it() -> None:
    mapping = {"q": {"sqli"}}
    route_config = RouteConfig()

    class _Decorators(ContentFilteringMixin):
        def _ensure_route_config(self, _func: Any) -> RouteConfig:
            return route_config

        def _apply_route_config(self, func: Any) -> Any:
            return func

    _Decorators().detection_exclusion(params=mapping)(lambda: None)
    mapping["q"].add("xss")

    assert route_config.excluded_detection_params == {"q": {"sqli"}}


def test_the_decorator_rejects_an_unknown_category() -> None:
    class _Decorators(ContentFilteringMixin):
        def _ensure_route_config(self, _func: Any) -> RouteConfig:
            return RouteConfig()

        def _apply_route_config(self, func: Any) -> Any:
            return func

    with pytest.raises(ValueError, match="Unknown detection categories"):
        _Decorators().detection_exclusion(params={"q": {"nope"}})(lambda: None)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ({"q": {"nope"}}, "Unknown detection categories"),
        ({"q": set()}, "lists no category"),
        ({"q": []}, "lists no category"),
        ("q", "excluded_detection_params is invalid"),
        ({"q": "sqli"}, "excluded_detection_params is invalid"),
    ],
)
def test_the_config_rejects_a_bad_param_exclusion(value: Any, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        SyncSecurityConfig(excluded_detection_params=value)

    config = SyncSecurityConfig()
    with pytest.raises(ValueError, match=message):
        config.excluded_detection_params = value


def test_the_config_keeps_the_shape_it_was_given() -> None:
    assert SyncSecurityConfig(
        excluded_detection_params=["a", "b"]
    ).excluded_detection_params == {
        "a",
        "b",
    }
    assert SyncSecurityConfig(
        excluded_detection_params={"q": ["sqli"]}
    ).excluded_detection_params == {"q": {"sqli"}}
