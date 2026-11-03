from collections.abc import Callable

import pytest

from guard_core.decorators.base import GuardedParams, GuardedReturn, RouteConfig
from guard_core.decorators.content_filtering import ContentFilteringMixin
from guard_core.models import SecurityConfig


class _Decorators(ContentFilteringMixin):
    def _ensure_route_config(self, _func: object) -> RouteConfig:
        return RouteConfig()

    def _apply_route_config(
        self, func: Callable[GuardedParams, GuardedReturn]
    ) -> Callable[GuardedParams, GuardedReturn]:
        return func


_BAD_MAPS: list[tuple[dict[str, set[str]], str]] = [
    ({"q": {"nope"}}, "Unknown detection categories for {option} 'q'"),
    ({"q": set()}, "{option} lists no category for 'q'"),
]


@pytest.mark.parametrize(
    "option", ["excluded_detection_params", "excluded_detection_body_fields"]
)
@pytest.mark.parametrize(("value", "message"), _BAD_MAPS)
def test_the_config_error_names_the_option_it_validates(
    option: str, value: dict[str, set[str]], message: str
) -> None:
    with pytest.raises(ValueError, match=message.format(option=option)):
        SecurityConfig.model_validate({option: value})

    config = SecurityConfig()
    with pytest.raises(ValueError, match=message.format(option=option)):
        setattr(config, option, value)


@pytest.mark.parametrize(
    ("argument", "option"),
    [
        ("params", "excluded_detection_params"),
        ("body_fields", "excluded_detection_body_fields"),
    ],
)
@pytest.mark.parametrize(("value", "message"), _BAD_MAPS)
def test_the_decorator_error_names_the_option_it_validates(
    argument: str, option: str, value: dict[str, set[str]], message: str
) -> None:
    with pytest.raises(ValueError, match=message.format(option=option)):
        if argument == "params":
            _Decorators().detection_exclusion(params=value)(lambda: None)
        else:
            _Decorators().detection_exclusion(body_fields=value)(lambda: None)
