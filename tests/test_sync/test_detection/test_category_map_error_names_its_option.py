from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.decorators.content_filtering import ContentFilteringMixin


class _Decorators(ContentFilteringMixin):
    def _ensure_route_config(self, _func: Any) -> RouteConfig:
        return RouteConfig()

    def _apply_route_config(self, func: Any) -> Any:
        return func


_BAD_MAPS = [
    ({"q": {"nope"}}, "Unknown detection categories for {option} 'q'"),
    ({"q": set()}, "{option} lists no category for 'q'"),
]


@pytest.mark.parametrize(
    "option", ["excluded_detection_params", "excluded_detection_body_fields"]
)
@pytest.mark.parametrize(("value", "message"), _BAD_MAPS)
def test_the_config_error_names_the_option_it_validates(
    option: str, value: Any, message: str
) -> None:
    with pytest.raises(ValueError, match=message.format(option=option)):
        SecurityConfig(**{option: value})

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
    argument: str, option: str, value: Any, message: str
) -> None:
    with pytest.raises(ValueError, match=message.format(option=option)):
        _Decorators().detection_exclusion(**{argument: value})(lambda: None)
