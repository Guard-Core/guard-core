import pytest
from pydantic import ValidationError

from guard_core.models import SecurityConfig

ACCEPTED: dict[str, dict[str, object] | None] = {
    "none": None,
    "empty": {},
    "default_like": {"enabled": True, "hsts": {"max_age": 1}, "csp": None},
    "disabled_with_junk": {"enabled": False, "frame_options": 5, "csp": "x"},
    "hsts_none": {"hsts": None},
    "falsy_csp": {"csp": ""},
    "falsy_custom": {"custom": []},
    "full": {
        "csp": {"default-src": ["'self'"]},
        "hsts": {"max_age": 1, "include_subdomains": False, "preload": False},
        "custom": {"X-A": "b"},
        "permissions_policy": "",
    },
}

REFUSED: dict[str, tuple[dict[str, object] | str | int, str]] = {
    "named_not_string": ({"frame_options": 5}, "the frame_options setting must be"),
    "csp_not_mapping": ({"csp": "x"}, "the csp setting must map each directive"),
    "hsts_not_mapping": ({"hsts": "x"}, "the hsts setting must be a mapping"),
    "custom_not_mapping": ({"custom": "x"}, "the custom setting must map header"),
    "custom_value_not_string": ({"custom": {"X-A": 1}}, "must be strings"),
    "bad_header_name": ({"custom": {"bad name": "v"}}, "Invalid header name"),
    "newline_value": ({"frame_options": "a\nb"}, "contains newline"),
    "too_long": ({"frame_options": "a" * 9000}, "Header value too long"),
    "not_a_dict": ("x", "security_headers"),
    "an_int": (3, "security_headers"),
}


@pytest.mark.parametrize("case", ACCEPTED)
def test_every_shape_accepted_before_is_still_accepted(case: str) -> None:
    value = ACCEPTED[case]

    config = SecurityConfig(enable_redis=False, security_headers=value)

    assert config.security_headers == value


@pytest.mark.parametrize("case", REFUSED)
def test_every_shape_refused_before_keeps_its_message(case: str) -> None:
    value, message = REFUSED[case]

    with pytest.raises(ValidationError) as refused:
        SecurityConfig(enable_redis=False, security_headers=value)

    assert message in str(refused.value)
