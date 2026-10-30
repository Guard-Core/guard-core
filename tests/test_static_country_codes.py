from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from guard_core.models import SecurityConfig


@pytest.mark.parametrize("field", ["blocked_countries", "whitelist_countries"])
@pytest.mark.parametrize("code", ["USA", "U1", " US", "None", "", "NONE", "U", None, 7])
def test_a_static_country_entry_that_is_not_a_two_letter_code_is_refused(
    field: str, code: object
) -> None:
    with pytest.raises(ValidationError, match="two-letter"):
        SecurityConfig(**{field: [code]}, geo_ip_handler=MagicMock())


@pytest.mark.parametrize("field", ["blocked_countries", "whitelist_countries"])
def test_a_two_letter_entry_is_accepted_and_upper_cased(field: str) -> None:
    config = SecurityConfig(**{field: ["us", "De"]}, geo_ip_handler=MagicMock())

    assert getattr(config, field) == frozenset({"US", "DE"})


def test_an_assignment_is_held_to_the_same_rule() -> None:
    config = SecurityConfig(geo_ip_handler=MagicMock())
    name = "blocked_countries"

    with pytest.raises(ValueError):
        setattr(config, name, {"USA"})
