import pytest

from guard_core.decorators.route_config import RouteConfig


@pytest.mark.parametrize(
    "restrictions",
    [
        {"start": "25:99", "end": "17:00"},
        {"start": "09:00", "end": "9pm"},
        {"start": "09:00", "end": "17:00", "timezone": "Mars/Olympus"},
        {"end": "17:00"},
        {"start": None, "end": "17:00"},
    ],
)
def test_direct_assignment_of_a_bad_window_raises(restrictions: dict) -> None:
    route_config = RouteConfig()

    with pytest.raises(ValueError, match="time_restrictions"):
        route_config.time_restrictions = restrictions

    assert route_config.time_restrictions is None


def test_direct_assignment_of_a_valid_window_works() -> None:
    route_config = RouteConfig()

    route_config.time_restrictions = {"start": "09:00", "end": "17:00"}
    route_config.time_restrictions = {
        "start": "22:00",
        "end": "06:00",
        "timezone": "Europe/Berlin",
    }
    route_config.time_restrictions = None

    assert route_config.time_restrictions is None
