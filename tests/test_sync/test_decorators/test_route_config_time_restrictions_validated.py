import pytest

from guard_core.sync.decorators.route_config import RouteConfig, RouteConfigRevision


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


@pytest.mark.parametrize("restrictions", ["09:00-17:00", ["09:00", "17:00"], 9])
def test_direct_assignment_of_a_non_dict_window_is_refused(
    restrictions: object,
) -> None:
    route_config = RouteConfig()

    with pytest.raises(ValueError, match="is not a dict"):
        route_config.__setattr__("time_restrictions", restrictions)

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


def _window() -> tuple[RouteConfigRevision, RouteConfig]:
    revision = RouteConfigRevision()
    route_config = RouteConfig(revision)
    route_config.time_restrictions = {"start": "09:00", "end": "17:00"}
    return revision, route_config


def _window_of(route_config: RouteConfig) -> dict[str, str]:
    window = route_config.time_restrictions
    assert window is not None
    return window


def test_item_mutations_leaving_a_bad_window_raise_and_change_nothing() -> None:
    mutations = [
        lambda d: d.__setitem__("start", "25:99"),
        lambda d: d.__setitem__("timezone", "Mars/Olympus"),
        lambda d: d.__delitem__("end"),
        lambda d: d.update(end="9pm"),
        lambda d: d.pop("start"),
        lambda d: d.__ior__({"start": None}),
    ]
    for mutation in mutations:
        _, route_config = _window()
        with pytest.raises(ValueError, match="time_restrictions"):
            mutation(_window_of(route_config))
        assert route_config.time_restrictions == {"start": "09:00", "end": "17:00"}


def test_a_valid_item_set_works_and_bumps_the_revision() -> None:
    revision, route_config = _window()
    revision.value = 0

    window = _window_of(route_config)
    window["start"] = "08:30"
    window.setdefault("timezone", "Europe/Berlin")

    assert window["start"] == "08:30"
    assert window["timezone"] == "Europe/Berlin"
    assert revision.value == 2
