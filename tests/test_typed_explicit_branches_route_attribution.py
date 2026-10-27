from operator import methodcaller

import pytest

from guard_core.decorators.route_config import RouteConfigRevision, _TrackedList
from guard_core.handlers._dynamic_rule_attribution import build_rule_attribution
from tests.test_event_attribution import _config, _rules


def test_a_static_field_that_is_not_iterable_is_refused_by_name() -> None:
    with pytest.raises(TypeError, match="blocked_countries .* must be iterable"):
        build_rule_attribution(_rules(), _config(), [], [], {"blocked_countries": 5})


def test_static_endpoint_limits_that_are_not_a_mapping_are_refused_by_name() -> None:
    with pytest.raises(TypeError, match="endpoint_rate_limits .* must be a mapping"):
        build_rule_attribution(
            _rules(), _config(), [], [], {"endpoint_rate_limits": [("/x", 5)]}
        )


def test_a_slice_assignment_of_a_non_iterable_is_refused_and_counted() -> None:
    revision = RouteConfigRevision()
    tracked = _TrackedList([1, 2, 3], revision=revision)

    with pytest.raises(TypeError, match="must assign iterable to extended slice"):
        methodcaller("__setitem__", slice(0, 2), 5)(tracked)

    assert tracked == [1, 2, 3]
    assert revision.value == 1


def test_a_slice_assignment_of_an_iterable_replaces_the_slice_and_counts() -> None:
    revision = RouteConfigRevision()
    tracked = _TrackedList([1, 2, 3], revision=revision)

    tracked[0:2] = (7, 8, 9)
    tracked[0] = 0

    assert tracked == [0, 8, 9, 3]
    assert revision.value == 2
