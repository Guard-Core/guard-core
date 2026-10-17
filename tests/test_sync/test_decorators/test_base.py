from unittest.mock import Mock

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.decorators.base import (
    BaseSecurityDecorator,
    BaseSecurityMixin,
    RouteConfig,
    RouteConfigRevision,
    _TrackedDict,
    _TrackedList,
    _TrackedSet,
    get_route_decorator_config,
)
from tests.test_sync.conftest import SyncMockGuardRequest


def test_route_config_initialization() -> None:
    config = RouteConfig()

    assert config.rate_limit is None
    assert config.rate_limit_window is None
    assert config.ip_whitelist is None
    assert config.ip_blacklist is None
    assert config.blocked_countries is None
    assert config.whitelist_countries is None
    assert config.bypassed_checks == set()
    assert config.require_https is False
    assert config.auth_required is None
    assert config.custom_validators == []
    assert config.blocked_user_agents == []
    assert config.required_headers == {}
    assert config.behavior_rules == []
    assert config.block_cloud_providers == set()
    assert config.max_request_size is None
    assert config.allowed_content_types is None
    assert config.time_restrictions is None
    assert config.enable_suspicious_detection is True
    assert config.require_referrer is None
    assert config.api_key_required is False


def test_route_config_auth_verifier_defaults() -> None:
    config = RouteConfig()
    assert config.auth_verifier is None
    assert config.api_key_verifier is None
    assert config.api_key_header is None
    assert config.authorization_header_required is None


def test_route_config_auth_verifier_settable() -> None:
    def verifier(request: object, credential: str) -> object:
        return credential

    config = RouteConfig()
    config.auth_verifier = verifier
    config.api_key_verifier = verifier
    config.api_key_header = "X-API-Key"
    config.authorization_header_required = "bearer"
    assert config.auth_verifier is verifier
    assert config.api_key_verifier is verifier
    assert config.api_key_header == "X-API-Key"
    assert config.authorization_header_required == "bearer"


def test_base_security_mixin_not_implemented() -> None:
    mixin = BaseSecurityMixin()

    mock_func = Mock()

    with pytest.raises(
        NotImplementedError, match="This mixin must be used with BaseSecurityDecorator"
    ):
        mixin._ensure_route_config(mock_func)

    with pytest.raises(
        NotImplementedError, match="This mixin must be used with BaseSecurityDecorator"
    ):
        mixin._apply_route_config(mock_func)


def test_base_security_decorator(security_config: SecurityConfig) -> None:
    decorator = BaseSecurityDecorator(security_config)

    assert decorator.config == security_config
    assert decorator._route_configs == {}
    assert decorator.behavior_tracker is not None

    mock_func = Mock()
    mock_func.__module__ = "test_module"
    mock_func.__qualname__ = "test_function"

    route_id = decorator._get_route_id(mock_func)
    assert route_id == "test_module.test_function"

    route_config = decorator._ensure_route_config(mock_func)
    assert isinstance(route_config, RouteConfig)
    assert (
        route_config.enable_suspicious_detection
        == security_config.enable_penetration_detection
    )

    route_config2 = decorator._ensure_route_config(mock_func)
    assert route_config is route_config2

    retrieved_config = decorator.get_route_config(route_id)
    assert retrieved_config is route_config

    non_existent_config = decorator.get_route_config("non.existent.route")
    assert non_existent_config is None

    decorated_func = decorator._apply_route_config(mock_func)
    assert decorated_func is mock_func
    assert hasattr(decorated_func, "_guard_route_id")
    assert decorated_func._guard_route_id == route_id


def test_get_route_decorator_config() -> None:
    security_config = SecurityConfig()
    decorator = BaseSecurityDecorator(security_config)

    mock_request = SyncMockGuardRequest()
    result = get_route_decorator_config(mock_request, decorator)
    assert result is None

    route_id = "test.route.id"
    route_config = decorator._ensure_route_config(
        Mock(__module__="test", __qualname__="route")
    )
    decorator._route_configs[route_id] = route_config

    mock_request._state.guard_route_id = route_id
    result = get_route_decorator_config(mock_request, decorator)
    assert result is route_config


def test_initialize_behavior_tracking(security_config: SecurityConfig) -> None:
    decorator = BaseSecurityDecorator(security_config)

    decorator.initialize_behavior_tracking()

    mock_redis_handler = Mock()
    decorator.initialize_behavior_tracking(mock_redis_handler)


def test_route_config_construction_does_not_bump_revision() -> None:
    revision = RouteConfigRevision()

    RouteConfig(revision)

    assert revision.value == 0


def test_route_config_attribute_assignment_bumps_revision() -> None:
    revision = RouteConfigRevision()
    route_config = RouteConfig(revision)

    route_config.auth_required = "bearer"

    assert revision.value == 1
    assert route_config.auth_required == "bearer"


def test_route_config_without_a_revision_cell_does_not_raise() -> None:
    route_config = RouteConfig()

    route_config.auth_required = "bearer"
    route_config.custom_validators.append(lambda request: None)
    route_config.required_headers["X-Api-Key"] = "required"

    assert route_config.auth_required == "bearer"
    assert len(route_config.custom_validators) == 1
    assert route_config.required_headers == {"X-Api-Key": "required"}


@pytest.mark.parametrize(
    "field_name",
    [
        "custom_validators",
        "require_referrer",
        "allowed_content_types",
        "blocked_user_agents",
    ],
)
def test_appending_to_a_tracked_list_field_bumps_revision(
    field_name: str,
) -> None:
    revision = RouteConfigRevision()
    route_config = RouteConfig(revision)
    setattr(route_config, field_name, [])
    revision.value = 0

    getattr(route_config, field_name).append("value")

    assert revision.value == 1
    assert getattr(route_config, field_name) == ["value"]


@pytest.mark.parametrize(
    "field_name", ["required_headers", "time_restrictions", "geo_rate_limits"]
)
def test_setting_an_item_on_a_tracked_dict_field_bumps_revision(
    field_name: str,
) -> None:
    revision = RouteConfigRevision()
    route_config = RouteConfig(revision)
    setattr(route_config, field_name, {})
    revision.value = 0

    getattr(route_config, field_name)["key"] = "value"

    assert revision.value == 1
    assert getattr(route_config, field_name) == {"key": "value"}


def test_adding_to_a_tracked_set_field_bumps_revision() -> None:
    revision = RouteConfigRevision()
    route_config = RouteConfig(revision)
    revision.value = 0

    route_config.block_cloud_providers.add("AWS")

    assert revision.value == 1
    assert route_config.block_cloud_providers == {"AWS"}


def test_mutating_an_untracked_container_field_does_not_bump_revision() -> None:
    revision = RouteConfigRevision()
    route_config = RouteConfig(revision)
    route_config.ip_whitelist = ["203.0.113.1"]
    revision.value = 0

    route_config.ip_whitelist.append("203.0.113.2")

    assert revision.value == 0
    assert route_config.ip_whitelist == ["203.0.113.1", "203.0.113.2"]


def test_route_config_revision_bumps_when_ensure_route_config_adds_a_new_route(
    security_config: SecurityConfig,
) -> None:
    decorator = BaseSecurityDecorator(security_config)
    assert decorator.route_config_revision == 0

    mock_func = Mock(__module__="test_module", __qualname__="new_route")
    decorator._ensure_route_config(mock_func)

    revision_after_first_call = decorator.route_config_revision
    assert revision_after_first_call > 0

    decorator._ensure_route_config(mock_func)

    assert decorator.route_config_revision == revision_after_first_call


def test_mutating_a_route_config_obtained_from_the_decorator_bumps_its_revision(
    security_config: SecurityConfig,
) -> None:
    decorator = BaseSecurityDecorator(security_config)
    mock_func = Mock(__module__="test_module", __qualname__="existing_route")
    route_config = decorator._ensure_route_config(mock_func)
    revision_before = decorator.route_config_revision

    route_config.auth_required = "bearer"

    assert decorator.route_config_revision > revision_before


def test_tracked_list_mutators_all_bump_the_shared_revision() -> None:
    revision = RouteConfigRevision()
    tracked = _TrackedList([1, 2, 3], revision=revision)

    tracked.append(4)
    assert revision.value == 1

    tracked.extend([5])
    assert revision.value == 2

    tracked.insert(0, 0)
    assert revision.value == 3

    tracked.remove(0)
    assert revision.value == 4

    tracked.pop()
    assert revision.value == 5

    tracked[0] = 99
    assert revision.value == 6

    del tracked[0]
    assert revision.value == 7

    tracked.sort()
    assert revision.value == 8

    tracked.reverse()
    assert revision.value == 9

    tracked += [7]
    assert revision.value == 10
    assert isinstance(tracked, _TrackedList)

    tracked *= 2
    assert revision.value == 11
    assert isinstance(tracked, _TrackedList)

    tracked.clear()
    assert revision.value == 12
    assert tracked == []


def test_tracked_list_non_augmented_operators_do_not_bump_revision() -> None:
    revision = RouteConfigRevision()
    tracked = _TrackedList([1, 2], revision=revision)

    combined = tracked + [3]
    assert revision.value == 0
    assert combined == [1, 2, 3]

    doubled = tracked * 2
    assert revision.value == 0
    assert doubled == [1, 2, 1, 2]


def test_tracked_list_without_a_revision_cell_is_a_no_op() -> None:
    tracked = _TrackedList([1])

    tracked.append(2)

    assert tracked == [1, 2]


def test_tracked_dict_mutators_all_bump_the_shared_revision() -> None:
    revision = RouteConfigRevision()
    tracked = _TrackedDict({"a": 1}, revision=revision)

    tracked["b"] = 2
    assert revision.value == 1

    del tracked["b"]
    assert revision.value == 2

    tracked.update({"c": 3})
    assert revision.value == 3

    tracked.setdefault("d", 4)
    assert revision.value == 4

    tracked.pop("d")
    assert revision.value == 5

    tracked.popitem()
    assert revision.value == 6

    tracked |= {"e": 5}
    assert revision.value == 7
    assert isinstance(tracked, _TrackedDict)

    tracked.clear()
    assert revision.value == 8
    assert tracked == {}


def test_tracked_dict_non_augmented_or_operator_does_not_bump_revision() -> None:
    revision = RouteConfigRevision()
    tracked = _TrackedDict({"a": 1}, revision=revision)

    merged = tracked | {"b": 2}

    assert revision.value == 0
    assert merged == {"a": 1, "b": 2}


def test_tracked_dict_without_a_revision_cell_is_a_no_op() -> None:
    tracked = _TrackedDict({"a": 1})

    tracked["b"] = 2

    assert tracked == {"a": 1, "b": 2}


def test_tracked_set_mutators_all_bump_the_shared_revision() -> None:
    revision = RouteConfigRevision()
    tracked = _TrackedSet({1, 2, 3}, revision=revision)

    tracked.add(4)
    assert revision.value == 1

    tracked.discard(4)
    assert revision.value == 2

    tracked.remove(1)
    assert revision.value == 3

    tracked.update({5, 6})
    assert revision.value == 4

    tracked.intersection_update({2, 3, 5, 6})
    assert revision.value == 5
    assert tracked == {2, 3, 5, 6}

    tracked.difference_update({5})
    assert revision.value == 6
    assert tracked == {2, 3, 6}

    tracked.symmetric_difference_update({3, 7})
    assert revision.value == 7
    assert tracked == {2, 6, 7}

    tracked |= {8}
    assert revision.value == 8
    assert isinstance(tracked, _TrackedSet)

    tracked &= {2, 6, 7, 8}
    assert revision.value == 9
    assert isinstance(tracked, _TrackedSet)

    tracked -= {8}
    assert revision.value == 10
    assert isinstance(tracked, _TrackedSet)

    tracked ^= {6}
    assert revision.value == 11
    assert isinstance(tracked, _TrackedSet)
    assert tracked == {2, 7}

    tracked.pop()
    assert revision.value == 12

    tracked.clear()
    assert revision.value == 13
    assert tracked == set()


def test_tracked_set_non_augmented_operators_do_not_bump_revision() -> None:
    revision = RouteConfigRevision()
    tracked = _TrackedSet({1, 2, 3}, revision=revision)

    assert tracked | {4} == {1, 2, 3, 4}
    assert revision.value == 0

    assert tracked & {2, 3} == {2, 3}
    assert revision.value == 0

    assert tracked - {1} == {2, 3}
    assert revision.value == 0

    assert tracked ^ {3, 4} == {1, 2, 4}
    assert revision.value == 0


def test_tracked_set_without_a_revision_cell_is_a_no_op() -> None:
    tracked = _TrackedSet({1})

    tracked.add(2)

    assert tracked == {1, 2}
