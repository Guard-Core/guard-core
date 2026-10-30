import pytest

from guard_core.decorators import SecurityDecorator
from guard_core.models import SecurityConfig


def _target() -> None:
    pass


def _decorator(*, refuse: bool) -> SecurityDecorator:
    return SecurityDecorator(
        SecurityConfig(enable_redis=False, fail_on_misconfiguration=refuse)
    )


def test_an_empty_block_countries_list_is_refused_like_allow_countries() -> None:
    decorator = _decorator(refuse=True)

    with pytest.raises(ValueError, match="empty country list"):
        decorator.block_countries([])(_target)
    with pytest.raises(ValueError, match="empty country list"):
        decorator.allow_countries([])(_target)


def test_an_empty_block_clouds_list_is_refused() -> None:
    with pytest.raises(ValueError, match="empty provider list"):
        _decorator(refuse=True).block_clouds([])(_target)


def test_block_clouds_without_a_list_still_blocks_every_provider() -> None:
    decorator = _decorator(refuse=True)

    decorated = decorator.block_clouds()(_target)

    route_config = decorator.get_route_config(decorator._get_route_id(decorated))
    assert route_config is not None
    assert route_config.block_cloud_providers


def test_the_empty_lists_only_warn_when_the_refusal_is_off(
    caplog: pytest.LogCaptureFixture,
) -> None:
    decorator = _decorator(refuse=False)

    decorator.block_countries([])(_target)
    decorator.block_clouds([])(_target)

    assert "empty country list" in caplog.text
    assert "empty provider list" in caplog.text
