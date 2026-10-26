from guard_core.handlers._ipban_bans import IpBanOperationsMixin
from guard_core.handlers._ipban_events import IpBanEventMixin


def test_the_ban_mixin_has_no_config_and_no_redis_until_a_manager_sets_them() -> None:
    assert IpBanOperationsMixin.config is None
    assert IpBanOperationsMixin.redis_handler is None


def test_the_event_mixin_has_no_agent_until_one_is_initialized() -> None:
    assert IpBanEventMixin.agent_handler is None
