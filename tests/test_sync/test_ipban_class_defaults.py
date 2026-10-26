from guard_core.sync.handlers._ipban_bans import IpBanOperationsMixin
from guard_core.sync.handlers._ipban_events import IpBanEventMixin
from guard_core.sync.handlers.ipban_handler import IPBanManager


def test_a_fresh_ban_manager_has_no_config_and_no_redis_until_one_is_bound() -> None:
    manager = IPBanManager._fresh()
    assert manager.config is None
    assert manager.redis_handler is None
    assert IpBanOperationsMixin.redis_handler is None


def test_the_event_mixin_has_no_agent_until_one_is_initialized() -> None:
    assert IpBanEventMixin.agent_handler is None
