"""One worker process of the cross-worker ban attribution pin (sync tree): it
applies rule R on "apply" and answers "ask" with the stamp for the rule's IP."""

import json
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync._utils import rule_attribution as attribution
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.handlers.redis_handler import RedisManager

RULE_IP = "198.51.100.21"


def main(url: str, prefix: str, duration: int) -> None:
    config = SecurityConfig(
        redis_url=url,
        redis_prefix=prefix,
        enable_redis=True,
        enable_agent=True,
        agent_api_key="k",
        enable_dynamic_rules=True,
        rate_limit=10,
        ban_on_hostile_signals=False,
    )
    redis_handler = RedisManager(config)
    redis_handler.initialize()
    ip_ban_manager.config = config
    ip_ban_manager.redis_handler = redis_handler
    manager = DynamicRuleManager(config)
    manager.redis_handler = redis_handler
    agent = MagicMock()
    agent.send_event = MagicMock()
    agent.get_dynamic_rules = MagicMock(
        return_value=DynamicRules(
            rule_id="R",
            version=1,
            timestamp=datetime.now(timezone.utc),
            ip_blacklist=[RULE_IP],
            ip_ban_duration=duration,
        )
    )
    manager.agent_handler = agent
    print(json.dumps({"ready": True}), flush=True)
    for line in sys.stdin:
        if line.strip() == "apply":
            manager.update_rules()
            reply: dict[str, object] = {"owned": manager._owned_bans}
        else:
            banned = ip_ban_manager.is_ip_banned(RULE_IP)
            view = attribution._applied
            stamp = view.for_ban(RULE_IP, ip_ban_manager) if view else None
            reply = {"banned": banned, "stamp": stamp}
        print(json.dumps(reply), flush=True)
    redis_handler.close()


main(sys.argv[1], sys.argv[2], int(sys.argv[3]))
