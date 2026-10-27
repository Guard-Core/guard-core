"""One worker process of the cross-worker ban attribution pin (async tree): it
applies rule R on "apply" and answers "ask" with the stamp for the rule's IP."""

import asyncio
import json
import sys
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

from guard_core._utils import rule_attribution as attribution
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import DynamicRules, SecurityConfig

RULE_IP = "198.51.100.21"


async def main(url: str, prefix: str, duration: int) -> None:
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
    await redis_handler.initialize()
    ip_ban_manager.config = config
    ip_ban_manager.redis_handler = redis_handler
    manager = DynamicRuleManager(config)
    manager.redis_handler = redis_handler
    agent = MagicMock()
    agent.send_event = AsyncMock()
    agent.get_dynamic_rules = AsyncMock(
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
            await manager.update_rules()
            reply: dict[str, object] = {"owned": manager._owned_bans}
        else:
            banned = await ip_ban_manager.is_ip_banned(RULE_IP)
            view = attribution._view_of(config)
            stamp = await view.for_ban(RULE_IP, ip_ban_manager) if view else None
            reply = {"banned": banned, "stamp": stamp}
        print(json.dumps(reply), flush=True)
    await redis_handler.close()


asyncio.run(main(sys.argv[1], sys.argv[2], int(sys.argv[3])))
