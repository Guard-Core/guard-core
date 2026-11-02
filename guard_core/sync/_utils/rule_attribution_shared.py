from typing import TYPE_CHECKING

from guard_core.sync._utils.app_managers import AppManagers

if TYPE_CHECKING:
    from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager

Stamp = dict[str, object]

_APP_RULE_MANAGERS: AppManagers["DynamicRuleManager"] = AppManagers(
    "dynamic_rules", shares_default_between_apps=False
)
