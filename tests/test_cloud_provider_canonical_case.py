from datetime import datetime, timezone
from typing import Any

import pytest

from guard_core._security_config_field_validators import (
    canonicalize_cloud_provider_selector,
)
from guard_core.decorators import SecurityDecorator, get_route_id
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.models import DynamicRules, SecurityConfig


async def _apply(manager: DynamicRuleManager, **fields: Any) -> None:
    rules = DynamicRules(
        rule_id="plan", version=1, timestamp=datetime.now(timezone.utc), **fields
    )
    await manager._apply_rules(rules)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("AZURE", "Azure"),
        ("azure", "Azure"),
        ("Azure", "Azure"),
        ("aws", "AWS"),
        ("Gcp", "GCP"),
        ("digitalocean", "DigitalOcean"),
        ("LINODE", "Linode"),
        ("vultr", "Vultr"),
        ("azure:!westeurope", "Azure:!westeurope"),
        ("AWS:!us-east-1", "AWS:!us-east-1"),
    ],
)
def test_canonicalize_cloud_provider_selector_known_spellings(
    raw: str, expected: str
) -> None:
    assert canonicalize_cloud_provider_selector(raw) == expected


@pytest.mark.parametrize("raw", ["", "Bogus", " azure", "azure ", "az", 7, None])
def test_canonicalize_cloud_provider_selector_unknown_is_none(raw: object) -> None:
    assert canonicalize_cloud_provider_selector(raw) is None


def test_static_config_canonicalizes_provider_spelling() -> None:
    config = SecurityConfig(
        enable_redis=False, block_cloud_providers={"AZURE", "aws", "gcp:!us-east1"}
    )
    assert config.block_cloud_providers == frozenset({"Azure", "AWS", "GCP:!us-east1"})


def test_static_config_still_rejects_unknown_provider() -> None:
    with pytest.raises(ValueError, match="Unknown cloud providers"):
        SecurityConfig(enable_redis=False, block_cloud_providers={"azur"})


def test_runtime_assignment_canonicalizes_provider_spelling() -> None:
    config = SecurityConfig(enable_redis=False)
    config.block_cloud_providers = frozenset({"AZURE"})
    assert config.block_cloud_providers == frozenset({"Azure"})


def test_block_clouds_decorator_canonicalizes_provider_spelling() -> None:
    decorator = SecurityDecorator(SecurityConfig(enable_redis=False))

    @decorator.block_clouds(["AZURE", "aws:!eu-west-1"])
    async def endpoint() -> None:
        return None

    route_config = decorator.get_route_config(get_route_id(endpoint))
    assert route_config is not None
    assert route_config.block_cloud_providers == {"Azure", "AWS:!eu-west-1"}


@pytest.mark.asyncio
@pytest.mark.parametrize("spelling", ["AZURE", "azure", "Azure"])
async def test_dynamic_rule_blocks_azure_in_every_spelling(spelling: str) -> None:
    DynamicRuleManager._instance = None
    config = SecurityConfig(enable_redis=False)
    manager = DynamicRuleManager(config)
    await _apply(manager, blocked_cloud_providers={spelling})
    assert config.block_cloud_providers == frozenset({"Azure"})
    DynamicRuleManager._instance = None
