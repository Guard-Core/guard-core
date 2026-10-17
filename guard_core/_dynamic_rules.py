import json
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DynamicRules(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    rule_id: str = Field(description="Unique rule ID")
    version: int = Field(description="Rule version number")
    timestamp: datetime = Field(description="Rule creation/update timestamp")
    expires_at: datetime | None = Field(
        default=None, description="Rule expiration time"
    )
    ttl: int = Field(default=300, description="Cache TTL in seconds")

    ip_blacklist: list[str] = Field(default_factory=list, description="IPs to ban")
    ip_whitelist: list[str] = Field(default_factory=list, description="IPs to allow")
    ip_ban_duration: int = Field(default=3600, description="Ban duration in seconds")

    blocked_countries: list[str] = Field(
        default_factory=list, description="Countries to block"
    )
    whitelist_countries: list[str] = Field(
        default_factory=list, description="Countries to allow"
    )

    global_rate_limit: int | None = Field(default=None, description="Global rate limit")
    global_rate_window: int | None = Field(
        default=None, description="Global rate window"
    )
    endpoint_rate_limits: dict[str, tuple[int, int]] = Field(
        default_factory=dict,
        description="Per-endpoint rate limits {endpoint: (requests, window)}",
    )

    blocked_cloud_providers: set[str] = Field(
        default_factory=set, description="Cloud providers to block"
    )

    blocked_user_agents: list[str] = Field(
        default_factory=list, description="User agents to block"
    )

    suspicious_patterns: list[str] = Field(
        default_factory=list, description="Additional suspicious patterns"
    )

    enable_penetration_detection: bool | None = Field(
        default=None, description="Override penetration detection setting"
    )
    enable_ip_banning: bool | None = Field(
        default=None, description="Override IP banning setting"
    )
    enable_rate_limiting: bool | None = Field(
        default=None, description="Override rate limiting setting"
    )
    auto_ban_threshold: int | None = Field(
        default=None, ge=1, description="Override auto-ban threshold setting"
    )
    auto_ban_duration: int | None = Field(
        default=None, ge=1, description="Override auto-ban duration setting"
    )
    enable_rate_limit_auto_ban: bool | None = Field(
        default=None, description="Override rate-limit auto-ban setting"
    )

    emergency_mode: bool = Field(default=False, description="Emergency lockdown mode")
    emergency_whitelist: list[str] = Field(
        default_factory=list, description="Emergency whitelist IPs"
    )
    emergency_whitelist_only: bool = Field(
        default=True,
        description="Admit only emergency_whitelist IPs during emergency mode; "
        "False also admits whitelist and exempt_ips",
    )


_FINGERPRINT_EXCLUDED_FIELDS = frozenset({"timestamp", "ttl"})


def content_fingerprint(rules: Any) -> str:
    content: dict[str, object] = {}
    for name in DynamicRules.model_fields:
        if name in _FINGERPRINT_EXCLUDED_FIELDS:
            continue
        value = getattr(rules, name, None)
        content[name] = sorted(value) if isinstance(value, set) else value
    return json.dumps(content, sort_keys=True, default=str)


LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION = 1


class LastKnownDynamicRules(DynamicRules):
    model_config = ConfigDict(extra="forbid")


class LastKnownOwnership(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bans: list[str] = Field(default_factory=list)
    patterns: list[str] = Field(default_factory=list)


class LastKnownRulesSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    rules: LastKnownDynamicRules
    owned: LastKnownOwnership | None = None


def dump_last_known_rules_snapshot(
    rules: DynamicRules,
    owned_bans: Sequence[str] | None = None,
    owned_patterns: Sequence[str] | None = None,
) -> str:
    mirrored_fields = rules.model_dump(include=set(DynamicRules.model_fields))
    owned = None
    if owned_bans is not None or owned_patterns is not None:
        owned = LastKnownOwnership(
            bans=list(owned_bans or ()), patterns=list(owned_patterns or ())
        )
    snapshot = LastKnownRulesSnapshot(
        schema_version=LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION,
        rules=LastKnownDynamicRules.model_validate(mirrored_fields),
        owned=owned,
    )
    return snapshot.model_dump_json(exclude={"owned"} if owned is None else None)


def load_last_known_rules_snapshot(payload: str | bytes) -> DynamicRules:
    snapshot = LastKnownRulesSnapshot.model_validate_json(payload)
    if snapshot.schema_version != LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION:
        raise ValueError(
            "Unsupported last-known dynamic rules snapshot schema version: "
            f"{snapshot.schema_version}"
        )
    return DynamicRules.model_validate(snapshot.rules.model_dump())


def load_last_known_ownership(payload: str | bytes) -> tuple[list[str], list[str]]:
    snapshot = LastKnownRulesSnapshot.model_validate_json(payload)
    if snapshot.owned is None:
        return [], []
    return list(snapshot.owned.bans), list(snapshot.owned.patterns)
