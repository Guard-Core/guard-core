import hashlib
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from guard_core._dynamic_rules import (
    content_fingerprint,
    load_last_known_ownership,
    load_last_known_rules_snapshot,
)
from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync.handlers._dynamic_rule_persistence import (
    DYNAMIC_RULES_REDIS_NAMESPACE,
    PURGED_MARKER_KEY,
    parse_purge_target,
    resolve_redis_value,
)

_NESTED_AUTO_BANS_NOTE = (
    "auto-bans nested inside the purged rule bans are cut back to their own expiry"
)


def purge_fingerprint(rules: Any) -> str:
    return hashlib.sha256(content_fingerprint(rules).encode()).hexdigest()


@dataclass(frozen=True)
class PurgeMarker:
    rule_id: str
    version: int
    fingerprint: str
    purged_at: datetime


class DynamicRulePurgeMixin:
    config: SecurityConfig
    redis_handler: Any = None
    agent_handler: Any = None
    logger: logging.Logger
    current_rules: DynamicRules | None
    _current_fingerprint: str | None
    _owned_bans: list[str] | tuple[()]
    _owned_patterns: list[str] | tuple[()]
    _reverted_rules: DynamicRules | None = None
    _read_redis_payload: Callable[[], str | bytes | None]
    _read_file_payload: Callable[[], str | None]
    _clear_last_known_rules: Callable[[], None]
    _revert_to_base_config: Callable[[], None]
    _refresh_attribution: Callable[[], None]

    def purge_configured_dynamic_rules(self) -> bool:
        """Run the purge the config asks for, at start. A WARNING at every start
        says whether the named set was found, so the setting is not forgotten."""
        target = self.config.purge_dynamic_rules_on_start
        if target is None:
            return False
        rule_id, version = parse_purge_target(target)
        matched = self.purge_dynamic_rules(rule_id, version)
        self.logger.warning(
            "purge_dynamic_rules_on_start=%r is set and %s; unset it once the SaaS "
            "answers rules checks again",
            target,
            "matched the last-known snapshot and was purged"
            if matched
            else "did not match the last-known snapshot, nothing was purged",
        )
        return matched

    def purge_dynamic_rules(self, rule_id: str, version: int) -> bool:
        """Drop one dashboard rule set locally: lift the bans it owns, remove its
        patterns, delete both snapshots and leave a marker so no worker applies
        that set again before a fresh SaaS check. True when the last-known
        snapshot held the set."""
        held = self._parse_if_holding(
            self._read_redis_payload(), rule_id, version
        ) or self._parse_if_holding(self._read_file_payload(), rule_id, version)
        if held is None:
            return False
        rules, snapshot_patterns = held
        from guard_core.sync.handlers.ipban_handler import ip_ban_manager

        counts = ip_ban_manager.purge_rule_owned_bans()
        patterns = list(dict.fromkeys([*snapshot_patterns, *self._owned_patterns]))
        removed = self._remove_purged_patterns(patterns)
        self._clear_last_known_rules()
        self._revert_if_purged(self._write_purge_marker(rules))
        self.logger.info(
            "Purged dynamic rules %s v%s: %d rule bans lifted, %d rewritten to the "
            "shorter ban they hid, %d left (a longer ban replaced them), %d already "
            "gone, %d failed, %d patterns removed; %s",
            rule_id,
            version,
            counts["deleted"],
            counts["rewritten"],
            counts["kept"],
            counts["gone"],
            counts["failed"],
            removed,
            _NESTED_AUTO_BANS_NOTE,
        )
        return True

    def _parse_if_holding(
        self, payload: str | bytes | None, rule_id: str, version: int
    ) -> tuple[DynamicRules, list[str]] | None:
        if payload is None:
            return None
        try:
            rules = load_last_known_rules_snapshot(payload)
            _bans, patterns = load_last_known_ownership(payload)
        except Exception as error:
            self.logger.error(f"Unusable last-known snapshot while purging: {error}")
            return None
        if (rules.rule_id, rules.version) != (rule_id, version):
            return None
        return rules, patterns

    def _remove_purged_patterns(self, patterns: list[str]) -> int:
        from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

        removed = 0
        for pattern in patterns:
            try:
                removed += int(sus_patterns_handler.remove_pattern(pattern))
            except Exception as error:
                self.logger.error(f"Failed to remove a purged pattern: {error}")
        self._owned_patterns = [p for p in self._owned_patterns if p not in patterns]
        self._refresh_attribution()
        return removed

    def _write_purge_marker(self, rules: DynamicRules) -> PurgeMarker:
        marker = PurgeMarker(
            rules.rule_id,
            rules.version,
            purge_fingerprint(rules),
            datetime.now(timezone.utc),
        )
        if not self.redis_handler:
            return marker
        payload = json.dumps(
            {
                "rule_id": marker.rule_id,
                "version": marker.version,
                "fingerprint": marker.fingerprint,
                "purged_at": marker.purged_at.isoformat(),
            }
        )
        try:
            resolve_redis_value(
                self.redis_handler.set_key(
                    DYNAMIC_RULES_REDIS_NAMESPACE, PURGED_MARKER_KEY, payload
                )
            )
        except Exception as error:
            self.logger.error(
                f"Failed to write the dynamic rules purge marker: {error}"
            )
        return marker

    def _read_purge_marker(self) -> PurgeMarker | None:
        if not self.redis_handler:
            return None
        try:
            raw = resolve_redis_value(
                self.redis_handler.get_key(
                    DYNAMIC_RULES_REDIS_NAMESPACE, PURGED_MARKER_KEY
                )
            )
            if raw is None or raw == b"" or raw == "":
                return None
            data = json.loads(raw)
            return PurgeMarker(
                str(data["rule_id"]),
                int(data["version"]),
                str(data["fingerprint"]),
                datetime.fromisoformat(data["purged_at"]),
            )
        except Exception as error:
            self.logger.error(f"Unusable dynamic rules purge marker, ignored: {error}")
            return None

    def _clear_purge_marker(self) -> None:
        self._reverted_rules = None
        if not self.redis_handler:
            return
        try:
            resolve_redis_value(
                self.redis_handler.delete(
                    DYNAMIC_RULES_REDIS_NAMESPACE, PURGED_MARKER_KEY
                )
            )
        except Exception as error:
            self.logger.error(
                f"Failed to clear the dynamic rules purge marker: {error}"
            )

    def _holds_purged_rules(self, marker: PurgeMarker) -> bool:
        held = self.current_rules
        return held is not None and purge_fingerprint(held) == marker.fingerprint

    def _read_marker_and_revert_if_purged(self) -> PurgeMarker | None:
        marker = self._read_purge_marker()
        self._revert_if_purged(marker)
        return marker

    def _revert_if_purged(self, marker: PurgeMarker | None) -> None:
        """A worker that still holds the purged set drops it locally: base config
        and patterns restored, ownership forgotten, no second unban."""
        if marker is None or not self._holds_purged_rules(marker):
            return
        from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

        # Strong reference: guard-agent below 5.0 answers a rules check that
        # changed nothing with the very object it cached, which is how a stale
        # answer is told from a fresh one when it has no status field.
        self._reverted_rules = self.current_rules
        patterns = self._owned_patterns
        self._owned_bans, self._owned_patterns = [], []
        self._revert_to_base_config()
        for pattern in patterns:
            try:
                sus_patterns_handler.remove_pattern(pattern)
            except Exception as error:
                self.logger.error(f"Failed to remove a purged pattern: {error}")
        self.logger.info(
            f"Dynamic rule {marker.rule_id} v{marker.version} was purged; "
            "this worker restored its base config"
        )

    def _answer_is_fresh(self, rules: DynamicRules, marker: PurgeMarker) -> bool:
        status = self._agent_status_with_rules_check_time()
        if status is not None:
            checked: datetime | None = status.rules_last_checked
            if checked is not None and checked.tzinfo is None:
                checked = checked.replace(tzinfo=timezone.utc)
            return checked is not None and checked > marker.purged_at
        return rules is not self._reverted_rules

    def _agent_status_with_rules_check_time(self) -> Any | None:
        """The agent's status when it reports the time of its last successful
        rules check (guard-agent 5.0 and later), else None."""
        get_status = getattr(self.agent_handler, "get_status", None)
        if get_status is None:
            return None
        try:
            status = get_status()
        except Exception as error:
            self.logger.error(f"Failed to read the agent status: {error}")
            return None
        return status if hasattr(status, "rules_last_checked") else None

    def _has_applicable_answer(
        self, rules: DynamicRules | None, marker: PurgeMarker | None
    ) -> bool:
        """An answer exists and, after a purge, is not the purged set: that set
        applies again only once a fresh SaaS check, newer than the purge,
        returns it. Any fresh answer ends the marker."""
        if not rules:
            return False
        if marker is None:
            return True
        if self._answer_is_fresh(rules, marker):
            self._clear_purge_marker()
            return True
        return purge_fingerprint(rules) != marker.fingerprint
