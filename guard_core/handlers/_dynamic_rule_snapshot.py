import logging
import os
import tempfile
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from guard_core._dynamic_rules import (
    content_fingerprint,
    dump_last_known_rules_snapshot,
    dump_legacy_last_known_rules_snapshot,
    load_last_known_ownership,
    load_last_known_rules_snapshot,
    snapshot_agrees_with_legacy,
)
from guard_core.handlers._dynamic_rule_persistence import (
    DYNAMIC_RULES_REDIS_NAMESPACE,
    LAST_KNOWN_RULES_FULL_FILE_SUFFIX,
    LAST_KNOWN_RULES_FULL_KEY,
    LAST_KNOWN_RULES_KEY,
    resolve_redis_value,
)
from guard_core.handlers._dynamic_rule_purge import (
    DynamicRulePurgeMixin,
    purge_fingerprint,
)
from guard_core.models import DynamicRules, SecurityConfig


class DynamicRuleSnapshotMixin(DynamicRulePurgeMixin):
    config: SecurityConfig
    redis_handler: Any = None
    logger: logging.Logger
    current_rules: DynamicRules | None
    last_update: float
    _restored_ownership: tuple[list[str], list[str]] = ([], [])
    _owned_bans: list[str] | tuple[()] = ()
    _owned_patterns: list[str] | tuple[()] = ()
    _reject_if_malformed: Callable[[DynamicRules], Awaitable[bool]]
    _current_fingerprint: str | None
    _apply_rules: Callable[[DynamicRules], Awaitable[list[str]]]
    _has_rule_expired: Callable[[DynamicRules], bool]

    async def _hydrate_last_known_rules(self) -> None:
        try:
            rules = await self._load_last_known_rules()
            if rules is None:
                return
            if await self._reject_if_malformed(rules):
                return
            self._owned_bans, self._owned_patterns = self._restored_ownership
            try:
                await self._apply_rules(rules)
            except Exception:
                self._owned_bans, self._owned_patterns = [], []
                self._refresh_attribution()
                raise
            self.current_rules = rules
            self._refresh_attribution()
            self._current_fingerprint = content_fingerprint(rules)
            self.last_update = time.time()
            self.logger.info(
                f"Hydrated last-known dynamic rules {rules.rule_id} "
                f"v{rules.version} before the update loop started"
            )
        except Exception as e:
            self.logger.error(f"Failed to hydrate last-known dynamic rules: {e}")

    async def _load_last_known_rules(self) -> DynamicRules | None:
        stores = (
            (await self._read_redis_payload(), await self._read_redis_full_payload()),
            (self._read_file_payload(), self._read_file_full_payload()),
        )
        marker = await self._read_purge_marker()
        for payload, full_payload in stores:
            if payload is None:
                continue
            rules = self._parse_last_known_rules(payload, full_payload)
            if rules is None:
                continue
            if marker is not None and purge_fingerprint(rules) == marker.fingerprint:
                self.logger.warning(
                    f"Discarding last-known dynamic rules {rules.rule_id} "
                    f"v{rules.version}: they were purged"
                )
                continue
            if self._has_rule_expired(rules):
                self.logger.error(
                    f"Discarding expired last-known dynamic rules "
                    f"{rules.rule_id} v{rules.version}; trying the next store"
                )
                continue
            return rules
        return None

    async def _read_redis_payload(self) -> str | bytes | None:
        return await self._read_redis_key(LAST_KNOWN_RULES_KEY)

    async def _read_redis_full_payload(self) -> str | bytes | None:
        return await self._read_redis_key(LAST_KNOWN_RULES_FULL_KEY)

    async def _read_redis_key(self, key: str) -> str | bytes | None:
        if not self.redis_handler:
            return None
        try:
            raw = await resolve_redis_value(
                self.redis_handler.get_key(DYNAMIC_RULES_REDIS_NAMESPACE, key)
            )
        except Exception as e:
            self.logger.error(
                f"Failed to read last-known dynamic rules from Redis: {e}"
            )
            return None
        if raw is None or raw == b"" or raw == "":
            return None
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        return str(raw)

    def _read_file_payload(self) -> str | None:
        return self._read_cache_file(self.config.dynamic_rules_cache_path)

    def _read_file_full_payload(self) -> str | None:
        path = self.config.dynamic_rules_cache_path
        return self._read_cache_file(None if path is None else _full_file_path(path))

    def _read_cache_file(self, path: Path | None) -> str | None:
        if path is None or not path.is_file():
            return None
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            self.logger.error(f"Failed to read dynamic rules cache file {path}: {e}")
            return None

    def _parse_last_known_rules(
        self, payload: str | bytes, full_payload: str | bytes | None = None
    ) -> DynamicRules | None:
        try:
            snapshot = self._reconcile_snapshot(payload, full_payload)
        except Exception as e:
            self.logger.error(
                f"Discarding unusable last-known dynamic rules payload: {e}"
            )
            return None
        self._restored_ownership = snapshot[1]
        return snapshot[0]

    def _reconcile_snapshot(
        self, payload: str | bytes, full_payload: str | bytes | None
    ) -> tuple[DynamicRules, tuple[list[str], list[str]]]:
        """The full snapshot when it agrees with the legacy one as data, else the
        legacy one (what a v4.4.0 worker last wrote or read) and one log line."""
        legacy = load_last_known_rules_snapshot(payload)
        if full_payload is not None:
            try:
                if snapshot_agrees_with_legacy(full_payload, legacy):
                    return (
                        load_last_known_rules_snapshot(full_payload),
                        load_last_known_ownership(full_payload),
                    )
                reason = "differs from the legacy snapshot"
            except Exception as e:
                reason = f"is unusable ({e})"
            self.logger.warning(
                f"Ignoring the full last-known dynamic rules snapshot: it {reason}; "
                "using the legacy snapshot"
            )
        return legacy, load_last_known_ownership(payload)

    async def _clear_last_known_rules(self) -> None:
        if self.redis_handler:
            for key in (LAST_KNOWN_RULES_KEY, LAST_KNOWN_RULES_FULL_KEY):
                try:
                    await resolve_redis_value(
                        self.redis_handler.delete(DYNAMIC_RULES_REDIS_NAMESPACE, key)
                    )
                except Exception as e:
                    self.logger.error(
                        f"Failed to clear last-known dynamic rules in Redis: {e}"
                    )

        cache_path = self.config.dynamic_rules_cache_path
        if cache_path is None:
            return
        for path in (cache_path, _full_file_path(cache_path)):
            try:
                path.unlink(missing_ok=True)
            except OSError as e:
                self.logger.error(
                    f"Failed to clear dynamic rules cache file {path}: {e}"
                )

    async def _persist_last_known_rules(self, rules: DynamicRules) -> None:
        try:
            legacy = dump_legacy_last_known_rules_snapshot(rules)
            full = dump_last_known_rules_snapshot(
                rules, self._owned_bans, self._owned_patterns
            )
        except Exception as e:
            self.logger.error(f"Failed to build last-known dynamic rules snapshot: {e}")
            return

        if self.redis_handler:
            await self._persist_snapshot_to_redis(legacy, full)

        cache_path = self.config.dynamic_rules_cache_path
        if cache_path is None:
            return
        try:
            self._write_last_known_rules_file(cache_path, legacy)
            self._write_last_known_rules_file(_full_file_path(cache_path), full)
        except OSError as e:
            self.logger.error(
                f"Failed to persist dynamic rules to cache file {cache_path}: {e}"
            )

    async def _persist_snapshot_to_redis(self, legacy: str, full: str) -> None:
        # Legacy first: a crash between the writes leaves the full key stale, which
        # the agreement rule on read treats as a disagreement, never the reverse.
        for key, payload in (
            (LAST_KNOWN_RULES_KEY, legacy),
            (LAST_KNOWN_RULES_FULL_KEY, full),
        ):
            try:
                await resolve_redis_value(
                    self.redis_handler.set_key(
                        DYNAMIC_RULES_REDIS_NAMESPACE, key, payload
                    )
                )
            except Exception as e:
                self.logger.error(f"Failed to persist dynamic rules to Redis: {e}")
                return

    def _write_last_known_rules_file(self, cache_path: Path, payload: str) -> None:
        descriptor, temp_name = tempfile.mkstemp(
            dir=cache_path.parent, prefix=f"{cache_path.name}.", suffix=".tmp"
        )
        temp_path = Path(temp_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.replace(temp_path, cache_path)
        except OSError:
            temp_path.unlink(missing_ok=True)
            raise


def _full_file_path(cache_path: Path) -> Path:
    return cache_path.with_name(cache_path.name + LAST_KNOWN_RULES_FULL_FILE_SUFFIX)
