import logging
import os
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from guard_core._dynamic_rules import (
    content_fingerprint,
    dump_last_known_rules_snapshot,
    load_last_known_rules_snapshot,
)
from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync.handlers._dynamic_rule_persistence import (
    DYNAMIC_RULES_REDIS_NAMESPACE,
    LAST_KNOWN_RULES_KEY,
    resolve_redis_value,
)


class DynamicRuleSnapshotMixin:
    config: SecurityConfig
    redis_handler: Any = None
    logger: logging.Logger
    current_rules: DynamicRules | None
    last_update: float
    _hydrating: bool
    _current_fingerprint: str | None
    _apply_rules: Callable[[DynamicRules], list[str]]
    _has_rule_expired: Callable[[DynamicRules], bool]

    def _hydrate_last_known_rules(self) -> None:
        try:
            rules = self._load_last_known_rules()
            if rules is None:
                return
            self._hydrating = True
            try:
                self._apply_rules(rules)
            finally:
                self._hydrating = False
            self.current_rules = rules
            self._current_fingerprint = content_fingerprint(rules)
            self.last_update = time.time()
            self.logger.info(
                f"Hydrated last-known dynamic rules {rules.rule_id} "
                f"v{rules.version} before the update loop started"
            )
        except Exception as e:
            self.logger.error(f"Failed to hydrate last-known dynamic rules: {e}")

    def _load_last_known_rules(self) -> DynamicRules | None:
        redis_payload = self._read_redis_payload()
        file_payload = self._read_file_payload()
        for payload in (redis_payload, file_payload):
            if payload is None:
                continue
            rules = self._parse_last_known_rules(payload)
            if rules is None:
                continue
            if self._has_rule_expired(rules):
                self.logger.error(
                    f"Discarding expired last-known dynamic rules "
                    f"{rules.rule_id} v{rules.version}; trying the next store"
                )
                continue
            return rules
        return None

    def _read_redis_payload(self) -> str | bytes | None:
        if not self.redis_handler:
            return None
        try:
            raw = resolve_redis_value(
                self.redis_handler.get_key(
                    DYNAMIC_RULES_REDIS_NAMESPACE, LAST_KNOWN_RULES_KEY
                )
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
        path = self.config.dynamic_rules_cache_path
        if path is None or not path.is_file():
            return None
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            self.logger.error(f"Failed to read dynamic rules cache file {path}: {e}")
            return None

    def _parse_last_known_rules(self, payload: str | bytes) -> DynamicRules | None:
        try:
            return load_last_known_rules_snapshot(payload)
        except Exception as e:
            self.logger.error(
                f"Discarding unusable last-known dynamic rules payload: {e}"
            )
            return None

    def _clear_last_known_rules(self) -> None:
        if self.redis_handler:
            try:
                resolve_redis_value(
                    self.redis_handler.delete(
                        DYNAMIC_RULES_REDIS_NAMESPACE, LAST_KNOWN_RULES_KEY
                    )
                )
            except Exception as e:
                self.logger.error(
                    f"Failed to clear last-known dynamic rules in Redis: {e}"
                )

        cache_path = self.config.dynamic_rules_cache_path
        if cache_path is None:
            return
        try:
            cache_path.unlink(missing_ok=True)
        except OSError as e:
            self.logger.error(
                f"Failed to clear dynamic rules cache file {cache_path}: {e}"
            )

    def _persist_last_known_rules(self, rules: DynamicRules) -> None:
        try:
            payload = dump_last_known_rules_snapshot(rules)
        except Exception as e:
            self.logger.error(f"Failed to build last-known dynamic rules snapshot: {e}")
            return

        if self.redis_handler:
            try:
                resolve_redis_value(
                    self.redis_handler.set_key(
                        DYNAMIC_RULES_REDIS_NAMESPACE,
                        LAST_KNOWN_RULES_KEY,
                        payload,
                    )
                )
            except Exception as e:
                self.logger.error(f"Failed to persist dynamic rules to Redis: {e}")

        cache_path = self.config.dynamic_rules_cache_path
        if cache_path is None:
            return
        try:
            self._write_last_known_rules_file(cache_path, payload)
        except OSError as e:
            self.logger.error(
                f"Failed to persist dynamic rules to cache file {cache_path}: {e}"
            )

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
