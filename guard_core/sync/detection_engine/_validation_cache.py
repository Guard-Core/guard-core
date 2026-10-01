"""Disk-backed cache for the pattern-safety validator's expensive layers.

The deterministic layers (dangerous constructs, compile check, structural
detectors) are pure syntax analysis and always re-run. Only the empirical
cost-verdict outcome (probe synthesis + timed subprocess probes) is cached,
keyed by pattern, flags, and engine version: a boot on a degraded host must
not spend minutes re-timing the same patterns it already certified, and a
pattern table must never silently reuse a verdict produced by a different
engine version.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import threading
from pathlib import Path

logger = logging.getLogger("guard_core.sync.detection_engine._validation_cache")

try:  # pragma: no cover - trivial environment probe
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _version

    try:
        ENGINE_VERSION: str = _version("guard-core")
    except PackageNotFoundError:  # pragma: no cover - source checkouts
        ENGINE_VERSION = "unknown"
except Exception:  # pragma: no cover - defensive
    ENGINE_VERSION = "unknown"


class PatternValidationCache:
    """Version-keyed disk cache for cost-verdict validation outcomes."""

    def __init__(self, path: str | os.PathLike[str]):
        self._path = Path(path)
        self._lock = threading.Lock()
        self._entries: dict[str, dict[str, object]] = {}
        self._load()

    def _key(self, pattern: str, flags: int) -> str:
        digest = hashlib.sha256(
            f"{pattern}\x00{flags}".encode("utf-8", errors="surrogatepass")
        ).hexdigest()
        return digest

    def _load(self) -> None:
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return
        except OSError as e:
            logger.warning("Pattern validation cache unreadable, ignoring: %s", e)
            return
        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("cache root is not an object")
            entries = {}
            for key, entry in data.items():
                if not isinstance(entry, dict):
                    raise ValueError("cache entry is not an object")
                if entry.get("version") != ENGINE_VERSION:
                    continue
                if not isinstance(entry.get("safe"), bool):
                    raise ValueError("cache entry missing safe verdict")
                if not isinstance(entry.get("reason"), str):
                    raise ValueError("cache entry missing reason")
                entries[str(key)] = entry
        except (ValueError, TypeError) as e:
            logger.warning("Pattern validation cache corrupt, starting empty: %s", e)
            return
        self._entries = entries

    def get(self, pattern: str, flags: int) -> tuple[bool, str] | None:
        with self._lock:
            entry = self._entries.get(self._key(pattern, flags))
        if entry is None:
            return None
        return bool(entry["safe"]), str(entry["reason"])

    def put(self, pattern: str, flags: int, safe: bool, reason: str) -> None:
        entry = {
            "safe": safe,
            "reason": reason,
            "version": ENGINE_VERSION,
        }
        with self._lock:
            self._entries[self._key(pattern, flags)] = entry
            self._save()

    def _save(self) -> None:
        payload = json.dumps(self._entries, sort_keys=True)
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            handle, tmp_name = tempfile.mkstemp(
                dir=self._path.parent, prefix=".validation-cache-", suffix=".tmp"
            )
            try:
                with os.fdopen(handle, "w", encoding="utf-8") as fd:
                    fd.write(payload)
                os.replace(tmp_name, self._path)
            except BaseException:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise
        except OSError as e:
            logger.warning("Pattern validation cache write failed: %s", e)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
