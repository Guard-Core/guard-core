"""Disk-backed cache for the pattern-safety validator's expensive layers.

The deterministic layers (dangerous constructs, compile check, structural
detectors) are pure syntax analysis and always re-run. Only the empirical
cost-verdict outcome (probe synthesis + timed subprocess probes) is cached,
keyed by every input of the verdict: pattern, flags, the effective
content-length cap, the interpreter, the validator source, and the engine
version. A boot on a degraded host must not spend minutes re-timing the same
patterns it already certified, and a verdict must never be served for inputs
it was not measured under. An accept is reused only when it was measured at a
host load scale no larger than the current one. A file that others can write
is not trusted and is never loaded or written.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import sys
import tempfile
import threading
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version
from pathlib import Path

logger = logging.getLogger("guard_core.detection_engine._validation_cache")


def _engine_version() -> str:
    try:
        return _version("guard-core")
    except PackageNotFoundError:
        return "unknown"
    except Exception:
        return "unknown"


ENGINE_VERSION = _engine_version()


def _validator_fingerprint() -> str:
    arbiter = Path(__file__).with_name("_redos_cost_arbiter.py")
    try:
        source = arbiter.read_bytes()
    except OSError:
        return "unreadable"
    return hashlib.sha256(source).hexdigest()


def _interpreter_tag() -> str:
    impl = sys.implementation
    return f"{impl.name}-{'.'.join(map(str, impl.version[:3]))}"


VALIDATOR_TAG = f"{_interpreter_tag()}:{_validator_fingerprint()}"


def _is_current_entry(entry: object) -> bool:
    if not isinstance(entry, dict):
        raise ValueError("cache entry is not an object")
    if entry.get("version") != ENGINE_VERSION:
        return False
    if entry.get("validator") != VALIDATOR_TAG or not isinstance(
        entry.get("load_scale"), (int, float)
    ):
        return False
    if not isinstance(entry.get("safe"), bool):
        raise ValueError("cache entry missing safe verdict")
    if not isinstance(entry.get("reason"), str):
        raise ValueError("cache entry missing reason")
    return True


def _is_trusted_location(path: Path) -> bool:
    if not hasattr(os, "getuid"):
        return True
    for target in (path, path.parent):
        try:
            info = target.stat()
        except FileNotFoundError:
            continue
        except OSError:
            return False
        if info.st_uid != os.getuid() or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return False
    return True


class PatternValidationCache:
    """Version-keyed disk cache for cost-verdict validation outcomes."""

    def __init__(self, path: str | os.PathLike[str]):
        self._path = Path(path)
        self._lock = threading.Lock()
        self._entries: dict[str, dict[str, object]] = {}
        self._trusted = _is_trusted_location(self._path)
        if self._trusted:
            self._load()
        else:
            logger.warning(
                "Pattern validation cache not trusted (writable by others or "
                "owned by another user), validating in full: %s",
                self._path,
            )

    def _key(self, pattern: str, flags: int, cap: int) -> str:
        material = (
            f"{pattern}\x00{flags}\x00{cap}\x00{VALIDATOR_TAG}\x00{ENGINE_VERSION}"
        )
        return hashlib.sha256(
            material.encode("utf-8", errors="surrogatepass")
        ).hexdigest()

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
                if _is_current_entry(entry):
                    entries[str(key)] = entry
        except (ValueError, TypeError) as e:
            logger.warning("Pattern validation cache corrupt, starting empty: %s", e)
            return
        self._entries = entries

    def get(
        self, pattern: str, flags: int, cap: int, load_scale: float
    ) -> tuple[bool, str] | None:
        if not self._trusted:
            return None
        with self._lock:
            entry = self._entries.get(self._key(pattern, flags, cap))
        if entry is None:
            return None
        safe = bool(entry["safe"])
        measured_at = entry["load_scale"]
        if safe and not (
            isinstance(measured_at, (int, float)) and measured_at <= load_scale
        ):
            return None
        return safe, str(entry["reason"])

    def put(
        self,
        pattern: str,
        flags: int,
        cap: int,
        safe: bool,
        reason: str,
        load_scale: float,
    ) -> None:
        if not self._trusted:
            return
        entry = {
            "safe": safe,
            "reason": reason,
            "version": ENGINE_VERSION,
            "validator": VALIDATOR_TAG,
            "load_scale": load_scale,
        }
        with self._lock:
            self._entries[self._key(pattern, flags, cap)] = entry
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
