import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, cast

import maxminddb
import pytest

from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.geo_fixture import (
    CLIENT_IP,
    database_server,
    padded_database_bytes,
)

WORKERS = 4
ROUNDS = 2
MIB = 1024 * 1024
WORKER = Path(__file__).with_name("geo_worker.py")
ROOT = next(p for p in WORKER.parents if (p / "guard_core").is_dir())


@pytest.fixture(autouse=True)
def _reset_singleton() -> Any:
    IPInfoManager._instance = None
    yield
    IPInfoManager._instance = None


def _spawn_workers(
    mode: str, url: str, prefix: str, db: Path, count: int = WORKERS
) -> list[dict[str, Any]]:
    start = time.time() + 2.0
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    command = [sys.executable, str(WORKER), mode, url, prefix, str(db), str(start)]
    processes = [
        subprocess.Popen(
            command,
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(count)
    ]
    results = []
    for process in processes:
        out, err = process.communicate(timeout=120)
        lines = out.strip().splitlines()
        results.append(
            json.loads(lines[-1]) if lines else {"done": False, "stderr": err[-400:]}
        )
    return results


async def test_workers_that_adopt_one_copy_at_once_all_adopt_and_the_key_survives(
    security_config_redis: SecurityConfig, tmp_path: Path
) -> None:
    handler = RedisManager(security_config_redis)
    await handler.initialize()
    source = tmp_path / "source.mmdb"
    source.write_bytes(padded_database_bytes(b"\xff", 16 * MIB))
    IPInfoManager._instance = None
    writer = IPInfoManager(token="tok", db_path=source)
    writer.redis_handler = handler
    writer._max_age = 3600
    await writer._cache_database_in_redis()
    key = f"{security_config_redis.redis_prefix}ipinfo:database"

    for number in range(ROUNDS):
        shared = tmp_path / f"shared{number}" / "geo.mmdb"
        shared.parent.mkdir()
        results = _spawn_workers(
            "adopt",
            str(security_config_redis.redis_url),
            str(security_config_redis.redis_prefix),
            shared,
        )
        assert results == [{"done": True, "key_survived": True}] * WORKERS
        assert sorted(p.name for p in shared.parent.iterdir()) == ["geo.mmdb"]
    async with handler.get_connection() as conn:
        assert await conn.exists(key) == 1
    await handler.close()


def test_workers_without_redis_that_download_at_once_all_end_with_a_valid_database(
    tmp_path: Path,
) -> None:
    body = padded_database_bytes(b"\x00", 8 * MIB)
    shared = tmp_path / "shared" / "geo.mmdb"
    shared.parent.mkdir()
    with database_server(body) as server:
        results = _spawn_workers("download", server.url, "", shared, 2)

    assert results == [{"done": True, "country": "CN"}] * 2
    assert server.attempts == 2
    assert shared.read_bytes() == body
    assert sorted(p.name for p in shared.parent.iterdir()) == ["geo.mmdb"]
    reader = maxminddb.open_database(str(shared))
    assert reader.get(CLIENT_IP) is not None
    reader.close()


def _aged(path: Path, seconds: float) -> Path:
    path.write_bytes(b"left behind")
    old = time.time() - seconds
    os.utime(path, (old, old))
    return path


async def test_a_temp_file_older_than_the_bound_is_removed_at_start_a_fresh_one_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = IPInfoManager(token="tok", db_path=tmp_path / "geo.mmdb")
    manager._download_total_timeout = 300
    stale = _aged(tmp_path / f"geo.mmdb.{uuid.uuid4().hex}.tmp", 301)
    stale_legacy = _aged(tmp_path / "geo.mmdb.tmp", 301)
    fresh = _aged(tmp_path / f"geo.mmdb.{uuid.uuid4().hex}.tmp", 10)
    other = _aged(tmp_path / "other.mmdb.abc.tmp", 301)
    dangling = tmp_path / "geo.mmdb.dangling.tmp"
    dangling.symlink_to(tmp_path / "nowhere")

    async def adopted(self: IPInfoManager) -> bool:
        return True

    monkeypatch.setattr(IPInfoManager, "_adopt_redis_copy", adopted)
    await manager._initialize_database()

    assert not stale.exists()
    assert not stale_legacy.exists()
    assert fresh.exists()
    assert other.exists()
    assert dangling.is_symlink()


def test_every_attempt_gets_its_own_temp_file_next_to_the_database(
    tmp_path: Path,
) -> None:
    manager = IPInfoManager(token="tok", db_path=tmp_path / "geo.mmdb")

    first, second = manager._database_tmp_path(), manager._database_tmp_path()

    assert first != second
    assert first.parent == second.parent == tmp_path
    assert first.name.startswith("geo.mmdb.") and first.name.endswith(".tmp")


async def test_an_os_error_while_installing_an_adopted_copy_is_a_failed_attempt_only(
    security_config_redis: SecurityConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = RedisManager(security_config_redis)
    await handler.initialize()
    manager = IPInfoManager(token="tok", db_path=tmp_path / "geo.mmdb")
    manager.redis_handler = handler
    manager._max_age = 3600
    await handler.set_key(
        "ipinfo", "database", padded_database_bytes(b"\x00", 50000).decode("latin-1")
    )

    def failing_replace(source: Any, target: Any) -> None:
        raise PermissionError("the data dir is read only")

    monkeypatch.setattr(os, "replace", failing_replace)

    assert await manager._adopt_redis_copy() is False

    assert await handler.get_key("ipinfo", "database") is not None
    assert sorted(p.name for p in tmp_path.iterdir()) == []
    await handler.close()


class _WholeValueRedis:
    def __init__(self, value: bytes) -> None:
        self.value = value
        self.deleted = False

    async def get_key(self, namespace: str, key: str) -> bytes:
        return self.value

    async def delete(self, namespace: str, key: str) -> None:
        self.deleted = True


async def test_an_os_error_while_installing_a_whole_value_copy_keeps_the_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = _WholeValueRedis(padded_database_bytes(b"\x00", 50000))
    manager = IPInfoManager(token="tok", db_path=tmp_path / "geo.mmdb")
    manager.redis_handler = cast(Any, stub)

    def failing_replace(source: Any, target: Any) -> None:
        raise PermissionError("the data dir is read only")

    monkeypatch.setattr(os, "replace", failing_replace)

    assert await manager._adopt_redis_copy() is False

    assert stub.deleted is False


def test_a_database_file_that_is_missing_is_an_os_error_not_an_invalid_database(
    tmp_path: Path,
) -> None:
    manager = IPInfoManager(token="tok", db_path=tmp_path / "geo.mmdb")

    with pytest.raises(FileNotFoundError):
        manager._validate_database_file(tmp_path / "gone.tmp")
