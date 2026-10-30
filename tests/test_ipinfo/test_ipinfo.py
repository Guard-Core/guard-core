import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock, call, patch

import maxminddb
import pytest

from guard_core.handlers.ipinfo_handler import IPInfoManager, _describe_download_error
from tests.geo_fixture import country_database_bytes
from tests.mock_download import streamed

VALID_DB = country_database_bytes("CN")


def _mock_aiohttp(
    content: bytes = VALID_DB,
    side_effect: Exception | None = None,
) -> MagicMock:
    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)

    if side_effect:
        mock_session.get = AsyncMock(side_effect=side_effect)
    else:
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.content_length = None
        mock_response.content.iter_chunked = streamed(content)
        mock_session.get = AsyncMock(return_value=mock_response)

    return mock_session


@pytest.mark.asyncio
async def test_ipinfo_db(tmp_path: Path) -> None:
    db = IPInfoManager(token="test_token", db_path=tmp_path / "test.mmdb")

    mock_session = _mock_aiohttp(content=VALID_DB)

    with (
        patch(
            "aiohttp.ClientSession",
            return_value=mock_session,
        ),
        patch("maxminddb.open_database"),
        patch("builtins.open", Mock()),
        patch("os.makedirs"),
    ):
        await db.initialize()

        db.reader = Mock()
        db.reader.get.return_value = {"country": "US"}
        assert db.get_country("1.1.1.1") == "US"


def test_ipinfo_missing_token() -> None:
    with pytest.raises(ValueError):
        IPInfoManager(token="")


class _StatusOnlyError(Exception):
    status = 401


class _ResponseStatusCodeError(Exception):
    def __init__(self) -> None:
        super().__init__("boom")
        self.response = SimpleNamespace(status_code=403)


class _NoStatusError(Exception):
    pass


def test_describe_download_error_uses_status_attribute() -> None:
    assert _describe_download_error(_StatusOnlyError()) == "_StatusOnlyError (HTTP 401)"


def test_describe_download_error_uses_response_status_code() -> None:
    assert (
        _describe_download_error(_ResponseStatusCodeError())
        == "_ResponseStatusCodeError (HTTP 403)"
    )


def test_describe_download_error_falls_back_to_class_name() -> None:
    assert _describe_download_error(_NoStatusError()) == "_NoStatusError"


async def test_ipinfo_download_failure(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    mock_session = _mock_aiohttp(side_effect=Exception("Download failed"))

    with (
        patch(
            "aiohttp.ClientSession",
            return_value=mock_session,
        ),
        patch.object(IPInfoManager, "_is_db_outdated", return_value=True),
    ):
        await db.initialize()
        assert db.reader is None
        assert not db.db_path.exists()


@pytest.mark.asyncio
async def test_download_database_sends_bearer_header_without_url_token(
    tmp_path: Path,
) -> None:
    token = "SECRET_IPINFO_TOKEN_abc123"
    db = IPInfoManager(token=token, db_path=tmp_path / "test.mmdb")
    mock_session = _mock_aiohttp(content=VALID_DB)

    with patch(
        "aiohttp.ClientSession",
        return_value=mock_session,
    ):
        await db._download_database()

    requested_args, requested_kwargs = mock_session.get.call_args
    assert token not in requested_args[0]
    assert requested_kwargs["headers"] == {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_db_initialization_retry(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    mock_session = _mock_aiohttp(side_effect=Exception("First fail"))

    with (
        patch(
            "aiohttp.ClientSession",
            return_value=mock_session,
        ),
        patch.object(db, "_sleep", AsyncMock()) as mock_sleep,
        patch("builtins.open", Mock()),
    ):
        await db.initialize()
        assert mock_sleep.call_count == 2
        assert db.reader is None


@pytest.mark.asyncio
async def test_database_retry_success(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")

    call_count = 0
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.content_length = None
    mock_response.content.iter_chunked = streamed(VALID_DB)

    async def get_side_effect(*args: Any, **kwargs: Any) -> MagicMock:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise Exception("First fail")
        return mock_response

    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    mock_session.get = AsyncMock(side_effect=get_side_effect)

    with (
        patch(
            "aiohttp.ClientSession",
            return_value=mock_session,
        ),
        patch("asyncio.sleep") as mock_sleep,
    ):
        await db._download_database()

        assert call_count == 2
        assert db.db_path.read_bytes() == VALID_DB
        # Membership, not assert_called_once_with: patching sleep replaces the
        # attribute on the shared module, so this mock records every sleep in
        # the process, including background handler threads left running by
        # earlier tests (dynamic_rule_handler's updater loops on
        # sleep(dynamic_rule_interval), and a mocked sleep returns instantly,
        # so it spins). call_count above already pins the retry to exactly one.
        assert call(1) in mock_sleep.call_args_list


def test_db_age_check(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")

    with (
        patch("pathlib.Path.exists", return_value=True),
        patch("pathlib.Path.stat") as mock_stat,
    ):
        mock_stat.return_value.st_mtime = time.time() - 86401
        assert db._is_db_outdated() is True

        mock_stat.return_value.st_mtime = time.time() - 100
        assert db._is_db_outdated() is False


@pytest.mark.asyncio
async def test_get_country_exception_handling(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = Mock()
    db.reader.get.side_effect = Exception("DB error")

    assert db.get_country("1.1.1.1") is None


def test_db_age_check_missing_db(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "missing.mmdb")
    with patch("pathlib.Path.exists", return_value=False):
        assert db._is_db_outdated() is True


@pytest.mark.asyncio
async def test_real_database_initialization(ipinfo_db_path: Path) -> None:
    ipinfo_db_path.parent.mkdir(parents=True, exist_ok=True)
    with open(ipinfo_db_path, "wb") as f:
        f.write(b"dummy data")

    db = IPInfoManager(token="test_token", db_path=ipinfo_db_path)

    with patch("maxminddb.open_database") as mock_open_db:
        mock_reader = Mock()
        mock_open_db.return_value = mock_reader
        mock_reader.get.return_value = {"country": "US"}

        await db.initialize()
        assert db.reader is not None
        assert db.db_path.exists()

        country = db.get_country("8.8.8.8")
        assert country == "US"
        db.close()


@pytest.mark.asyncio
async def test_close_with_reader(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    mock_reader = Mock()
    db.reader = mock_reader

    db.close()
    mock_reader.close.assert_called_once()


@pytest.mark.asyncio
async def test_close_is_noop_when_reader_is_none(tmp_path: Path) -> None:
    IPInfoManager._instance = None
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = None
    db.close()
    IPInfoManager._instance = None


@pytest.mark.asyncio
async def test_download_database_with_zero_retries_exits_cleanly(
    tmp_path: Path,
) -> None:
    IPInfoManager._instance = None
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db._download_retries = 0
    await db._download_database()
    IPInfoManager._instance = None


@pytest.mark.asyncio
async def test_redis_cache_hit(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.redis_handler = AsyncMock()
    db.redis_handler.get_key.return_value = b"mock_db_data"

    mock_reader = Mock()
    mock_reader.get.return_value = {"country": "US"}

    with patch("maxminddb.open_database", return_value=mock_reader) as mock_open:
        await db.initialize()

        db.redis_handler.get_key.assert_awaited_once_with("ipinfo", "database")

        with open(db.db_path, "rb") as f:
            assert f.read() == b"mock_db_data"

        assert len(mock_open.call_args_list) == 2
        temp = Path(mock_open.call_args_list[0].args[0])
        assert temp.parent == db.db_path.parent
        assert temp.name.startswith("test.mmdb.") and temp.name.endswith(".tmp")
        assert mock_open.call_args_list[1].args == (str(db.db_path),)
        assert db.reader is mock_reader


@pytest.mark.asyncio
async def test_redis_cache_hit_with_corrupt_database(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.redis_handler = AsyncMock()
    db.redis_handler.get_key.return_value = b"mock_db_data"

    with (
        patch(
            "maxminddb.open_database",
            side_effect=Exception("corrupt database"),
        ),
        patch.object(
            db,
            "_download_database",
            AsyncMock(side_effect=RuntimeError("network down")),
        ),
    ):
        await db.initialize()

    assert db.reader is None
    assert not db.db_path.exists()


@pytest.mark.asyncio
async def test_redis_cache_hit_atomic_replace_leaves_no_temp_file(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "test.mmdb"
    db_path.write_bytes(b"stale bytes")
    db = IPInfoManager(token="test", db_path=db_path)
    db.redis_handler = AsyncMock()
    db.redis_handler.get_key.return_value = b"cached bytes"

    with patch("maxminddb.open_database", return_value=Mock()):
        await db.initialize()

    assert db_path.read_bytes() == b"cached bytes"
    assert not db_path.with_name(db_path.name + ".tmp").exists()


@pytest.mark.asyncio
async def test_initialize_redis_cache_read_failure_falls_through_to_download(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    from guard_core.exceptions import GuardRedisError

    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.redis_handler = AsyncMock()
    db.redis_handler.get_key = AsyncMock(
        side_effect=GuardRedisError(503, "redis unavailable")
    )

    mock_session = _mock_aiohttp(content=VALID_DB)
    mock_reader = Mock()

    with (
        caplog.at_level("WARNING", logger="guard_core.handlers.ipinfo"),
        patch(
            "aiohttp.ClientSession",
            return_value=mock_session,
        ),
        patch("maxminddb.open_database", return_value=mock_reader),
    ):
        await db.initialize()

    db.redis_handler.get_key.assert_any_await("ipinfo", "database")
    assert db.reader is mock_reader
    assert db.redis_handler is not None
    assert "Cached GeoIP database unavailable" in caplog.text


@pytest.mark.asyncio
async def test_redis_cache_update(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.redis_handler = AsyncMock()

    mock_session = _mock_aiohttp(content=VALID_DB)

    with (
        patch(
            "aiohttp.ClientSession",
            return_value=mock_session,
        ),
        patch("maxminddb.open_database"),
    ):
        await db._download_database()

        db.redis_handler.set_key.assert_awaited_once_with(
            "ipinfo", "database", VALID_DB.decode("latin-1"), ttl=86400
        )


@pytest.mark.asyncio
async def test_download_database_redis_cache_write_failure_does_not_block_download(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    from guard_core.exceptions import GuardRedisError

    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.redis_handler = AsyncMock()
    db.redis_handler.set_key = AsyncMock(
        side_effect=GuardRedisError(503, "redis unavailable")
    )

    mock_session = _mock_aiohttp(content=VALID_DB)

    with (
        caplog.at_level("WARNING", logger="guard_core.handlers.ipinfo"),
        patch(
            "aiohttp.ClientSession",
            return_value=mock_session,
        ),
    ):
        await db._download_database()

    assert db.db_path.read_bytes() == VALID_DB
    assert db.redis_handler is not None
    assert "Failed to cache GeoIP database in Redis" in caplog.text


@pytest.mark.asyncio
async def test_redis_initialization_flow(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    mock_redis = AsyncMock()

    with patch.object(db, "initialize", new_callable=AsyncMock) as mock_init:
        await db.initialize_redis(mock_redis)

        assert db.redis_handler is mock_redis
        mock_init.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_country_result_without_country(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = Mock()

    db.reader.get.return_value = {"some_other_field": "value"}

    assert db.get_country("1.1.1.1") is None

    db.reader.get.return_value = None
    assert db.get_country("1.1.1.1") is None


LITE_RECORD = {
    "country_code": "DE",
    "country": "Germany",
    "continent_code": "EU",
    "continent": "Europe",
    "asn": "AS3320",
}


@pytest.mark.asyncio
async def test_get_country_legacy_record_gives_iso_code(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = Mock()
    db.reader.get.return_value = {"country": "DE", "country_name": "Germany"}

    assert db.get_country("1.1.1.1") == "DE"


@pytest.mark.asyncio
async def test_get_country_lite_record_gives_iso_code_not_name(
    tmp_path: Path,
) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = Mock()
    db.reader.get.return_value = dict(LITE_RECORD)

    assert db.get_country("1.1.1.1") == "DE"


@pytest.mark.asyncio
async def test_country_rule_blocks_ip_with_lite_record(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = Mock()
    db.reader.get.return_value = dict(LITE_RECORD)

    allowed, country = await db.check_country_access("1.1.1.1", ["DE"])
    assert (allowed, country) == (False, "DE")

    allowed, country = await db.check_country_access("1.1.1.1", [], ["FR"])
    assert (allowed, country) == (False, "DE")

    allowed, country = await db.check_country_access("1.1.1.1", [], ["DE"])
    assert (allowed, country) == (True, "DE")


def test_ipinfo_not_initialized() -> None:
    db = IPInfoManager(token="test")
    assert db.is_initialized is False


async def test_corrupted_db_removal(tmp_path: Path) -> None:
    test_db_path = tmp_path / "country_asn.mmdb"
    test_db_path.touch()
    db = IPInfoManager(token="test", db_path=test_db_path)

    with (
        patch.object(IPInfoManager, "_is_db_outdated", return_value=False),
        patch(
            "maxminddb.open_database",
            side_effect=Exception("corrupt database"),
        ),
    ):
        await db.initialize()

    assert db.reader is None
    assert not db.db_path.exists()


@pytest.mark.asyncio
async def test_download_exhausts_retries(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    mock_session = _mock_aiohttp(side_effect=Exception("Download failed"))

    with (
        patch(
            "aiohttp.ClientSession",
            return_value=mock_session,
        ),
        patch("asyncio.sleep"),
    ):
        with pytest.raises(Exception, match="Download failed"):
            await db._download_database()


@pytest.mark.asyncio
async def test_redirect_handling(tmp_path: Path) -> None:
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")

    mock_session = _mock_aiohttp(content=VALID_DB)

    with patch(
        "aiohttp.ClientSession",
        return_value=mock_session,
    ):
        await db._download_database()

        assert db.db_path.exists()
        with open(db.db_path, "rb") as f:
            assert f.read() == VALID_DB

        mock_session.get.assert_called_once()


@pytest.mark.asyncio
async def test_download_database_atomic_replace_leaves_no_temp_file(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "test.mmdb"
    db = IPInfoManager(token="test", db_path=db_path)
    mock_session = _mock_aiohttp(content=VALID_DB)

    with patch(
        "aiohttp.ClientSession",
        return_value=mock_session,
    ):
        await db._download_database()

    assert db_path.read_bytes() == VALID_DB
    assert not db_path.with_name(db_path.name + ".tmp").exists()


@pytest.mark.asyncio
async def test_download_database_removes_temp_file_when_replace_fails(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "existing.mmdb"
    db_path.write_bytes(b"good db bytes")
    db = IPInfoManager(token="test", db_path=db_path)
    db._download_retries = 1
    mock_session = _mock_aiohttp(content=VALID_DB)

    with (
        patch(
            "aiohttp.ClientSession",
            return_value=mock_session,
        ),
        patch(
            "guard_core.handlers.ipinfo_handler.os.replace",
            side_effect=OSError("cross-device link"),
        ),
    ):
        with pytest.raises(OSError, match="cross-device link"):
            await db._download_database()

    assert db_path.read_bytes() == b"good db bytes"
    assert not db_path.with_name(db_path.name + ".tmp").exists()


def test_file_operations(tmp_path: Path) -> None:
    test_path = tmp_path / "test.mmdb"
    test_path.touch()

    mock_reader = Mock()
    mock_reader.__enter__ = Mock(return_value=mock_reader)
    mock_reader.__exit__ = Mock(return_value=None)

    with patch("maxminddb.open_database", return_value=mock_reader):
        with maxminddb.open_database(str(test_path)) as reader:
            assert reader is not None


def test_an_unavailable_reader_warns_once_a_minute_without_the_client_address(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    IPInfoManager._instance = None
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = None

    with caplog.at_level("WARNING", logger="guard_core.handlers.ipinfo"):
        for index in range(50):
            assert db.get_country(f"198.51.100.{index}") is None

    assert len(caplog.records) == 1
    assert "198.51.100" not in caplog.text
    IPInfoManager._instance = None


def test_get_country_without_init_returns_none_and_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    IPInfoManager._instance = None
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")
    db.reader = None

    with caplog.at_level("WARNING", logger="guard_core.handlers.ipinfo"):
        result = db.get_country("1.1.1.1")

    assert result is None
    warnings = [
        record
        for record in caplog.records
        if record.levelname == "WARNING" and record.name == "guard_core.handlers.ipinfo"
    ]
    assert len(warnings) == 1
    assert "Geo-IP reader uninitialized" in warnings[0].getMessage()
    assert "1.1.1.1" not in warnings[0].getMessage()
    IPInfoManager._instance = None


async def test_initialize_sets_reader_none_when_download_fails_and_db_missing(
    tmp_path: Path,
) -> None:
    from unittest.mock import AsyncMock, patch

    from guard_core.handlers.ipinfo_handler import IPInfoManager

    IPInfoManager._instance = None
    db = tmp_path / "missing.mmdb"
    mgr = IPInfoManager(token="tok", db_path=db)
    mgr.redis_handler = None

    async def _raise(*_a: object, **_kw: object) -> None:
        raise RuntimeError("download failed")

    with patch.object(mgr, "_download_database", new=AsyncMock(side_effect=_raise)):
        await mgr.initialize()

    assert mgr.reader is None
    assert not db.exists()


async def test_initialize_leaves_reader_unset_when_download_silently_no_file(
    tmp_path: Path,
) -> None:
    from unittest.mock import AsyncMock, patch

    from guard_core.handlers.ipinfo_handler import IPInfoManager

    IPInfoManager._instance = None
    db = tmp_path / "quiet.mmdb"
    mgr = IPInfoManager(token="tok", db_path=db)
    mgr.redis_handler = None
    mgr.reader = None

    async def _noop() -> None:
        return None

    with patch.object(mgr, "_download_database", new=AsyncMock(side_effect=_noop)):
        await mgr.initialize()

    assert mgr.reader is None


async def test_initialize_redis_cache_miss_falls_through_to_download(
    tmp_path: Path,
) -> None:
    from unittest.mock import AsyncMock, patch

    from guard_core.handlers.ipinfo_handler import IPInfoManager

    IPInfoManager._instance = None
    db = tmp_path / "cached.mmdb"
    mgr = IPInfoManager(token="tok", db_path=db)
    mgr.redis_handler = AsyncMock()
    mgr.redis_handler.get_key = AsyncMock(return_value=None)

    with patch.object(mgr, "_download_database", new=AsyncMock()):
        await mgr.initialize()


async def test_initialize_skips_download_when_db_exists_and_fresh(
    tmp_path: Path,
) -> None:
    from unittest.mock import AsyncMock, MagicMock, patch

    import maxminddb

    from guard_core.handlers.ipinfo_handler import IPInfoManager

    IPInfoManager._instance = None
    db = tmp_path / "fresh.mmdb"
    db.write_bytes(b"stub")

    mgr = IPInfoManager(token="tok", db_path=db)
    mgr.redis_handler = None

    fake_reader = MagicMock()
    fake_reader.close = MagicMock()
    with (
        patch.object(mgr, "_is_db_outdated", return_value=False),
        patch.object(mgr, "_download_database", new=AsyncMock()) as mock_dl,
        patch.object(maxminddb, "open_database", return_value=fake_reader),
    ):
        await mgr.initialize()

    mock_dl.assert_not_awaited()
    IPInfoManager._instance = None


async def test_initialize_redis_delegates_to_initialize() -> None:
    from unittest.mock import AsyncMock, patch

    from guard_core.handlers.ipinfo_handler import IPInfoManager

    IPInfoManager._instance = None
    mgr = IPInfoManager(token="tok")
    redis_handler = AsyncMock()
    with patch.object(mgr, "initialize", new=AsyncMock()) as mock_init:
        await mgr.initialize_redis(redis_handler)
    mock_init.assert_awaited_once()
    assert mgr.redis_handler is redis_handler


async def test_one_instance_per_path_keeps_first_token_smallest_max_age() -> None:
    from guard_core.handlers.ipinfo_handler import IPInfoManager

    IPInfoManager._instance = None
    first = IPInfoManager(token="initial-token", max_age=2592000)
    first_id = id(first)

    elsewhere = IPInfoManager(
        token="updated-token", db_path=Path("/tmp/different.mmdb")
    )
    assert id(elsewhere) != first_id
    assert elsewhere.token == "updated-token"
    assert elsewhere.db_path == Path("/tmp/different.mmdb")

    third = IPInfoManager(token="third-token", max_age=86400)
    assert id(third) == first_id
    assert third.token == "initial-token"
    assert third._max_age == 86400
    assert first.db_path == Path("data/ipinfo/country_asn.mmdb")
    IPInfoManager._instance = None


async def test_initialize_agent_assigns_handler() -> None:
    IPInfoManager._instance = None
    mgr = IPInfoManager(token="tok")
    agent = AsyncMock()
    await mgr.initialize_agent(agent)
    assert mgr.agent_handler is agent
    IPInfoManager._instance = None


async def test_send_geo_event_no_op_without_agent_handler() -> None:
    IPInfoManager._instance = None
    mgr = IPInfoManager(token="tok")
    mgr.agent_handler = None
    await mgr._send_geo_event(
        event_type="x",
        ip_address="1.1.1.1",
        action_taken="y",
        reason="z",
    )
    IPInfoManager._instance = None


async def test_send_geo_event_dispatches_to_agent_handler() -> None:
    IPInfoManager._instance = None
    mgr = IPInfoManager(token="tok")
    mgr.agent_handler = AsyncMock()
    mgr.agent_handler.send_event = AsyncMock()
    await mgr._send_geo_event(
        event_type="probe",
        ip_address="2.2.2.2",
        action_taken="noted",
        reason="because",
        extra="meta",
    )
    mgr.agent_handler.send_event.assert_awaited_once()
    IPInfoManager._instance = None


async def test_send_geo_event_logs_when_agent_send_event_fails(
    caplog: pytest.LogCaptureFixture,
) -> None:
    IPInfoManager._instance = None
    mgr = IPInfoManager(token="tok")
    mgr.agent_handler = AsyncMock()
    mgr.agent_handler.send_event = AsyncMock(side_effect=RuntimeError("agent down"))

    with caplog.at_level("ERROR", logger="guard_core.handlers.ipinfo"):
        await mgr._send_geo_event(
            event_type="probe",
            ip_address="3.3.3.3",
            action_taken="failed",
            reason="boom",
        )

    assert any(
        "Failed to send geo event to agent" in record.getMessage()
        for record in caplog.records
    )
    IPInfoManager._instance = None


async def test_initialize_failure_emits_geo_event_when_agent_present(
    tmp_path: Path,
) -> None:
    IPInfoManager._instance = None
    mgr = IPInfoManager(token="tok", db_path=tmp_path / "missing.mmdb")
    mgr.redis_handler = None
    mgr.agent_handler = AsyncMock()
    mgr.agent_handler.send_event = AsyncMock()

    async def _raise(*_a: object, **_kw: object) -> None:
        raise RuntimeError("download failed")

    with patch.object(mgr, "_download_database", new=AsyncMock(side_effect=_raise)):
        await mgr.initialize()

    mgr.agent_handler.send_event.assert_awaited_once()
    assert mgr.reader is None
    IPInfoManager._instance = None


async def test_get_country_exception_with_agent_dispatches_geo_event(  # async-only
    tmp_path: Path,
) -> None:
    IPInfoManager._instance = None
    mgr = IPInfoManager(token="tok", db_path=tmp_path / "test.mmdb")
    mgr.reader = Mock()
    mgr.reader.get.side_effect = RuntimeError("DB error")
    mgr.agent_handler = AsyncMock()
    mgr.agent_handler.send_event = AsyncMock()

    captured: list[Any] = []

    def fake_create_task(coro: Any) -> Mock:
        captured.append(coro)
        coro.close()
        return Mock()

    with patch("asyncio.create_task", side_effect=fake_create_task):
        assert mgr.get_country("4.4.4.4") is None

    assert len(captured) == 1
    IPInfoManager._instance = None


async def test_get_country_exception_with_agent_handles_create_task_failure(
    tmp_path: Path,
) -> None:
    IPInfoManager._instance = None
    mgr = IPInfoManager(token="tok", db_path=tmp_path / "test.mmdb")
    mgr.reader = Mock()
    mgr.reader.get.side_effect = RuntimeError("DB error")
    mgr.agent_handler = AsyncMock()
    mgr.agent_handler.send_event = AsyncMock()

    with patch("asyncio.create_task", side_effect=RuntimeError("no loop")):
        assert mgr.get_country("5.5.5.5") is None
    IPInfoManager._instance = None


async def test_check_country_access_returns_true_when_country_unknown(
    tmp_path: Path,
) -> None:
    IPInfoManager._instance = None
    mgr = IPInfoManager(token="tok", db_path=tmp_path / "test.mmdb")
    mgr.reader = Mock()
    mgr.reader.get.return_value = None

    allowed, country = await mgr.check_country_access("6.6.6.6", blocked_countries=[])
    assert allowed is True
    assert country is None
    IPInfoManager._instance = None


async def test_check_country_access_blocks_when_country_unknown_and_whitelisted(
    tmp_path: Path,
) -> None:
    IPInfoManager._instance = None
    mgr = IPInfoManager(token="tok", db_path=tmp_path / "test.mmdb")
    mgr.reader = Mock()
    mgr.reader.get.return_value = None

    allowed, country = await mgr.check_country_access(
        "7.7.7.7", blocked_countries=[], whitelist_countries=["US"]
    )
    assert allowed is False
    assert country is None
    IPInfoManager._instance = None


async def test_check_country_access_blocks_country_not_in_whitelist(
    tmp_path: Path,
) -> None:
    IPInfoManager._instance = None
    mgr = IPInfoManager(token="tok", db_path=tmp_path / "test.mmdb")
    mgr.reader = Mock()
    mgr.reader.get.return_value = {"country": "FR"}
    mgr.agent_handler = AsyncMock()
    mgr.agent_handler.send_event = AsyncMock()

    allowed, country = await mgr.check_country_access(
        "8.8.8.8", blocked_countries=[], whitelist_countries=["US"]
    )
    assert allowed is False
    assert country == "FR"
    mgr.agent_handler.send_event.assert_awaited_once()
    IPInfoManager._instance = None


async def test_check_country_access_blocks_country_in_blacklist(
    tmp_path: Path,
) -> None:
    IPInfoManager._instance = None
    mgr = IPInfoManager(token="tok", db_path=tmp_path / "test.mmdb")
    mgr.reader = Mock()
    mgr.reader.get.return_value = {"country": "RU"}
    mgr.agent_handler = AsyncMock()
    mgr.agent_handler.send_event = AsyncMock()

    allowed, country = await mgr.check_country_access(
        "9.9.9.9", blocked_countries=["RU"]
    )
    assert allowed is False
    assert country == "RU"
    mgr.agent_handler.send_event.assert_awaited_once()
    IPInfoManager._instance = None


async def test_check_country_access_allows_country_when_unblocked(
    tmp_path: Path,
) -> None:
    IPInfoManager._instance = None
    mgr = IPInfoManager(token="tok", db_path=tmp_path / "test.mmdb")
    mgr.reader = Mock()
    mgr.reader.get.return_value = {"country": "US"}

    allowed, country = await mgr.check_country_access(
        "10.10.10.10", blocked_countries=["RU"], whitelist_countries=["US"]
    )
    assert allowed is True
    assert country == "US"
    IPInfoManager._instance = None


async def test_refresh_reopens_database_after_download(tmp_path: Path) -> None:
    IPInfoManager._instance = None
    db_path = tmp_path / "refresh.mmdb"
    mgr = IPInfoManager(token="tok", db_path=db_path)
    mgr.reader = Mock()

    async def _write_file() -> None:
        db_path.write_bytes(b"refreshed")

    fake_reader = Mock()
    with (
        patch.object(mgr, "_download_database", new=AsyncMock(side_effect=_write_file)),
        patch("maxminddb.open_database", return_value=fake_reader),
    ):
        await mgr.refresh()

    assert mgr.reader is fake_reader
    IPInfoManager._instance = None


async def test_refresh_aborts_when_download_fails(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    IPInfoManager._instance = None
    db_path = tmp_path / "refresh.mmdb"
    mgr = IPInfoManager(token="tok", db_path=db_path)

    async def _raise() -> None:
        raise RuntimeError("network down")

    with (
        patch.object(mgr, "close") as mock_close,
        patch.object(mgr, "_download_database", new=AsyncMock(side_effect=_raise)),
        caplog.at_level("ERROR", logger="guard_core.handlers.ipinfo"),
    ):
        await mgr.refresh()

    mock_close.assert_not_called()
    assert mgr.reader is None
    assert any("IPInfo refresh failed" in r.getMessage() for r in caplog.records)
    IPInfoManager._instance = None


async def test_refresh_keeps_reader_unset_when_download_yields_no_file(
    tmp_path: Path,
) -> None:
    IPInfoManager._instance = None
    db_path = tmp_path / "refresh_no_file.mmdb"
    mgr = IPInfoManager(token="tok", db_path=db_path)

    with (
        patch.object(mgr, "close") as mock_close,
        patch.object(mgr, "_download_database", new=AsyncMock()),
    ):
        await mgr.refresh()

    mock_close.assert_not_called()
    assert mgr.reader is None


async def test_initialize_keeps_working_reader_when_download_fails(
    tmp_path: Path,
) -> None:
    IPInfoManager._instance = None
    db_path = tmp_path / "existing.mmdb"
    db_path.write_bytes(b"good db bytes")
    db = IPInfoManager(token="test", db_path=db_path)
    working_reader = Mock()
    working_reader.get.return_value = {"country": "US"}
    db.reader = working_reader

    async def _raise(*_a: object, **_kw: object) -> None:
        raise RuntimeError("network down")

    with (
        patch.object(db, "_is_db_outdated", return_value=True),
        patch.object(db, "_download_database", new=AsyncMock(side_effect=_raise)),
    ):
        await db.initialize()

    assert db.reader is working_reader
    assert db.db_path.exists()
    assert db.get_country("1.1.1.1") == "US"
    IPInfoManager._instance = None


async def test_refresh_keeps_working_reader_when_download_fails(
    tmp_path: Path,
) -> None:
    IPInfoManager._instance = None
    db_path = tmp_path / "existing.mmdb"
    db_path.write_bytes(b"good db bytes")
    db = IPInfoManager(token="test", db_path=db_path)
    working_reader = Mock()
    working_reader.get.return_value = {"country": "US"}
    db.reader = working_reader

    async def _raise() -> None:
        raise RuntimeError("network down")

    with patch.object(db, "_download_database", new=AsyncMock(side_effect=_raise)):
        await db.refresh()

    assert db.reader is working_reader
    assert db.db_path.exists()
    assert db.get_country("1.1.1.1") == "US"
    IPInfoManager._instance = None


async def test_refresh_keeps_previous_reader_when_reopened_db_is_corrupt(
    tmp_path: Path,
) -> None:
    IPInfoManager._instance = None
    db_path = tmp_path / "existing.mmdb"
    db_path.write_bytes(b"good db bytes")
    db = IPInfoManager(token="test", db_path=db_path)
    working_reader = Mock()
    working_reader.get.return_value = {"country": "US"}
    db.reader = working_reader

    async def fake_download() -> None:
        db_path.write_bytes(b"corrupt bytes")

    with (
        patch.object(
            db, "_download_database", new=AsyncMock(side_effect=fake_download)
        ),
        patch(
            "maxminddb.open_database",
            side_effect=Exception("corrupt database"),
        ),
    ):
        await db.refresh()

    assert db.reader is working_reader
    assert not db.db_path.exists()
    assert db.get_country("1.1.1.1") == "US"
    IPInfoManager._instance = None


async def test_refresh_keeps_previous_database_when_temp_write_fails(
    tmp_path: Path,
) -> None:
    IPInfoManager._instance = None
    db_path = tmp_path / "existing.mmdb"
    db_path.write_bytes(b"good db bytes")
    db = IPInfoManager(token="test", db_path=db_path)
    db._download_retries = 1
    working_reader = Mock()
    working_reader.get.return_value = {"country": "US"}
    db.reader = working_reader

    mock_session = _mock_aiohttp(content=VALID_DB)
    real_open = open

    def fake_open(path: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if str(path).endswith(".tmp") and "w" in mode:
            raise OSError("disk full")
        return real_open(path, mode, *args, **kwargs)

    with (
        patch(
            "aiohttp.ClientSession",
            return_value=mock_session,
        ),
        patch("builtins.open", side_effect=fake_open),
    ):
        await db.refresh()

    assert db.reader is working_reader
    assert db_path.read_bytes() == b"good db bytes"
    assert db.get_country("1.1.1.1") == "US"
    assert not db_path.with_name(db_path.name + ".tmp").exists()
    IPInfoManager._instance = None


def test_open_database_or_none_skips_unlink_when_file_already_missing(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "missing.mmdb"
    db = IPInfoManager(token="test", db_path=db_path)

    with patch(
        "maxminddb.open_database",
        side_effect=Exception("corrupt database"),
    ):
        result = db._open_database_or_none()

    assert result is None
    assert not db.db_path.exists()
    IPInfoManager._instance = None


def test_get_country_warns_uninitialized_before_any_init_attempt(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    IPInfoManager._instance = None
    db = IPInfoManager(token="test", db_path=tmp_path / "test.mmdb")

    with caplog.at_level("WARNING", logger="guard_core.handlers.ipinfo"):
        result = db.get_country("1.1.1.1")

    assert result is None
    assert "Geo-IP reader uninitialized" in caplog.text
    assert "failed initialization attempt" not in caplog.text
    IPInfoManager._instance = None


async def test_get_country_warns_permanent_failure_after_failed_init_attempt(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    IPInfoManager._instance = None
    db = IPInfoManager(token="test", db_path=tmp_path / "missing.mmdb")
    mock_session = _mock_aiohttp(side_effect=Exception("Download failed"))

    with (
        patch(
            "aiohttp.ClientSession",
            return_value=mock_session,
        ),
        patch("asyncio.sleep"),
    ):
        await db.initialize()

    assert db.reader is None

    with caplog.at_level("WARNING", logger="guard_core.handlers.ipinfo"):
        result = db.get_country("1.1.1.1")

    assert result is None
    assert "failed initialization attempt" in caplog.text
    assert "1.1.1.1" not in caplog.text
    IPInfoManager._instance = None


async def test_get_status_reports_not_ready_before_init_and_ready_after(
    tmp_path: Path,
) -> None:
    IPInfoManager._instance = None
    db_path = tmp_path / "status.mmdb"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with open(db_path, "wb") as f:
        f.write(b"dummy data")

    db = IPInfoManager(token="test_token", db_path=db_path)

    status_before = db.get_status()
    assert status_before == {"ready": False, "last_refreshed": None, "entries": 0}

    with patch("maxminddb.open_database") as mock_open_db:
        mock_reader = Mock()
        mock_reader.metadata.return_value = Mock(node_count=42)
        mock_open_db.return_value = mock_reader

        await db.initialize()

    status_after = db.get_status()
    assert status_after["ready"] is True
    assert status_after["entries"] == 42
    assert status_after["last_refreshed"] is not None
    IPInfoManager._instance = None


def test_get_country_regression_returns_none_when_reader_missing() -> None:
    IPInfoManager._instance = None
    db = IPInfoManager(token="test")
    db.reader = None

    result = db.get_country("1.1.1.1")

    assert result is None
    IPInfoManager._instance = None
    IPInfoManager._instance = None
