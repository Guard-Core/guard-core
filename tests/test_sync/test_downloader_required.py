from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from guard_core._config_capabilities import install_hint
from guard_core.exceptions import DownloaderNotInstalledError
from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.handlers._downloader import (
    TREE_DOWNLOADER,
    require_downloader_installed,
)
from guard_core.sync.handlers.cloud_handler import cloud_handler
from guard_core.sync.handlers.cloud_ip_stores import InMemoryCloudIpStore
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager

_MISSING = patch(
    "guard_core.sync.handlers._downloader._extra_installed", return_value=False
)


def test_install_hint_names_the_adapter_given_or_registered() -> None:
    assert install_hint("cloud") == "pip install guard-core[cloud]"
    assert install_hint("cloud", "x-guard").endswith("(or x-guard[cloud])")


def test_a_present_downloader_passes_and_a_missing_one_raises_a_value_error() -> None:
    require_downloader_installed("cloud", "Fetching")
    with _MISSING, pytest.raises(DownloaderNotInstalledError) as raised:
        require_downloader_installed("cloud", "Fetching", "x-guard")
    assert isinstance(raised.value, ValueError)
    assert TREE_DOWNLOADER in str(raised.value)
    assert "x-guard[cloud]" in str(raised.value)


def test_the_initializer_refuses_cloud_blocking_without_the_downloader() -> None:
    config = SyncSecurityConfig(block_cloud_providers={"AWS"})
    with _MISSING, pytest.raises(DownloaderNotInstalledError):
        HandlerInitializer(config, adapter="x-guard")


def test_the_initializer_refuses_the_builtin_geo_download_without_it() -> None:
    config = SyncSecurityConfig(ipinfo_token="t", blocked_countries={"US"})
    with _MISSING, pytest.raises(DownloaderNotInstalledError):
        HandlerInitializer(config, geo_ip_handler=config.geo_ip_handler)


def test_the_initializer_accepts_a_config_that_needs_no_downloader() -> None:
    config = SyncSecurityConfig()
    with _MISSING:
        HandlerInitializer(config)
        HandlerInitializer(config, geo_ip_handler=MagicMock())


def test_a_fetch_without_the_downloader_raises_on_every_refresh_path() -> None:
    cloud_handler.set_store(InMemoryCloudIpStore())
    cloud_handler.redis_handler = None
    cloud_handler.ip_ranges = {}
    with _MISSING:
        with pytest.raises(DownloaderNotInstalledError):
            cloud_handler.refresh(["AWS"])
        with pytest.raises(DownloaderNotInstalledError):
            cloud_handler.refresh_async(["AWS"])
        redis_handler = MagicMock()
        redis_handler.get_key = MagicMock(return_value=None)
        cloud_handler._store = None
        cloud_handler.redis_handler = redis_handler
        with pytest.raises(DownloaderNotInstalledError):
            cloud_handler.refresh_async(["AWS"])
    cloud_handler.redis_handler = None
    cloud_handler.set_store(InMemoryCloudIpStore())
    assert cloud_handler.ip_ranges == {}


def test_the_geo_download_without_the_downloader_raises(tmp_path: Path) -> None:
    manager = IPInfoManager(token="t", db_path=tmp_path / "geo.mmdb")
    with _MISSING, pytest.raises(DownloaderNotInstalledError):
        manager._fetch_and_store_database()
