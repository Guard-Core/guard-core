import logging

import aiohttp
import pytest

from guard_core.handlers import _cloud_azure_fetch as azure
from guard_core.handlers import _cloud_provider_fetchers as fetchers


class _Response:
    def __init__(self, document: object) -> None:
        self.document = document

    def raise_for_status(self) -> None:
        return None

    async def json(self, content_type: object = None) -> object:
        return self.document

    async def text(self) -> str:
        return ""


class _Session:
    def __init__(self, document: object) -> None:
        self.document = document

    async def __aenter__(self) -> "_Session":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def get(self, *_args: object, **_kwargs: object) -> _Response:
        return _Response(self.document)


def _serve(monkeypatch: pytest.MonkeyPatch, document: object) -> None:
    monkeypatch.setattr(aiohttp, "ClientSession", lambda *a, **k: _Session(document))


async def test_aws_keeps_the_valid_prefixes_and_logs_the_bad_one(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _serve(
        monkeypatch,
        {
            "prefixes": [
                {"service": "AMAZON", "ip_prefix": "3.5.140.0/22", "region": "x"},
                {"service": "AMAZON", "ip_prefix": "3.5.140.7/22", "region": "x"},
                {"service": "AMAZON", "ip_prefix": "not-a-prefix", "region": "x"},
            ]
        },
    )

    with caplog.at_level(logging.WARNING, logger="guard_core.handlers.cloud"):
        networks, regions = await fetchers.fetch_aws_ip_ranges()

    assert {str(network) for network in networks} == {"3.5.140.0/22"}
    assert regions == {"3.5.140.0/22": "x"}
    assert "skipped 2 invalid prefix" in caplog.text


async def test_gcp_keeps_the_valid_prefixes(monkeypatch: pytest.MonkeyPatch) -> None:
    _serve(
        monkeypatch,
        {"prefixes": [{"ipv4Prefix": "34.80.0.0/15"}, {"ipv4Prefix": "34.80.0.9/15"}]},
    )

    networks, _ = await fetchers.fetch_gcp_ip_ranges()

    assert {str(network) for network in networks} == {"34.80.0.0/15"}


async def test_azure_keeps_the_valid_prefixes(monkeypatch: pytest.MonkeyPatch) -> None:
    document = {
        "values": [
            {
                "name": "AzureCloud",
                "properties": {"addressPrefixes": ["20.33.0.0/16", "20.34.0.1/16"]},
            }
        ]
    }
    _serve(monkeypatch, document)

    async def download(url: str, deadline: object = None) -> object:
        return document

    monkeypatch.setattr(azure, "_download_azure_service_tags", download)
    monkeypatch.setattr(
        azure,
        "_extract_azure_download_url",
        lambda html: (
            "https://download.microsoft.com/x/ServiceTags_Public_20260101.json"
        ),
    )

    networks = await azure.fetch_azure_ip_ranges()

    assert {str(network) for network in networks} == {"20.33.0.0/16"}
