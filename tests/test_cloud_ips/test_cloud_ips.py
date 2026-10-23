import ipaddress
import itertools
import logging
from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.handlers.cloud_handler import (
    _AZURE_DOWNLOAD_MAX_ELAPSED_SECONDS,
    _AZURE_PAGE_FETCH_TIMEOUT_SECONDS,
    _download_azure_service_tags,
    _extract_azure_download_url,
    _extract_failover_link_url,
    _extract_newest_service_tags_url,
    _is_trusted_azure_download_url,
    cloud_handler,
    fetch_aws_ip_ranges,
    fetch_azure_ip_ranges,
    fetch_digitalocean_ip_ranges,
    fetch_gcp_ip_ranges,
    fetch_linode_ip_ranges,
    fetch_vultr_ip_ranges,
)
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig


def _mock_aiohttp_response(
    json_data: dict | None = None,
    text_data: str | None = None,
    status: int = 200,
) -> MagicMock:
    mock_response = MagicMock()
    mock_response.status = status
    mock_response.raise_for_status = MagicMock()
    if json_data is not None:
        mock_response.json = AsyncMock(return_value=json_data)
    if text_data is not None:
        mock_response.text = AsyncMock(return_value=text_data)
    mock_response.read = AsyncMock(return_value=b"")
    return mock_response


def _mock_session(*responses: MagicMock) -> MagicMock:
    mock_session = MagicMock()
    mock_session.get = AsyncMock(
        side_effect=list(responses) if len(responses) > 1 else responses[0]
    )
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    return mock_session


def _azure_cloud_tag(prefixes: list[str]) -> dict[str, Any]:
    return {
        "name": "AzureCloud",
        "id": "AzureCloud",
        "properties": {"addressPrefixes": prefixes},
    }


@pytest.fixture
def mock_aiohttp_session() -> Generator[MagicMock, None, None]:
    with patch("aiohttp.ClientSession") as mock_cls:
        mock_sess = MagicMock()
        mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
        mock_sess.__aexit__ = AsyncMock(return_value=None)
        mock_cls.return_value = mock_sess
        yield mock_sess


async def test_fetch_aws_ip_ranges(mock_aiohttp_session: MagicMock) -> None:
    mock_resp = _mock_aiohttp_response(
        json_data={
            "prefixes": [
                {
                    "ip_prefix": "192.168.0.0/24",
                    "service": "AMAZON",
                    "region": "us-east-1",
                },
                {"ip_prefix": "10.0.0.0/8", "service": "EC2"},
                {"ip_prefix": "172.16.0.0/12", "service": "AMAZON"},
            ]
        }
    )
    mock_aiohttp_session.get = AsyncMock(return_value=mock_resp)

    networks, regions = await fetch_aws_ip_ranges()
    assert ipaddress.IPv4Network("192.168.0.0/24") in networks
    assert ipaddress.IPv4Network("10.0.0.0/8") not in networks
    assert regions[str(ipaddress.IPv4Network("192.168.0.0/24"))] == "us-east-1"
    assert ipaddress.IPv4Network("172.16.0.0/12") in networks
    assert str(ipaddress.IPv4Network("172.16.0.0/12")) not in regions


async def test_fetch_gcp_ip_ranges(mock_aiohttp_session: MagicMock) -> None:
    mock_resp = _mock_aiohttp_response(
        json_data={
            "prefixes": [
                {"ipv4Prefix": "172.16.0.0/12", "scope": "us-central1"},
                {"ipv6Prefix": "2001:db8::/32", "scope": "europe-west1"},
            ]
        }
    )
    mock_aiohttp_session.get = AsyncMock(return_value=mock_resp)

    networks, regions = await fetch_gcp_ip_ranges()
    assert ipaddress.IPv4Network("172.16.0.0/12") in networks
    assert ipaddress.IPv6Network("2001:db8::/32") in networks
    assert len(networks) == 2
    assert regions[str(ipaddress.IPv4Network("172.16.0.0/12"))] == "us-central1"


async def test_fetch_azure_ip_ranges(mock_aiohttp_session: MagicMock) -> None:
    mock_html_resp = _mock_aiohttp_response(
        text_data="""
        Some HTML content
        manually <a href="https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20230515.json">
        More HTML content
        """
    )
    mock_json_resp = _mock_aiohttp_response(
        json_data={"values": [_azure_cloud_tag(["192.168.1.0/24", "2001:db8::/32"])]}
    )
    mock_aiohttp_session.get = AsyncMock(side_effect=[mock_html_resp, mock_json_resp])

    result = await fetch_azure_ip_ranges()
    assert ipaddress.IPv4Network("192.168.1.0/24") in result
    assert ipaddress.IPv6Network("2001:db8::/32") in result
    assert len(result) == 2


async def test_fetch_azure_ip_ranges_url_in_plain_text(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_html_resp = _mock_aiohttp_response(
        text_data='var url = "https://download.microsoft.com/x/ServiceTags_Public.json";'
    )
    mock_json_resp = _mock_aiohttp_response(
        json_data={"values": [_azure_cloud_tag(["10.0.0.0/8"])]}
    )
    mock_aiohttp_session.get = AsyncMock(side_effect=[mock_html_resp, mock_json_resp])

    result = await fetch_azure_ip_ranges()
    assert ipaddress.IPv4Network("10.0.0.0/8") in result


async def test_fetch_azure_ip_ranges_ignores_non_servicetags_json(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_html_resp = _mock_aiohttp_response(
        text_data='var m = "https://download.microsoft.com/download/manifests/index.json";'
    )
    mock_aiohttp_session.get = AsyncMock(return_value=mock_html_resp)

    result = await fetch_azure_ip_ranges()
    assert result == set()


async def test_fetch_azure_ip_ranges_preserves_query_string(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_html_resp = _mock_aiohttp_response(
        text_data='<a href="https://download.microsoft.com/x/ServiceTags.json?v=2">'
    )
    mock_json_resp = _mock_aiohttp_response(
        json_data={"values": [_azure_cloud_tag(["10.0.0.0/8"])]}
    )
    mock_aiohttp_session.get = AsyncMock(side_effect=[mock_html_resp, mock_json_resp])

    result = await fetch_azure_ip_ranges()
    assert ipaddress.IPv4Network("10.0.0.0/8") in result
    download_call = mock_aiohttp_session.get.call_args_list[1]
    assert (
        download_call.args[0] == "https://download.microsoft.com/x/ServiceTags.json?v=2"
    )


async def test_fetch_azure_ip_ranges_prefers_servicetags_link_over_unrelated_json(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_html_resp = _mock_aiohttp_response(
        text_data="""
        <a href="https://download.microsoft.com/download/manifests/unrelated.json">
        unrelated download
        </a>
        <a href="https://download.microsoft.com/download/7/1/D/ServiceTags_Public_20230515.json">
        service tags
        </a>
        """
    )
    mock_json_resp = _mock_aiohttp_response(
        json_data={"values": [_azure_cloud_tag(["10.0.0.0/8"])]}
    )
    mock_aiohttp_session.get = AsyncMock(side_effect=[mock_html_resp, mock_json_resp])

    result = await fetch_azure_ip_ranges()

    assert ipaddress.IPv4Network("10.0.0.0/8") in result
    download_call = mock_aiohttp_session.get.call_args_list[1]
    assert "ServiceTags_Public_20230515.json" in download_call.args[0]


async def test_fetch_azure_ip_ranges_ignores_stale_url_mentioned_before_download_link(
    mock_aiohttp_session: MagicMock,
) -> None:
    stale_url = (
        "https://download.microsoft.com/download/7/1/D/ServiceTags_Public_20230130.json"
    )
    current_url = (
        "https://download.microsoft.com/download/7/1/D/ServiceTags_Public_20250116.json"
    )
    mock_html_resp = _mock_aiohttp_response(
        text_data=f"""
        <html>
        <body>
          <section class="version-history" aria-label="Previous versions">
            <p>Looking for an older snapshot? See the prior release archived at
            {stale_url} for reference.</p>
          </section>
          <div id="mainDetailsSection">
            <a id="failoverLink" href="{current_url}">Manual download</a>
          </div>
        </body>
        </html>
        """
    )
    mock_json_resp = _mock_aiohttp_response(
        json_data={"values": [_azure_cloud_tag(["20.20.0.0/16"])]}
    )
    mock_aiohttp_session.get = AsyncMock(side_effect=[mock_html_resp, mock_json_resp])

    result = await fetch_azure_ip_ranges()

    assert ipaddress.IPv4Network("20.20.0.0/16") in result
    download_call = mock_aiohttp_session.get.call_args_list[1]
    assert download_call.args[0] == current_url


async def test_fetch_azure_ip_ranges_falls_back_to_newest_when_no_failover_link(
    mock_aiohttp_session: MagicMock,
) -> None:
    older_url = (
        "https://download.microsoft.com/download/7/1/D/ServiceTags_Public_20230130.json"
    )
    newer_url = (
        "https://download.microsoft.com/download/7/1/D/ServiceTags_Public_20250116.json"
    )
    mock_html_resp = _mock_aiohttp_response(
        text_data=f"""
        <a href="{older_url}">older</a>
        <a href="{newer_url}">newer</a>
        """
    )
    mock_json_resp = _mock_aiohttp_response(
        json_data={"values": [_azure_cloud_tag(["30.30.0.0/16"])]}
    )
    mock_aiohttp_session.get = AsyncMock(side_effect=[mock_html_resp, mock_json_resp])

    result = await fetch_azure_ip_ranges()

    assert ipaddress.IPv4Network("30.30.0.0/16") in result
    download_call = mock_aiohttp_session.get.call_args_list[1]
    assert download_call.args[0] == newer_url


def test_is_trusted_azure_download_url_accepts_the_real_host() -> None:
    assert _is_trusted_azure_download_url(
        "https://download.microsoft.com/download/x/ServiceTags.json"
    )


def test_is_trusted_azure_download_url_rejects_a_different_host() -> None:
    assert not _is_trusted_azure_download_url(
        "https://attacker.example.com/fake_ranges.json"
    )


def test_is_trusted_azure_download_url_rejects_non_https_scheme() -> None:
    assert not _is_trusted_azure_download_url(
        "http://169.254.169.254/latest/meta-data/"
    )


def test_is_trusted_azure_download_url_rejects_host_suffix_confusable_domain() -> None:
    assert not _is_trusted_azure_download_url(
        "https://download.microsoft.com.evil.com/x.json"
    )


async def test_download_azure_service_tags_defaults_to_a_full_budget_with_no_deadline(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_json_resp = _mock_aiohttp_response(
        json_data={"values": [_azure_cloud_tag(["10.0.0.0/8"])]}
    )
    mock_aiohttp_session.get = AsyncMock(return_value=mock_json_resp)

    data = await _download_azure_service_tags(
        "https://download.microsoft.com/valid.json"
    )

    assert data["values"][0]["properties"]["addressPrefixes"] == ["10.0.0.0/8"]


def test_extract_failover_link_url_with_no_href_attribute_returns_none() -> None:
    page = '<div id="mainDetailsSection"><a id="failoverLink">Manual download</a></div>'
    assert _extract_failover_link_url(page) is None


async def test_fetch_azure_ip_ranges_fails_fast_when_deadline_already_exhausted(
    mock_aiohttp_session: MagicMock,
) -> None:
    with patch(
        "guard_core.handlers.cloud_handler.time.monotonic",
        side_effect=[0.0, _AZURE_DOWNLOAD_MAX_ELAPSED_SECONDS],
    ):
        result = await fetch_azure_ip_ranges()

    assert result == set()
    mock_aiohttp_session.get.assert_not_called()


def test_extract_failover_link_url_rejects_untrusted_href() -> None:
    page = (
        '<div id="mainDetailsSection">'
        '<a id="failoverLink" href="https://attacker.example.com/fake_ranges.json">'
        "Manual download</a></div>"
    )
    assert _extract_failover_link_url(page) is None
    assert _extract_azure_download_url(page) is None


async def test_fetch_azure_ip_ranges_falls_back_when_failover_link_is_untrusted(
    mock_aiohttp_session: MagicMock,
) -> None:
    legit_url = (
        "https://download.microsoft.com/download/7/1/D/ServiceTags_Public_20250116.json"
    )
    mock_html_resp = _mock_aiohttp_response(
        text_data=f"""
        <div id="mainDetailsSection">
          <a id="failoverLink" href="https://attacker.example.com/fake_ranges.json">
            Manual download</a>
        </div>
        <a href="{legit_url}">service tags</a>
        """
    )
    mock_json_resp = _mock_aiohttp_response(
        json_data={"values": [_azure_cloud_tag(["40.40.0.0/16"])]}
    )
    mock_aiohttp_session.get = AsyncMock(side_effect=[mock_html_resp, mock_json_resp])

    result = await fetch_azure_ip_ranges()

    assert ipaddress.IPv4Network("40.40.0.0/16") in result
    download_call = mock_aiohttp_session.get.call_args_list[1]
    assert download_call.args[0] == legit_url


async def test_fetch_azure_ip_ranges_selects_azurecloud_tag_when_not_first(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_html_resp = _mock_aiohttp_response(
        text_data='<a href="https://download.microsoft.com/x/ServiceTags_Public_20250116.json">'
    )
    mock_json_resp = _mock_aiohttp_response(
        json_data={
            "values": [
                {
                    "name": "ActionGroup",
                    "id": "ActionGroup",
                    "properties": {"addressPrefixes": ["40.40.0.0/16"]},
                },
                {
                    "name": "AzureCloud",
                    "id": "AzureCloud",
                    "properties": {"addressPrefixes": ["10.0.0.0/8", "2001:db8::/32"]},
                },
                {
                    "name": "Storage",
                    "id": "Storage",
                    "properties": {"addressPrefixes": ["50.50.0.0/16"]},
                },
            ]
        }
    )
    mock_aiohttp_session.get = AsyncMock(side_effect=[mock_html_resp, mock_json_resp])

    result = await fetch_azure_ip_ranges()

    assert result == {
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv6Network("2001:db8::/32"),
    }


async def test_fetch_azure_ip_ranges_returns_empty_set_without_azurecloud_tag(
    mock_aiohttp_session: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    mock_html_resp = _mock_aiohttp_response(
        text_data='<a href="https://download.microsoft.com/x/ServiceTags_Public_20250116.json">'
    )
    mock_json_resp = _mock_aiohttp_response(
        json_data={
            "values": [
                {
                    "name": "ActionGroup",
                    "id": "ActionGroup",
                    "properties": {"addressPrefixes": ["40.40.0.0/16"]},
                },
            ]
        }
    )
    mock_aiohttp_session.get = AsyncMock(side_effect=[mock_html_resp, mock_json_resp])

    with caplog.at_level(logging.ERROR, logger="guard_core.handlers.cloud"):
        result = await fetch_azure_ip_ranges()

    assert result == set()
    assert any("AzureCloud" in r.getMessage() for r in caplog.records)


def test_extract_newest_service_tags_url_rejects_an_impossible_calendar_date() -> None:
    real_url = (
        "https://download.microsoft.com/download/7/1/D/ServiceTags_Public_20250115.json"
    )
    bogus_url = (
        "https://download.microsoft.com/download/9/9/9/ServiceTags_Public_99999999.json"
    )
    page = f'<a href="{real_url}">a</a> <a href="{bogus_url}">b</a>'
    assert _extract_newest_service_tags_url(page) == real_url


def test_extract_newest_service_tags_url_rejects_a_future_calendar_date() -> None:
    real_url = (
        "https://download.microsoft.com/download/7/1/D/ServiceTags_Public_20250115.json"
    )
    future_url = (
        "https://download.microsoft.com/download/9/9/9/ServiceTags_Public_20991231.json"
    )
    page = f'<a href="{real_url}">a</a> <a href="{future_url}">b</a>'
    assert _extract_newest_service_tags_url(page) == real_url


def test_extract_newest_service_tags_url_tie_break_is_independent_of_page_order() -> (
    None
):
    legit_url = (
        "https://download.microsoft.com/download/7/1/D/ServiceTags_Public_20250115.json"
    )
    lookalike_url = (
        "https://download.microsoft.com/download/A/T/K/ServiceTags_Public_20250115.json"
    )
    page_a = f'<a href="{lookalike_url}">a</a> <a href="{legit_url}">b</a>'
    page_b = f'<a href="{legit_url}">a</a> <a href="{lookalike_url}">b</a>'
    assert _extract_newest_service_tags_url(page_a) == _extract_newest_service_tags_url(
        page_b
    )


def test_extract_newest_service_tags_url_no_dates_is_independent_of_page_order() -> (
    None
):
    first_url = (
        "https://download.microsoft.com/download/1/1/1/ServiceTags_Public_stale.json"
    )
    second_url = "https://download.microsoft.com/download/2/2/2/ServiceTags_Public.json"
    page_a = f'<a href="{first_url}">a</a> <a href="{second_url}">b</a>'
    page_b = f'<a href="{second_url}">a</a> <a href="{first_url}">b</a>'
    assert _extract_newest_service_tags_url(page_a) == _extract_newest_service_tags_url(
        page_b
    )


def test_extract_newest_service_tags_url_warns_when_no_candidate_has_a_parseable_date(
    caplog: pytest.LogCaptureFixture,
) -> None:
    url = "https://download.microsoft.com/download/1/1/1/ServiceTags_Public_vNext.json"
    page = f'<a href="{url}">current</a>'

    with caplog.at_level(logging.WARNING, logger="guard_core.handlers.cloud"):
        selected = _extract_newest_service_tags_url(page)

    assert selected == url
    assert any("no parseable date" in record.message for record in caplog.records)


def test_extract_newest_service_tags_url_warns_when_winner_is_implausibly_old(
    caplog: pytest.LogCaptureFixture,
) -> None:
    stale_label = (datetime.now(timezone.utc) - timedelta(days=200)).strftime("%Y%m%d")
    url = (
        "https://download.microsoft.com/download/1/1/1/"
        f"ServiceTags_Public_{stale_label}.json"
    )
    page = f'<a href="{url}">current</a>'

    with caplog.at_level(logging.WARNING, logger="guard_core.handlers.cloud"):
        selected = _extract_newest_service_tags_url(page)

    assert selected == url
    assert any("possibly stale" in record.message for record in caplog.records)


def test_extract_newest_service_tags_url_does_not_warn_for_a_recent_date(
    caplog: pytest.LogCaptureFixture,
) -> None:
    recent_label = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y%m%d")
    url = (
        "https://download.microsoft.com/download/1/1/1/"
        f"ServiceTags_Public_{recent_label}.json"
    )
    page = f'<a href="{url}">current</a>'

    with caplog.at_level(logging.WARNING, logger="guard_core.handlers.cloud"):
        selected = _extract_newest_service_tags_url(page)

    assert selected == url
    assert caplog.records == []


async def test_azure_page_fetch_shares_the_download_deadline(  # async-only
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_html_resp = _mock_aiohttp_response(
        text_data='<a href="https://download.microsoft.com/valid.json">'
    )
    mock_json_resp = _mock_aiohttp_response(
        json_data={"values": [_azure_cloud_tag(["10.0.0.0/8"])]}
    )
    mock_aiohttp_session.get = AsyncMock(side_effect=[mock_html_resp, mock_json_resp])

    with (
        patch(
            "guard_core.handlers.cloud_handler.time.monotonic",
            side_effect=[0.0, 0.0, 12.0],
        ),
        patch("aiohttp.ClientTimeout") as mock_client_timeout,
    ):
        result = await fetch_azure_ip_ranges()

    assert ipaddress.IPv4Network("10.0.0.0/8") in result
    page_fetch_timeout = mock_client_timeout.call_args_list[0]
    download_attempt_timeout = mock_client_timeout.call_args_list[1]
    assert page_fetch_timeout.kwargs["total"] == _AZURE_PAGE_FETCH_TIMEOUT_SECONDS
    assert download_attempt_timeout.kwargs["total"] == (
        _AZURE_DOWNLOAD_MAX_ELAPSED_SECONDS - 12.0
    )


async def test_cloud_ip_ranges() -> None:
    with (
        patch(
            "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("192.168.0.0/24")},
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("172.16.0.0/12")},
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_azure_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("10.0.0.0/8")},
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_digitalocean_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_linode_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_vultr_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
    ):
        await cloud_handler._refresh_providers()

        assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        assert not cloud_handler.is_cloud_ip("192.168.0.1", {"GCP"})
        assert cloud_handler.is_cloud_ip("172.16.0.1", {"GCP"})
        assert cloud_handler.is_cloud_ip("10.0.0.1", {"Azure"})
        assert not cloud_handler.is_cloud_ip("8.8.8.8", {"AWS", "GCP", "Azure"})


async def test_cloud_ip_refresh() -> None:
    with (
        patch(
            "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
            new_callable=AsyncMock,
        ) as mock_aws,
        patch(
            "guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("172.16.0.0/12")},
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_azure_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("10.0.0.0/8")},
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_digitalocean_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_linode_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_vultr_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
    ):
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}

        await cloud_handler._refresh_providers()
        assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})

        mock_aws.return_value = {ipaddress.IPv4Network("192.168.1.0/24")}
        await cloud_handler.refresh()

        assert not cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        assert cloud_handler.is_cloud_ip("192.168.1.1", {"AWS"})


async def test_cloud_ip_refresh_subset() -> None:
    with (
        patch(
            "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("192.168.0.0/24")},
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("172.16.0.0/12")},
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_azure_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("10.0.0.0/8")},
        ),
    ):
        providers = ["AWS", "GCP", "Azure"]
        for r in range(1, 4):
            for combo in itertools.combinations(providers, r):
                provider_set = set(combo)
                cloud_handler.ip_ranges = {}
                await cloud_handler._refresh_providers(provider_set)

                if "AWS" in provider_set:
                    assert cloud_handler.is_cloud_ip("192.168.0.1")
                if "GCP" in provider_set:
                    assert cloud_handler.is_cloud_ip("172.16.0.1")
                if "Azure" in provider_set:
                    assert cloud_handler.is_cloud_ip("10.0.0.1")

                if "AWS" not in provider_set:
                    assert not cloud_handler.is_cloud_ip("192.168.0.1")
                if "GCP" not in provider_set:
                    assert not cloud_handler.is_cloud_ip("172.16.0.1")
                if "Azure" not in provider_set:
                    assert not cloud_handler.is_cloud_ip("10.0.0.1")


async def test_cloud_ip_ranges_error_handling() -> None:
    with (
        patch(
            "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
            new_callable=AsyncMock,
            side_effect=Exception("AWS error"),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges",
            new_callable=AsyncMock,
            side_effect=Exception("GCP error"),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_azure_ip_ranges",
            new_callable=AsyncMock,
            side_effect=Exception("Azure error"),
        ),
    ):
        assert not cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        assert not cloud_handler.is_cloud_ip("172.16.0.1", {"GCP"})
        assert not cloud_handler.is_cloud_ip("10.0.0.1", {"Azure"})


def test_cloud_ip_ranges_invalid_ip() -> None:
    assert not cloud_handler.is_cloud_ip("invalid_ip", {"AWS", "GCP", "Azure"})


async def test_fetch_aws_ip_ranges_error(mock_aiohttp_session: MagicMock) -> None:
    mock_aiohttp_session.get = AsyncMock(side_effect=Exception("API failure"))
    networks, _ = await fetch_aws_ip_ranges()
    assert networks == set()


async def test_fetch_gcp_ip_ranges_error(mock_aiohttp_session: MagicMock) -> None:
    mock_resp = _mock_aiohttp_response()
    mock_resp.json = AsyncMock(side_effect=Exception("Invalid JSON"))
    mock_aiohttp_session.get = AsyncMock(return_value=mock_resp)
    networks, _ = await fetch_gcp_ip_ranges()
    assert networks == set()


async def test_cloud_manager_refresh_handling() -> None:
    with (
        patch(
            "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("192.168.0.0/24")},
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("172.16.0.0/12")},
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_azure_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("10.0.0.0/8")},
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_digitalocean_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_linode_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_vultr_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
    ):
        cloud_handler.ip_ranges["AWS"] = set()
        assert len(cloud_handler.ip_ranges["AWS"]) == 0

        await cloud_handler.refresh()
        assert len(cloud_handler.ip_ranges["AWS"]) == 1


def test_is_cloud_ip_ipv6() -> None:
    assert not cloud_handler.is_cloud_ip("2001:db8::1", {"AWS"})


async def test_fetch_azure_ip_ranges_url_not_found(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_resp = _mock_aiohttp_response(text_data="HTML without download link")
    mock_aiohttp_session.get = AsyncMock(return_value=mock_resp)
    result = await fetch_azure_ip_ranges()
    assert result == set()


async def test_fetch_azure_ip_ranges_bad_status_is_not_retried(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_html_resp = _mock_aiohttp_response(
        text_data='<a href="https://download.microsoft.com/valid.json">'
    )
    mock_download_resp = MagicMock()
    mock_download_resp.raise_for_status = MagicMock(
        side_effect=Exception("404 Not Found")
    )
    mock_aiohttp_session.get = AsyncMock(
        side_effect=[mock_html_resp, mock_download_resp]
    )
    with patch(
        "guard_core.handlers.cloud_handler.asyncio.sleep", new_callable=AsyncMock
    ) as sleep_mock:
        result = await fetch_azure_ip_ranges()
    assert result == set()
    assert mock_aiohttp_session.get.await_count == 2
    sleep_mock.assert_not_called()


async def test_fetch_azure_ip_ranges_bad_json_body_is_not_retried(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_html_resp = _mock_aiohttp_response(
        text_data='<a href="https://download.microsoft.com/valid.json">'
    )
    mock_download_resp = MagicMock()
    mock_download_resp.raise_for_status = MagicMock()
    mock_download_resp.json = AsyncMock(side_effect=ValueError("Expecting value"))
    mock_aiohttp_session.get = AsyncMock(
        side_effect=[mock_html_resp, mock_download_resp]
    )
    with patch(
        "guard_core.handlers.cloud_handler.asyncio.sleep", new_callable=AsyncMock
    ) as sleep_mock:
        result = await fetch_azure_ip_ranges()
    assert result == set()
    assert mock_aiohttp_session.get.await_count == 2
    sleep_mock.assert_not_called()


async def test_fetch_azure_ip_ranges_retries_then_succeeds(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_html_resp = _mock_aiohttp_response(
        text_data='<a href="https://download.microsoft.com/valid.json">'
    )
    mock_json_resp = _mock_aiohttp_response(
        json_data={"values": [_azure_cloud_tag(["192.168.1.0/24"])]}
    )
    mock_aiohttp_session.get = AsyncMock(
        side_effect=[
            mock_html_resp,
            ConnectionError("connection reset"),
            mock_json_resp,
        ]
    )
    with patch(
        "guard_core.handlers.cloud_handler.asyncio.sleep", new_callable=AsyncMock
    ):
        result = await fetch_azure_ip_ranges()
    assert ipaddress.IPv4Network("192.168.1.0/24") in result
    assert mock_aiohttp_session.get.await_count == 3


async def test_fetch_azure_ip_ranges_gives_up_after_max_attempts(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_html_resp = _mock_aiohttp_response(
        text_data='<a href="https://download.microsoft.com/valid.json">'
    )
    mock_aiohttp_session.get = AsyncMock(
        side_effect=[
            mock_html_resp,
            ConnectionError("connection reset"),
            ConnectionError("connection reset"),
            ConnectionError("connection reset"),
        ]
    )
    with patch(
        "guard_core.handlers.cloud_handler.asyncio.sleep", new_callable=AsyncMock
    ):
        result = await fetch_azure_ip_ranges()
    assert result == set()
    assert mock_aiohttp_session.get.await_count == 4


async def test_fetch_azure_ip_ranges_stops_retrying_past_elapsed_bound(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_html_resp = _mock_aiohttp_response(
        text_data='<a href="https://download.microsoft.com/valid.json">'
    )
    mock_aiohttp_session.get = AsyncMock(
        side_effect=[
            mock_html_resp,
            ConnectionError("connection reset"),
            ConnectionError("connection reset"),
        ]
    )
    with (
        patch(
            "guard_core.handlers.cloud_handler.asyncio.sleep", new_callable=AsyncMock
        ) as sleep_mock,
        patch(
            "guard_core.handlers.cloud_handler.time.monotonic",
            side_effect=[0.0, 0.0, 0.0, 25.0],
        ),
    ):
        result = await fetch_azure_ip_ranges()
    assert result == set()
    assert mock_aiohttp_session.get.await_count == 2
    sleep_mock.assert_not_called()


async def test_fetch_azure_ip_ranges_checks_elapsed_before_each_attempt(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_html_resp = _mock_aiohttp_response(
        text_data='<a href="https://download.microsoft.com/valid.json">'
    )
    mock_aiohttp_session.get = AsyncMock(
        side_effect=[
            mock_html_resp,
            ConnectionError("connection reset"),
            ConnectionError("connection reset"),
        ]
    )
    with (
        patch(
            "guard_core.handlers.cloud_handler.asyncio.sleep", new_callable=AsyncMock
        ) as sleep_mock,
        patch(
            "guard_core.handlers.cloud_handler.time.monotonic",
            side_effect=[0.0, 0.0, 0.0, 0.5, 25.0],
        ),
    ):
        result = await fetch_azure_ip_ranges()
    assert result == set()
    assert mock_aiohttp_session.get.await_count == 2
    sleep_mock.assert_called_once_with(2.0)


async def test_fetch_azure_ip_ranges_sizes_timeout_from_remaining_budget(  # async-only
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_html_resp = _mock_aiohttp_response(
        text_data='<a href="https://download.microsoft.com/valid.json">'
    )
    mock_json_resp = _mock_aiohttp_response(
        json_data={"values": [_azure_cloud_tag(["10.0.0.0/8"])]}
    )
    mock_aiohttp_session.get = AsyncMock(
        side_effect=[
            mock_html_resp,
            ConnectionError("connection reset"),
            mock_json_resp,
        ]
    )
    with (
        patch(
            "guard_core.handlers.cloud_handler.asyncio.sleep", new_callable=AsyncMock
        ),
        patch(
            "guard_core.handlers.cloud_handler.time.monotonic",
            side_effect=[0.0, 0.0, 0.0, 15.0, 15.0],
        ),
        patch("aiohttp.ClientTimeout") as mock_client_timeout,
    ):
        result = await fetch_azure_ip_ranges()
    assert ipaddress.IPv4Network("10.0.0.0/8") in result
    second_attempt_timeout = mock_client_timeout.call_args_list[2]
    assert second_attempt_timeout.kwargs["total"] == 5.0


async def test_cloud_ip_redis_caching(
    security_config_redis_isolated_prefix: SecurityConfig,
) -> None:
    with (
        patch(
            "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
            new_callable=AsyncMock,
        ) as mock_aws,
        patch(
            "guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_azure_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_digitalocean_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_linode_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_vultr_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
    ):
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}

        redis_handler = RedisManager(security_config_redis_isolated_prefix)
        await redis_handler.initialize()

        await cloud_handler.initialize_redis(redis_handler)

        assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        import json as _json

        cached_raw = await redis_handler.get_key("cloud_ip_v2", "AWS")
        assert _json.loads(cached_raw) == ["192.168.0.0/24"]

        mock_aws.return_value = {ipaddress.IPv4Network("192.168.1.0/24")}
        await cloud_handler.refresh_async()

        await redis_handler.delete("cloud_ip_v2", "AWS")
        await cloud_handler.refresh_async()

        mock_aws.side_effect = Exception("API Error")
        await cloud_handler.refresh_async()
        assert cloud_handler.is_cloud_ip("192.168.1.1", {"AWS"})

        cloud_handler._store = None
        cloud_handler.redis_handler = None
        await cloud_handler.refresh_async()

        await redis_handler.close()


async def test_cloud_ip_redis_cache_hit(
    security_config_redis_isolated_prefix: SecurityConfig,
) -> None:
    import json as _json

    redis_handler = RedisManager(security_config_redis_isolated_prefix)
    await redis_handler.initialize()

    await redis_handler.set_key("cloud_ip_v2", "AWS", _json.dumps(["192.168.0.0/24"]))

    with patch(
        "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
        new_callable=AsyncMock,
    ) as mock_aws:
        await cloud_handler.initialize_redis(redis_handler, {"AWS"})

        assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        mock_aws.assert_not_called()

    await redis_handler.close()


async def test_cloud_ip_redis_sync_async(
    security_config_redis_isolated_prefix: SecurityConfig,
) -> None:
    with (
        patch(
            "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
            new_callable=AsyncMock,
        ) as mock_aws,
        patch(
            "guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("172.16.0.0/12")},
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_azure_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("10.0.0.0/8")},
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_digitalocean_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_linode_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_vultr_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
    ):
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}

        cloud_handler.redis_handler = None

        await cloud_handler.refresh()
        assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})

        redis_handler = RedisManager(security_config_redis_isolated_prefix)
        await redis_handler.initialize()
        await cloud_handler.initialize_redis(redis_handler)

        with pytest.raises(RuntimeError) as exc_info:
            await cloud_handler.refresh()
        assert "refresh_async()" in str(exc_info.value)

        await redis_handler.close()


async def test_cloud_ip_redis_error_handling(
    security_config_redis_isolated_prefix: SecurityConfig,
) -> None:
    with patch(
        "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
        new_callable=AsyncMock,
    ) as mock_aws:
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}

        redis_handler = RedisManager(security_config_redis_isolated_prefix)
        await redis_handler.initialize()

        await redis_handler.delete("cloud_ranges_v2", "AWS")
        await redis_handler.delete("cloud_ip_v2", "AWS")

        mock_aws.side_effect = Exception("API Error")
        await cloud_handler.initialize_redis(redis_handler, {"AWS"})

        cloud_handler.ip_ranges.pop("AWS", None)
        await cloud_handler.refresh_async({"AWS"})

        assert isinstance(cloud_handler.ip_ranges["AWS"], set)
        assert len(cloud_handler.ip_ranges["AWS"]) == 0

        await redis_handler.close()


async def test_fetch_digitalocean_ip_ranges_returns_networks_from_csv_feed(
    mock_aiohttp_session: MagicMock,
) -> None:
    csv_body = (
        "5.101.96.0/21,NL,NL-NH,Amsterdam,1098 XH\n"
        "24.144.64.0/22,US,US-NJ,North Bergen,07047\n"
        "2604:a880::/32,US,US-NJ,North Bergen,07047\n"
    )
    mock_resp = _mock_aiohttp_response(text_data=csv_body)
    mock_aiohttp_session.get = AsyncMock(return_value=mock_resp)

    result = await fetch_digitalocean_ip_ranges()
    assert ipaddress.IPv4Network("5.101.96.0/21") in result
    assert ipaddress.IPv4Network("24.144.64.0/22") in result
    assert ipaddress.IPv6Network("2604:a880::/32") in result
    assert len(result) == 3


async def test_fetch_digitalocean_ip_ranges_returns_empty_set_on_http_failure(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_aiohttp_session.get = AsyncMock(side_effect=Exception("API failure"))
    result = await fetch_digitalocean_ip_ranges()
    assert result == set()


async def test_fetch_digitalocean_ip_ranges_skips_blank_and_invalid_rows(
    mock_aiohttp_session: MagicMock,
) -> None:
    csv_body = (
        "5.101.96.0/21,NL,NL-NH,Amsterdam,1098 XH\n"
        "\n"
        ",placeholder,row,with,empty-prefix\n"
        "not-a-cidr,US,US-NJ,North Bergen,07047\n"
        "24.144.64.0/22,US,US-NJ,North Bergen,07047\n"
    )
    mock_resp = _mock_aiohttp_response(text_data=csv_body)
    mock_aiohttp_session.get = AsyncMock(return_value=mock_resp)

    result = await fetch_digitalocean_ip_ranges()
    assert ipaddress.IPv4Network("5.101.96.0/21") in result
    assert ipaddress.IPv4Network("24.144.64.0/22") in result
    assert len(result) == 2


async def test_fetch_linode_ip_ranges_returns_networks_from_csv_feed(
    mock_aiohttp_session: MagicMock,
) -> None:
    csv_body = (
        "# RFC8805 geofeed\n"
        "# ip_prefix, alpha2code, region, city, postal_code\n"
        "2600:3c00::/32,US,US-TX,Richardson,\n"
        "45.79.0.0/16,US,US-NJ,Cedar Knolls,\n"
        "172.232.0.0/16,US,US-CA,Fremont,\n"
    )
    mock_resp = _mock_aiohttp_response(text_data=csv_body)
    mock_aiohttp_session.get = AsyncMock(return_value=mock_resp)

    result = await fetch_linode_ip_ranges()
    assert ipaddress.IPv6Network("2600:3c00::/32") in result
    assert ipaddress.IPv4Network("45.79.0.0/16") in result
    assert ipaddress.IPv4Network("172.232.0.0/16") in result
    assert len(result) == 3


async def test_fetch_linode_ip_ranges_returns_empty_set_on_http_failure(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_aiohttp_session.get = AsyncMock(side_effect=Exception("API failure"))
    result = await fetch_linode_ip_ranges()
    assert result == set()


async def test_fetch_linode_ip_ranges_skips_comments_and_invalid_rows(
    mock_aiohttp_session: MagicMock,
) -> None:
    csv_body = (
        "# header line\n"
        "\n"
        ",empty,prefix,row,here\n"
        "garbage,,,,\n"
        "45.79.0.0/16,US,US-NJ,Cedar Knolls,\n"
    )
    mock_resp = _mock_aiohttp_response(text_data=csv_body)
    mock_aiohttp_session.get = AsyncMock(return_value=mock_resp)

    result = await fetch_linode_ip_ranges()
    assert ipaddress.IPv4Network("45.79.0.0/16") in result
    assert len(result) == 1


async def test_fetch_vultr_ip_ranges_returns_networks_from_json_feed(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_resp = _mock_aiohttp_response(
        json_data={
            "description": "Constant.com / Vultr.com GeoFeed",
            "asn": 20473,
            "subnets": [
                {
                    "ip_prefix": "45.32.0.0/21",
                    "alpha2code": "US",
                    "region": "US-NJ",
                    "city": "Piscataway",
                    "postal_code": "08854",
                },
                {
                    "ip_prefix": "2001:19f0::/29",
                    "alpha2code": "US",
                    "region": "US-NJ",
                    "city": "Piscataway",
                    "postal_code": "08854",
                },
            ],
        }
    )
    mock_aiohttp_session.get = AsyncMock(return_value=mock_resp)

    result = await fetch_vultr_ip_ranges()
    assert ipaddress.IPv4Network("45.32.0.0/21") in result
    assert ipaddress.IPv6Network("2001:19f0::/29") in result
    assert len(result) == 2


async def test_fetch_vultr_ip_ranges_returns_empty_set_on_http_failure(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_aiohttp_session.get = AsyncMock(side_effect=Exception("API failure"))
    result = await fetch_vultr_ip_ranges()
    assert result == set()


async def test_fetch_vultr_ip_ranges_skips_entries_without_prefix(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_resp = _mock_aiohttp_response(
        json_data={
            "subnets": [
                {"ip_prefix": "45.32.0.0/21"},
                {"alpha2code": "US"},
                {"ip_prefix": "not-a-cidr"},
            ]
        }
    )
    mock_aiohttp_session.get = AsyncMock(return_value=mock_resp)

    result = await fetch_vultr_ip_ranges()
    assert ipaddress.IPv4Network("45.32.0.0/21") in result
    assert len(result) == 1


async def test_new_providers_wired_into_refresh_pipeline() -> None:
    with (
        patch(
            "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_azure_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_digitalocean_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("5.101.96.0/21")},
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_linode_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("45.79.0.0/16")},
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_vultr_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("45.32.0.0/21")},
        ),
    ):
        cloud_handler.redis_handler = None
        await cloud_handler._refresh_providers()
        assert cloud_handler.is_cloud_ip("5.101.96.1", {"DigitalOcean"})
        assert cloud_handler.is_cloud_ip("45.79.0.1", {"Linode"})
        assert cloud_handler.is_cloud_ip("45.32.0.1", {"Vultr"})


async def test_new_providers_wired_into_refresh_async_store_path() -> None:
    from guard_core.handlers.cloud_ip_stores import InMemoryCloudIpStore

    cloud_handler.set_store(InMemoryCloudIpStore())
    cloud_handler.redis_handler = None
    cloud_handler.ip_ranges = {}

    with (
        patch(
            "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_azure_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_digitalocean_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("5.101.96.0/21")},
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_linode_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("45.79.0.0/16")},
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_vultr_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("45.32.0.0/21")},
        ),
    ):
        await cloud_handler.refresh_async({"DigitalOcean", "Linode", "Vultr"})
        assert cloud_handler.is_cloud_ip("5.101.96.1", {"DigitalOcean"})
        assert cloud_handler.is_cloud_ip("45.79.0.1", {"Linode"})
        assert cloud_handler.is_cloud_ip("45.32.0.1", {"Vultr"})


async def test_new_providers_wired_into_refresh_via_redis_handler(
    security_config_redis_isolated_prefix: SecurityConfig,
) -> None:
    redis_handler = RedisManager(security_config_redis_isolated_prefix)
    await redis_handler.initialize()
    await redis_handler.delete("cloud_ranges", "DigitalOcean")
    await redis_handler.delete("cloud_ranges", "Linode")
    await redis_handler.delete("cloud_ranges", "Vultr")

    cloud_handler.redis_handler = redis_handler
    cloud_handler._store = None
    cloud_handler.ip_ranges = {}

    with (
        patch(
            "guard_core.handlers.cloud_handler.fetch_digitalocean_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("5.101.96.0/21")},
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_linode_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("45.79.0.0/16")},
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_vultr_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("45.32.0.0/21")},
        ),
    ):
        await cloud_handler._refresh_providers_via_redis_handler(
            {"DigitalOcean", "Linode", "Vultr"}
        )
        assert cloud_handler.is_cloud_ip("5.101.96.1", {"DigitalOcean"})
        assert cloud_handler.is_cloud_ip("45.79.0.1", {"Linode"})
        assert cloud_handler.is_cloud_ip("45.32.0.1", {"Vultr"})

        await cloud_handler._refresh_providers_via_redis_handler({"DigitalOcean"})
        assert cloud_handler.is_cloud_ip("5.101.96.1", {"DigitalOcean"})

    await redis_handler.close()
    cloud_handler.redis_handler = None
    from guard_core.handlers.cloud_ip_stores import InMemoryCloudIpStore

    cloud_handler.set_store(InMemoryCloudIpStore())


async def test_refresh_via_redis_handler_falls_back_when_redis_missing() -> None:
    cloud_handler.redis_handler = None
    cloud_handler.ip_ranges = {}

    with (
        patch(
            "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
            new_callable=AsyncMock,
            return_value={ipaddress.IPv4Network("192.168.0.0/24")},
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_azure_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_digitalocean_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_linode_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_vultr_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
    ):
        await cloud_handler._refresh_providers_via_redis_handler({"AWS"})
        assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})


async def test_refresh_via_redis_handler_records_empty_on_fetch_error(
    security_config_redis_isolated_prefix: SecurityConfig,
) -> None:
    redis_handler = RedisManager(security_config_redis_isolated_prefix)
    await redis_handler.initialize()
    await redis_handler.delete("cloud_ranges", "AWS")

    cloud_handler.redis_handler = redis_handler
    cloud_handler._store = None
    cloud_handler.ip_ranges = {}

    with patch(
        "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
        new_callable=AsyncMock,
        side_effect=Exception("boom"),
    ):
        await cloud_handler._refresh_providers_via_redis_handler({"AWS"})

    assert cloud_handler.ip_ranges["AWS"] == set()

    await redis_handler.close()
    cloud_handler.redis_handler = None
    from guard_core.handlers.cloud_ip_stores import InMemoryCloudIpStore

    cloud_handler.set_store(InMemoryCloudIpStore())


def test_set_store_replaces_active_store() -> None:
    from guard_core.handlers.cloud_ip_stores import InMemoryCloudIpStore

    fresh_store = InMemoryCloudIpStore()
    cloud_handler.set_store(fresh_store)
    assert cloud_handler._store is fresh_store


def test_get_cloud_provider_details_returns_match_or_none() -> None:
    cloud_handler.ip_ranges = {
        "AWS": {ipaddress.IPv4Network("192.168.0.0/24")},
        "GCP": set(),
    }
    match = cloud_handler.get_cloud_provider_details("192.168.0.5", {"AWS", "GCP"})
    assert match == ("AWS", "192.168.0.0/24")
    assert cloud_handler.get_cloud_provider_details("8.8.8.8", {"AWS", "GCP"}) is None
    assert cloud_handler.get_cloud_provider_details("not-an-ip", {"AWS"}) is None


async def test_send_cloud_detection_event_no_op_without_agent() -> None:
    cloud_handler.agent_handler = None
    await cloud_handler.send_cloud_detection_event("1.2.3.4", "AWS", "192.168.0.0/24")


async def test_send_cloud_detection_event_dispatches_when_agent_present() -> None:
    agent = MagicMock()
    agent.send_event = AsyncMock()
    cloud_handler.agent_handler = agent
    try:
        await cloud_handler.send_cloud_detection_event(
            "1.2.3.4", "AWS", "192.168.0.0/24"
        )
        agent.send_event.assert_awaited()
    finally:
        cloud_handler.agent_handler = None


async def test_send_cloud_event_logs_when_agent_dispatch_raises() -> None:
    agent = MagicMock()
    agent.send_event = AsyncMock(side_effect=RuntimeError("agent down"))
    cloud_handler.agent_handler = agent
    try:
        await cloud_handler._send_cloud_event(
            event_type="cloud_blocked",
            ip_address="1.2.3.4",
            action_taken="blocked",
            reason="test",
        )
    finally:
        cloud_handler.agent_handler = None


async def test_fetch_gcp_ip_ranges_skips_unknown_prefix_keys(
    mock_aiohttp_session: MagicMock,
) -> None:
    mock_resp = _mock_aiohttp_response(
        json_data={
            "prefixes": [
                {"ipv4Prefix": "172.16.0.0/12"},
                {"someOtherKey": "ignored"},
            ]
        }
    )
    mock_aiohttp_session.get = AsyncMock(return_value=mock_resp)
    networks, _ = await fetch_gcp_ip_ranges()
    assert ipaddress.IPv4Network("172.16.0.0/12") in networks
    assert len(networks) == 1


async def test_initialize_redis_replaces_in_memory_store(
    security_config_redis_isolated_prefix: SecurityConfig,
) -> None:
    from guard_core.handlers.cloud_ip_stores import (
        InMemoryCloudIpStore,
        RedisCloudIpStore,
    )

    cloud_handler.set_store(InMemoryCloudIpStore())
    cloud_handler.redis_handler = None
    cloud_handler.ip_ranges = {}

    redis_handler = RedisManager(security_config_redis_isolated_prefix)
    await redis_handler.initialize()

    with (
        patch(
            "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_azure_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_digitalocean_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_linode_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_vultr_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
    ):
        await cloud_handler.initialize_redis(redis_handler)

    assert isinstance(cloud_handler._store, RedisCloudIpStore)

    await redis_handler.close()
    cloud_handler.redis_handler = None
    cloud_handler.set_store(InMemoryCloudIpStore())


async def test_initialize_agent_records_handler() -> None:
    agent = MagicMock()
    await cloud_handler.initialize_agent(agent)
    assert cloud_handler.agent_handler is agent
    cloud_handler.agent_handler = None


async def test_initialize_redis_keeps_existing_redis_store(
    security_config_redis_isolated_prefix: SecurityConfig,
) -> None:
    from guard_core.handlers.cloud_ip_stores import (
        InMemoryCloudIpStore,
        RedisCloudIpStore,
    )

    redis_handler = RedisManager(security_config_redis_isolated_prefix)
    await redis_handler.initialize()

    cloud_handler.set_store(RedisCloudIpStore(redis_handler))
    cloud_handler.redis_handler = None
    cloud_handler.ip_ranges = {}

    with (
        patch(
            "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_azure_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_digitalocean_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_linode_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            "guard_core.handlers.cloud_handler.fetch_vultr_ip_ranges",
            new_callable=AsyncMock,
            return_value=set(),
        ),
    ):
        original_store = cloud_handler._store
        await cloud_handler.initialize_redis(redis_handler)
        assert cloud_handler._store is original_store

    await redis_handler.close()
    cloud_handler.redis_handler = None
    cloud_handler.set_store(InMemoryCloudIpStore())


async def test_refresh_via_redis_handler_handles_empty_fetch(
    security_config_redis_isolated_prefix: SecurityConfig,
) -> None:
    redis_handler = RedisManager(security_config_redis_isolated_prefix)
    await redis_handler.initialize()
    await redis_handler.delete("cloud_ranges", "AWS")

    cloud_handler.redis_handler = redis_handler
    cloud_handler._store = None

    with patch(
        "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
        new_callable=AsyncMock,
        return_value=set(),
    ):
        await cloud_handler._refresh_providers_via_redis_handler({"AWS"})

    await redis_handler.close()
    cloud_handler.redis_handler = None
    from guard_core.handlers.cloud_ip_stores import InMemoryCloudIpStore

    cloud_handler.set_store(InMemoryCloudIpStore())


def test_get_cloud_provider_details_skips_unknown_provider() -> None:
    cloud_handler.ip_ranges = {"AWS": {ipaddress.IPv4Network("192.168.0.0/24")}}
    assert cloud_handler.get_cloud_provider_details("8.8.8.8", {"Bogus"}) is None


async def test_send_cloud_event_returns_when_agent_handler_missing() -> None:
    cloud_handler.agent_handler = None
    await cloud_handler._send_cloud_event(
        event_type="cloud_blocked",
        ip_address="1.2.3.4",
        action_taken="blocked",
        reason="test",
    )


def test_cloud_manager_returns_existing_singleton() -> None:
    from guard_core.handlers.cloud_handler import CloudManager

    first = CloudManager()
    second = CloudManager()
    assert first is second


async def test_refresh_via_redis_handler_keeps_existing_provider_state(
    security_config_redis_isolated_prefix: SecurityConfig,
) -> None:
    redis_handler = RedisManager(security_config_redis_isolated_prefix)
    await redis_handler.initialize()
    await redis_handler.delete("cloud_ranges", "AWS")

    cloud_handler.redis_handler = redis_handler
    cloud_handler._store = None
    cloud_handler.ip_ranges = {"AWS": {ipaddress.IPv4Network("192.168.0.0/24")}}

    with patch(
        "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
        new_callable=AsyncMock,
        side_effect=Exception("fetch failure"),
    ):
        await cloud_handler._refresh_providers_via_redis_handler({"AWS"})

    assert cloud_handler.ip_ranges["AWS"] == {ipaddress.IPv4Network("192.168.0.0/24")}

    await redis_handler.close()
    cloud_handler.redis_handler = None
    from guard_core.handlers.cloud_ip_stores import InMemoryCloudIpStore

    cloud_handler.set_store(InMemoryCloudIpStore())


def test_is_cloud_ip_warns_on_empty_ranges_without_changing_return_value(
    caplog: pytest.LogCaptureFixture,
) -> None:
    cloud_handler.ip_ranges["AWS"] = set()
    cloud_handler._empty_ranges_warned_at.clear()

    with caplog.at_level("WARNING", logger="guard_core.handlers.cloud"):
        result = cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})

    assert result is False
    warnings_logged = [
        record
        for record in caplog.records
        if record.levelname == "WARNING" and "not populated yet" in record.getMessage()
    ]
    assert len(warnings_logged) == 1
    assert "AWS" in warnings_logged[0].getMessage()


def test_is_cloud_ip_empty_ranges_warning_is_throttled(
    caplog: pytest.LogCaptureFixture,
) -> None:
    cloud_handler.ip_ranges["AWS"] = set()
    cloud_handler._empty_ranges_warned_at.clear()

    with (
        patch("time.monotonic", return_value=1000.0),
        caplog.at_level("WARNING", logger="guard_core.handlers.cloud"),
    ):
        for _ in range(5):
            cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})

    warnings_logged = [
        record
        for record in caplog.records
        if record.levelname == "WARNING" and "not populated yet" in record.getMessage()
    ]
    assert len(warnings_logged) == 1


def test_is_cloud_ip_empty_ranges_warning_repeats_after_cooldown_elapses(
    caplog: pytest.LogCaptureFixture,
) -> None:
    cloud_handler.ip_ranges["AWS"] = set()
    cloud_handler._empty_ranges_warned_at.clear()

    clock = {"now": 2000.0}
    with (
        patch("time.monotonic", side_effect=lambda: clock["now"]),
        caplog.at_level("WARNING", logger="guard_core.handlers.cloud"),
    ):
        cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})

        clock["now"] += 10.0
        cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})

        clock["now"] += cloud_handler._EMPTY_RANGES_WARNING_COOLDOWN
        cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})

    warnings_logged = [
        record
        for record in caplog.records
        if record.levelname == "WARNING" and "not populated yet" in record.getMessage()
    ]
    assert len(warnings_logged) == 2


def test_get_status_reports_not_ready_before_refresh_and_ready_after() -> None:
    cloud_handler.ip_ranges["AWS"] = set()
    cloud_handler.last_updated["AWS"] = None

    status_before = cloud_handler.get_status()
    assert status_before["AWS"] == {
        "ready": False,
        "last_refreshed": None,
        "entries": 0,
    }

    now = datetime.now(timezone.utc)
    cloud_handler.ip_ranges["AWS"] = {ipaddress.IPv4Network("192.168.0.0/24")}
    cloud_handler.last_updated["AWS"] = now

    status_after = cloud_handler.get_status()
    assert status_after["AWS"] == {
        "ready": True,
        "last_refreshed": now,
        "entries": 1,
    }


def test_is_cloud_ip_regression_returns_false_not_true_with_empty_ranges() -> None:
    cloud_handler.ip_ranges = {provider: set() for provider in cloud_handler.ip_ranges}
    result = cloud_handler.is_cloud_ip("8.8.8.8", {"AWS", "GCP", "Azure"})
    assert result is False
