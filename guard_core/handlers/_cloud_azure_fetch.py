import asyncio
import html
import ipaddress
import logging
import re
import time
from datetime import date, datetime, timezone
from typing import TypedDict
from urllib.parse import urlparse

logger = logging.getLogger("guard_core.handlers.cloud")

_AZURE_DOWNLOAD_MAX_ATTEMPTS = 3
_AZURE_DOWNLOAD_RETRY_DELAY_SECONDS = 2.0
_AZURE_DOWNLOAD_MAX_ELAPSED_SECONDS = 20.0
_AZURE_DOWNLOAD_ATTEMPT_TIMEOUT_SECONDS = 10.0
_AZURE_PAGE_FETCH_TIMEOUT_SECONDS = 10.0

_AZURE_TRUSTED_DOWNLOAD_HOST = "download.microsoft.com"
_AZURE_SERVICE_TAGS_URL_PATTERN = (
    r'https://download\.microsoft\.com/[^"\'\s<>]+ServiceTags'
    r'[^"\'\s<>]*\.json(?:\?[^"\'\s<>]*)?'
)
_AZURE_SERVICE_TAGS_DATE_PATTERN = re.compile(r"ServiceTags_Public_(\d{8})")
_AZURE_SERVICE_TAGS_STALE_WARNING_DAYS = 90
_AZURE_CLOUD_SERVICE_TAG_NAME = "AzureCloud"


class _ServiceTagProperties(TypedDict, total=False):
    addressPrefixes: list[str]


class _ServiceTag(TypedDict, total=False):
    name: str
    properties: _ServiceTagProperties


class _ServiceTagsDocument(TypedDict, total=False):
    values: list[_ServiceTag]


async def _download_azure_service_tags(
    download_url: str, deadline: float | None = None
) -> _ServiceTagsDocument:
    import aiohttp

    if deadline is None:
        deadline = time.monotonic() + _AZURE_DOWNLOAD_MAX_ELAPSED_SECONDS
    attempt = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Azure IP ranges download exceeded max elapsed time")
        attempt += 1
        attempt_timeout = min(_AZURE_DOWNLOAD_ATTEMPT_TIMEOUT_SECONDS, remaining)
        async with aiohttp.ClientSession() as session:
            try:
                response = await session.get(
                    download_url,
                    timeout=aiohttp.ClientTimeout(total=attempt_timeout),
                    allow_redirects=False,
                )
            except Exception:
                remaining = deadline - time.monotonic()
                if attempt >= _AZURE_DOWNLOAD_MAX_ATTEMPTS or remaining <= 0:
                    raise
                await asyncio.sleep(min(_AZURE_DOWNLOAD_RETRY_DELAY_SECONDS, remaining))
                continue
            if 300 <= response.status < 400:
                raise ValueError(
                    "Azure IP ranges download redirected "
                    f"(status {response.status}); refusing to follow redirects"
                )
            response.raise_for_status()
            document: _ServiceTagsDocument = await response.json(content_type=None)
            return document


def _is_trusted_azure_download_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and parsed.hostname == _AZURE_TRUSTED_DOWNLOAD_HOST


def _parse_service_tags_date(url: str) -> date | None:
    date_match = _AZURE_SERVICE_TAGS_DATE_PATTERN.search(url)
    if not date_match:
        return None
    try:
        parsed_date = datetime.strptime(date_match.group(1), "%Y%m%d").date()
    except ValueError:
        return None
    if parsed_date > datetime.now(timezone.utc).date():
        return None
    return parsed_date


def _service_tags_sort_key(url: str) -> tuple[bool, date, str]:
    parsed_date = _parse_service_tags_date(url)
    return (parsed_date is not None, parsed_date or date.min, url)


def _warn_if_service_tags_url_is_stale(url: str) -> None:
    parsed_date = _parse_service_tags_date(url)
    if parsed_date is None:
        logger.warning(
            "Selected Azure ServiceTags URL has no parseable date, cannot confirm "
            "it is current: %s",
            url,
        )
        return
    age_days = (datetime.now(timezone.utc).date() - parsed_date).days
    if age_days > _AZURE_SERVICE_TAGS_STALE_WARNING_DAYS:
        logger.warning(
            "Selected Azure ServiceTags URL is %d days old, possibly stale: %s",
            age_days,
            url,
        )


def _extract_failover_link_url(decoded_html: str) -> str | None:
    anchor_match = re.search(
        r'<a\b[^>]*\bid=["\']failoverLink["\'][^>]*>', decoded_html
    )
    if not anchor_match:
        return None
    href_match = re.search(r'href=["\']([^"\']+)["\']', anchor_match.group(0))
    if not href_match:
        return None
    url = href_match.group(1)
    return url if _is_trusted_azure_download_url(url) else None


def _extract_newest_service_tags_url(decoded_html: str) -> str | None:
    candidates: list[str] = [
        url
        for url in re.findall(_AZURE_SERVICE_TAGS_URL_PATTERN, decoded_html)
        if _is_trusted_azure_download_url(url)
    ]
    if not candidates:
        return None
    winner = max(candidates, key=_service_tags_sort_key)
    _warn_if_service_tags_url_is_stale(winner)
    return winner


def _extract_generic_json_url(decoded_html: str) -> str | None:
    match = re.search(
        r'href=["\'](https://download\.microsoft\.com/[^"\']+\.json(?:\?[^"\']*)?)["\']',
        decoded_html,
    )
    if not match:
        return None
    url = match.group(1)
    return url if _is_trusted_azure_download_url(url) else None


def _extract_azure_download_url(decoded_html: str) -> str | None:
    return (
        _extract_failover_link_url(decoded_html)
        or _extract_newest_service_tags_url(decoded_html)
        or _extract_generic_json_url(decoded_html)
    )


def _select_azure_cloud_prefixes(data: _ServiceTagsDocument) -> list[str]:
    for entry in data.get("values", []):
        if entry.get("name") == _AZURE_CLOUD_SERVICE_TAG_NAME:
            return list(entry.get("properties", {}).get("addressPrefixes", []))
    logger.error(
        f"Azure ServiceTags document has no {_AZURE_CLOUD_SERVICE_TAG_NAME!r} tag"
    )
    return []


async def fetch_azure_ip_ranges() -> set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    import aiohttp

    try:
        deadline = time.monotonic() + _AZURE_DOWNLOAD_MAX_ELAPSED_SECONDS
        page_timeout = min(
            _AZURE_PAGE_FETCH_TIMEOUT_SECONDS, deadline - time.monotonic()
        )
        if page_timeout <= 0:
            raise TimeoutError("Azure IP ranges download exceeded max elapsed time")

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/91.0.4472.124 Safari/537.36"
        }
        route = "/download/details.aspx?id=56519"
        async with aiohttp.ClientSession() as session:
            response = await session.get(
                f"https://www.microsoft.com/en-us{route}",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=page_timeout),
            )
            response.raise_for_status()
            page_text = await response.text()

        decoded_html = html.unescape(page_text)
        download_url = _extract_azure_download_url(decoded_html)
        if not download_url:
            raise ValueError("Could not find Azure IP ranges download URL")

        data = await _download_azure_service_tags(download_url, deadline)

        return {
            ipaddress.ip_network(ip_range)
            for ip_range in _select_azure_cloud_prefixes(data)
        }
    except Exception as e:
        logger.error(f"Failed to fetch Azure IP ranges: {str(e)}")
        return set()
