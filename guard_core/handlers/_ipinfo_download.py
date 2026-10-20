import aiohttp


class IpInfoDownloadMixin:
    _download_url: str
    _download_connect_timeout: float
    _download_read_timeout: float
    _download_total_timeout: float

    async def _download_body(
        self, session: aiohttp.ClientSession, headers: dict[str, str]
    ) -> bytes:
        timeout = aiohttp.ClientTimeout(
            sock_connect=self._download_connect_timeout,
            sock_read=self._download_read_timeout,
            total=self._download_total_timeout,
        )
        response = await session.get(
            self._download_url, headers=headers, timeout=timeout
        )
        response.raise_for_status()
        return await response.read()
