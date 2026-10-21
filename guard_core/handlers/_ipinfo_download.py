import logging
from typing import BinaryIO

import aiohttp

from guard_core.handlers._ipinfo_download_cap import (
    reject_declared_size,
    reject_received_size,
)


class IpInfoDownloadMixin:
    _download_url: str
    _download_connect_timeout: float
    _download_read_timeout: float
    _download_total_timeout: float
    _download_max_bytes: int
    logger: logging.Logger

    async def _download_body(
        self,
        session: aiohttp.ClientSession,
        headers: dict[str, str],
        sink: BinaryIO,
    ) -> None:
        timeout = aiohttp.ClientTimeout(
            sock_connect=self._download_connect_timeout,
            sock_read=self._download_read_timeout,
            total=self._download_total_timeout,
        )
        response = await session.get(
            self._download_url, headers=headers, timeout=timeout
        )
        try:
            response.raise_for_status()
            cap = self._download_max_bytes
            reject_declared_size(response.content_length, cap, self.logger)
            received = 0
            async for chunk in response.content.iter_chunked(65536):
                received += len(chunk)
                reject_received_size(received, cap, self.logger)
                sink.write(chunk)
        finally:
            response.close()
