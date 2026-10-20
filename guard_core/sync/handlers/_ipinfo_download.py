import time

import requests
from urllib3.response import HTTPResponse


class IpInfoDownloadMixin:
    _download_url: str
    _download_connect_timeout: float
    _download_read_timeout: float
    _download_total_timeout: float

    def _download_body(
        self, session: requests.Session, headers: dict[str, str]
    ) -> bytes:
        deadline = time.monotonic() + self._download_total_timeout
        timeout = (self._download_connect_timeout, self._download_read_timeout)
        with session.get(
            self._download_url, headers=headers, timeout=timeout, stream=True
        ) as response:
            response.raise_for_status()
            raw: HTTPResponse = response.raw
            chunks: list[bytes] = []
            while (left := deadline - time.monotonic()) > 0:
                connection = raw.connection
                if connection is not None and connection.sock is not None:
                    connection.sock.settimeout(min(self._download_read_timeout, left))
                if not (chunk := raw.read1(65536, decode_content=True)):
                    return b"".join(chunks)
                chunks.append(chunk)
        raise TimeoutError("GeoIP download exceeded the total time bound")
