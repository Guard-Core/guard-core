import time

import requests
from urllib3.response import HTTPResponse

from guard_core.sync.handlers._ipinfo_download_cut import (
    DownloadCut,
    RecordingAdapter,
)

_TOTAL_BOUND_EXCEEDED = "GeoIP download exceeded the total time bound"


class IpInfoDownloadMixin:
    _download_url: str
    _download_connect_timeout: float
    _download_read_timeout: float
    _download_total_timeout: float

    def _download_body(
        self, session: requests.Session, headers: dict[str, str]
    ) -> bytes:
        cut = DownloadCut(self._download_total_timeout)
        adapter = RecordingAdapter(cut)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        deadline = time.monotonic() + self._download_total_timeout
        cut.arm()
        try:
            content = self._read_body(session, headers, deadline)
        except Exception as error:
            if cut.stop():
                raise TimeoutError(_TOTAL_BOUND_EXCEEDED) from error
            raise
        if cut.stop():
            raise TimeoutError(_TOTAL_BOUND_EXCEEDED)
        return content

    def _read_body(
        self,
        session: requests.Session,
        headers: dict[str, str],
        deadline: float,
    ) -> bytes:
        timeout = (
            self._download_connect_timeout,
            self._download_read_timeout,
        )
        with session.get(
            self._download_url, headers=headers, timeout=timeout, stream=True
        ) as response:
            response.raise_for_status()
            raw: HTTPResponse = response.raw
            chunks: list[bytes] = []
            while time.monotonic() < deadline:
                if not (chunk := raw.read1(65536, decode_content=True)):
                    return b"".join(chunks)
                chunks.append(chunk)
        raise TimeoutError(_TOTAL_BOUND_EXCEEDED)
