from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, BinaryIO

from guard_core.sync.handlers._ipinfo_download_cap import (
    reject_declared_size,
    reject_received_size,
)

if TYPE_CHECKING:
    import requests
    from urllib3.response import HTTPResponse

_TOTAL_BOUND_EXCEEDED = "GeoIP download exceeded the total time bound"


class IpInfoDownloadMixin:
    _download_url: str
    _download_connect_timeout: float
    _download_read_timeout: float
    _download_total_timeout: float
    _download_max_bytes: int
    logger: logging.Logger

    def _download_body(
        self,
        session: requests.Session,
        headers: dict[str, str],
        sink: BinaryIO,
    ) -> None:
        from guard_core.sync.handlers._ipinfo_download_cut import (
            DownloadCut,
            RecordingAdapter,
        )

        cut = DownloadCut(self._download_total_timeout)
        adapter = RecordingAdapter(cut)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        deadline = time.monotonic() + self._download_total_timeout
        cut.arm()
        try:
            self._read_body(session, headers, deadline, sink)
        except Exception as error:
            if cut.stop() or time.monotonic() >= deadline:
                raise TimeoutError(_TOTAL_BOUND_EXCEEDED) from error
            raise
        if cut.stop():
            raise TimeoutError(_TOTAL_BOUND_EXCEEDED)

    def _read_body(
        self,
        session: requests.Session,
        headers: dict[str, str],
        deadline: float,
        sink: BinaryIO,
    ) -> None:
        timeout = (
            self._download_connect_timeout,
            self._download_read_timeout,
        )
        with session.get(
            self._download_url, headers=headers, timeout=timeout, stream=True
        ) as response:
            response.raise_for_status()
            cap = self._download_max_bytes
            declared = response.headers.get("Content-Length", "")
            reject_declared_size(
                int(declared) if declared.isdigit() else None, cap, self.logger
            )
            raw: HTTPResponse = response.raw
            received = 0
            while time.monotonic() < deadline:
                if not (chunk := raw.read1(65536, decode_content=True)):
                    return
                received += len(chunk)
                reject_received_size(received, cap, self.logger)
                sink.write(chunk)
        raise TimeoutError(_TOTAL_BOUND_EXCEEDED)
