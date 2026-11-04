import asyncio
import logging
import threading
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

from guard_core.exceptions import GeoDatabaseLoadError


class IpInfoBackgroundMixin:
    db_path: Path
    reader: object | None
    logger: logging.Logger
    _max_age: int
    _RETRY_BACKOFF_SECONDS: float
    _last_attempt_at: float | None
    _background_in_flight: bool
    _background_task: asyncio.Task[None] | None
    _refresh_due: bool
    _staleness_timer: threading.Timer | None

    async def initialize(self) -> None: ...

    async def refresh(self) -> None: ...

    async def _initialize_database(self) -> None: ...

    async def _refresh_database(self) -> None: ...

    def _is_backing_off(self) -> bool:
        return (
            self._last_attempt_at is not None
            and time.monotonic() - self._last_attempt_at < self._RETRY_BACKOFF_SECONDS
        )

    _load_loop: asyncio.AbstractEventLoop | None = None

    def _start_or_join_load(
        self, work: Callable[[], Awaitable[None]]
    ) -> asyncio.Task[None]:
        loop = asyncio.get_running_loop()
        task = self._background_task
        if task is not None and not task.done() and self._load_loop is loop:
            return task
        self._load_loop = loop
        self._background_in_flight = True
        self._background_task = asyncio.create_task(self._load_in_background(work))
        return self._background_task

    async def _stop_background_load(self) -> None:
        task = self._background_task
        if (
            task is None
            or task.done()
            or self._load_loop is not asyncio.get_running_loop()
        ):
            return
        self._load_stopped_by_close = task
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    _load_stopped_by_close: "asyncio.Task[None] | None" = None

    async def _wait_for_load(self, load: "asyncio.Task[None]") -> None:
        try:
            await asyncio.shield(load)
        except asyncio.CancelledError:
            # shield cancels its outer future with the inner task; a
            # waiter whose own task is not being cancelled sees a failed load.
            if load is not self._load_stopped_by_close or not load.cancelled():
                raise
            self._last_load_error = "GeoIP load stopped because Redis closed"

    _last_load_error: str | None = None

    async def ensure_database_loaded(self) -> None:
        if self.reader is not None:
            return
        if not self._is_backing_off():
            await self._wait_for_load(
                self._start_or_join_load(self._initialize_database)
            )
        self._raise_last_load_error()

    def _raise_last_load_error(self) -> None:
        failure = self._last_load_error
        if failure is not None:
            raise GeoDatabaseLoadError(failure)

    def schedule_database_load(self) -> None:
        if self._is_backing_off():
            return
        work = (
            self._initialize_database if self.reader is None else self._refresh_database
        )
        try:
            self._start_or_join_load(work)
        except RuntimeError:
            self.logger.exception("Could not schedule the GeoIP database load")
            self._background_in_flight = False

    async def _load_in_background(self, work: Callable[[], Awaitable[None]]) -> None:
        # The outcome is written when the attempt ends, so a request that reads it
        # while a retry is in flight still sees the previous failure; only the text
        # is kept, since the exception's frames hold the failed load's buffers.
        try:
            await work()
        except Exception as failure:
            self.logger.exception("Background GeoIP database load failed")
            self._last_load_error = f"{type(failure).__name__}: {failure}"
        else:
            self._last_load_error = None
        finally:
            self._background_in_flight = False
        self._back_off_unless_loaded()

    def _back_off_unless_loaded(self) -> None:
        if self.reader is None or self._refresh_due:
            self._last_attempt_at = time.monotonic()

    def _mark_refresh_due(self) -> None:
        self._refresh_due = True

    def _cancel_staleness_timer(self) -> None:
        if self._staleness_timer is not None:
            self._staleness_timer.cancel()
            self._staleness_timer = None

    def _arm_staleness_timer(self) -> None:
        self._cancel_staleness_timer()
        try:
            age = time.time() - self.db_path.stat().st_mtime
        except OSError:
            return
        timer = threading.Timer(max(self._max_age - age, 1.0), self._mark_refresh_due)
        timer.daemon = True
        timer.start()
        self._staleness_timer = timer
