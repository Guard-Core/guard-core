import threading
import time
import logging
import threading
import time
from collections.abc import Callable
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
    _background_task: threading.Thread | None
    _refresh_due: bool
    _staleness_timer: threading.Timer | None

    def initialize(self) -> None: ...

    def refresh(self) -> None: ...

    def _initialize_database(self) -> None: ...

    def _refresh_database(self) -> None: ...

    def _is_backing_off(self) -> bool:
        return (
            self._last_attempt_at is not None
            and time.monotonic() - self._last_attempt_at < self._RETRY_BACKOFF_SECONDS
        )

    _load_lock = threading.Lock()

    def _start_or_join_load(self, work: Callable[[], None]) -> threading.Thread:
        with self._load_lock:
            running = self._background_task
            if running is not None and running.is_alive():
                return running
            self._background_in_flight = True
            self._background_task = threading.Thread(
                target=self._load_in_background, args=(work,), daemon=True
            )
            self._background_task.start()
            return self._background_task

    _last_load_error: str | None = None

    def ensure_database_loaded(self) -> None:
        if self.reader is not None:
            return
        if not self._is_backing_off():
            self._start_or_join_load(self._initialize_database).join()
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

    def _load_in_background(self, work: Callable[[], None]) -> None:
        # The outcome is written when the attempt ends, so a request that reads it
        # while a retry is in flight still sees the previous failure; only the text
        # is kept, since the exception's frames hold the failed load's buffers.
        try:
            work()
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
