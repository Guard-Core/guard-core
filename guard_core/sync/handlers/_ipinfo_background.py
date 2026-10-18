import logging
import threading
import time
from pathlib import Path


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

    def _is_backing_off(self) -> bool:
        return (
            self._last_attempt_at is not None
            and time.monotonic() - self._last_attempt_at < self._RETRY_BACKOFF_SECONDS
        )

    def schedule_database_load(self) -> None:
        if self._background_in_flight or self._is_backing_off():
            return
        self._background_in_flight = True
        load = self._load_in_background
        try:
            self._background_task = threading.Thread(target=load, daemon=True)

            self._background_task.start()
        except RuntimeError:
            self.logger.exception("Could not schedule the GeoIP database load")
            self._background_in_flight = False

    def _load_in_background(self) -> None:
        try:
            if self.reader is None:
                self.initialize()
            else:
                self.refresh()
        except Exception:
            self.logger.exception("Background GeoIP database load failed")
        finally:
            self._background_in_flight = False

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
