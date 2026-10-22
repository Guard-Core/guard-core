import logging
from collections.abc import Callable
from datetime import datetime, timezone, tzinfo
from zoneinfo import ZoneInfo


def time_window_allows(
    time_restrictions: dict[str, str],
    logger: logging.Logger,
    now: Callable[[tzinfo], datetime],
) -> bool:
    try:
        start_time = time_restrictions["start"]
        end_time = time_restrictions["end"]

        timezone_str = time_restrictions.get("timezone", "UTC")
        try:
            tz: ZoneInfo | timezone = ZoneInfo(timezone_str)
        except (KeyError, Exception):
            tz = timezone.utc
        current_time = now(tz)
        current_hour_minute = current_time.strftime("%H:%M")

        if start_time > end_time:
            return current_hour_minute >= start_time or current_hour_minute <= end_time
        else:
            return start_time <= current_hour_minute <= end_time

    except Exception as e:
        logger.error(f"Error checking time window: {e!s}")
        return True
