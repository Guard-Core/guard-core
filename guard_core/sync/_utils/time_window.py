import logging
from collections.abc import Callable
from datetime import datetime, tzinfo
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
        current_time = now(ZoneInfo(timezone_str))
        current_hour_minute = current_time.strftime("%H:%M")

        if start_time > end_time:
            return current_hour_minute >= start_time or current_hour_minute <= end_time
        else:
            return start_time <= current_hour_minute <= end_time

    except Exception as e:
        detail = (
            f"{type(e).__name__}, request denied, restriction={time_restrictions!r}"
        )
        logger.error(f"Error checking time window: {detail}")
        return False
