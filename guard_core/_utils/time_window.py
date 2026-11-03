import logging
import re
from collections.abc import Callable
from datetime import datetime, tzinfo
from zoneinfo import ZoneInfo

_TIME_OF_DAY = re.compile(r"(\d{1,2}):(\d{1,2})")


def minutes_of_day(value: str) -> int:
    """Minutes since midnight of an ``H:MM``/``HH:MM`` time; ``ValueError`` when
    the text is not a time of day (the decoration-time check and the request-time
    comparison share this one reading, so '9:00' and '09:00' are the same bound)."""
    found = _TIME_OF_DAY.fullmatch(value)
    hours, minutes = map(int, found.groups()) if found else (24, 60)
    if hours > 23 or minutes > 59:
        raise ValueError(f"{value!r} is not a valid HH:MM time")
    return hours * 60 + minutes


def time_window_allows(
    time_restrictions: dict[str, str],
    logger: logging.Logger,
    now: Callable[[tzinfo], datetime],
) -> bool:
    try:
        start_minute = minutes_of_day(time_restrictions["start"])
        end_minute = minutes_of_day(time_restrictions["end"])

        timezone_str = time_restrictions.get("timezone", "UTC")
        current_time = now(ZoneInfo(timezone_str))
        current_minute = current_time.hour * 60 + current_time.minute

        if start_minute > end_minute:
            return current_minute >= start_minute or current_minute <= end_minute
        else:
            return start_minute <= current_minute <= end_minute

    except Exception as e:
        detail = (
            f"{type(e).__name__}, request denied, restriction={time_restrictions!r}"
        )
        logger.error(f"Error checking time window: {detail}")
        return False
