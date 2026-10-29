import re
from functools import cache

from guard_core.sync.detection_engine.binary_prefix import _BINARY_ARTIFACT_RE

_ISLAND_CHARS = (
    "\t\n\r\x20-\x7e\u00a1-\ud7ff\ue000-\ufffc\ufffe-\uffff\U00010000-\U0010ffff"
)
_ISLAND_WINDOW = 32768


@cache
def _island_run_re() -> re.Pattern[str]:
    return re.compile(f"[{_ISLAND_CHARS}]+")


@cache
def _non_island_char_re() -> re.Pattern[str]:
    return re.compile(f"[^{_ISLAND_CHARS}]")


def __getattr__(name: str) -> re.Pattern[str]:
    # The two character-class patterns compile on first use, not at import.
    if name == "_ISLAND_RUN_RE":
        return _island_run_re()
    if name == "_NON_ISLAND_CHAR_RE":
        return _non_island_char_re()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


_BINARY_LIKE_ARTIFACT_RATIO = 0.2


def value_is_binary_like(content: str) -> bool:
    if not content:
        return False
    artifact_count = sum(1 for _ in _BINARY_ARTIFACT_RE.finditer(content))
    return artifact_count / len(content) >= _BINARY_LIKE_ARTIFACT_RATIO


def extract_binary_islands(content: str, min_run_length: int) -> list[str]:
    if min_run_length <= 1:
        return [content]
    islands: list[str] = []
    start = 0
    while start < len(content):
        barrier = _non_island_char_re().search(content, start + _ISLAND_WINDOW)
        stop = len(content) if barrier is None else barrier.start()
        islands.extend(
            run
            for run in _island_run_re().findall(content, start, stop)
            if len(run) >= min_run_length
        )
        start = stop
    return islands
