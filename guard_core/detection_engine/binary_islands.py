import re

from guard_core.detection_engine.binary_prefix import _BINARY_ARTIFACT_RE

_ISLAND_CHARS = (
    "\t\n\r\x20-\x7e\u00a1-\ud7ff\ue000-\ufffc\ufffe-\uffff\U00010000-\U0010ffff"
)
_ISLAND_RUN_RE = re.compile(f"[{_ISLAND_CHARS}]+")
_NON_ISLAND_CHAR_RE = re.compile(f"[^{_ISLAND_CHARS}]")
_ISLAND_WINDOW = 32768

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
        barrier = _NON_ISLAND_CHAR_RE.search(content, start + _ISLAND_WINDOW)
        stop = len(content) if barrier is None else barrier.start()
        islands.extend(
            run
            for run in _ISLAND_RUN_RE.findall(content, start, stop)
            if len(run) >= min_run_length
        )
        start = stop
    return islands
