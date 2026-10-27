import re

from guard_core.detection_engine import truncation

_WHITESPACE_RUN_RE = re.compile(r"\s+")
_NON_WHITESPACE_RE = re.compile(r"\S")


async def collapse_yielding(content: str, window: int) -> str:
    collapsed: list[str] = []
    start = 0
    while start < len(content):
        cut = _NON_WHITESPACE_RE.search(content, start + window)
        end = cut.start() if cut else len(content)
        collapsed.append(_WHITESPACE_RUN_RE.sub(" ", content[start:end]))
        await truncation.yield_once_slice_elapsed()
        start = end
    return "".join(collapsed)
