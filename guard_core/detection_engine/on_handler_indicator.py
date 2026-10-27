import re
from collections.abc import Iterator

ON_HANDLER_PATTERN = r"on\w+="
_WORD_RUN_RE = re.compile(r"\w+")
_ON_RE = re.compile("on", re.IGNORECASE)


class _Span:
    __slots__ = ("_end", "_start")

    def __init__(self, start: int, end: int) -> None:
        self._start = start
        self._end = end

    def start(self) -> int:
        return self._start

    def end(self) -> int:
        return self._end


class OnHandlerIndicator:
    """The attack indicator ``on\\w+=`` as one linear pass over the word runs.

    ``re.finditer(r"on\\w+=", text, re.IGNORECASE)`` retries every start inside a
    long word run that is not followed by ``=``, which is quadratic on
    ``onon...``. Because ``=`` is not a word character, a match is exactly: a
    maximal word run followed by ``=``, from its leftmost ``on`` that leaves at
    least one word character before the ``=``, to the ``=``. Each run is
    visited once.
    """

    pattern = ON_HANDLER_PATTERN
    flags = re.compile(ON_HANDLER_PATTERN, re.IGNORECASE).flags

    def finditer(
        self, text: str, start: int = 0, stop: int | None = None
    ) -> Iterator[_Span]:
        for run in _WORD_RUN_RE.finditer(
            text, start, len(text) if stop is None else stop
        ):
            run_end = run.end()
            if text[run_end : run_end + 1] != "=":
                continue
            on = _ON_RE.search(text, run.start(), run_end - 1)
            if on is not None:
                yield _Span(on.start(), run_end + 1)

    def search(self, text: str) -> _Span | None:
        return next(self.finditer(text), None)
