import io
import pickle
import re
import sys
from collections.abc import Callable
from typing import TYPE_CHECKING, ClassVar, NoReturn

from guard_core.sync.handlers._suspatterns_sources import (
    _PICKLE_OPCODE_WORK_BUDGET_BYTES,
)


class _PickleOpcodePrefixResolutionBlocked(Exception):
    pass


class _PickleOpcodePrefixShortRead(Exception):
    pass


if TYPE_CHECKING:
    _UnpicklerBase = pickle.Unpickler
else:
    _UnpicklerBase = pickle._Unpickler


class _PickleOpcodePrefixUnpickler(_UnpicklerBase):
    dispatch: ClassVar[dict[int, Callable[["_PickleOpcodePrefixUnpickler"], object]]]
    stack: list[object]
    metastack: list[object]
    append: Callable[[object], None]
    read: Callable[[int], bytes]
    readline: Callable[[], bytes]
    readinto: Callable[[bytearray], int]

    def find_class(self, module: str, name: str) -> NoReturn:
        raise _PickleOpcodePrefixResolutionBlocked(module, name)

    def get_extension(self, code: int) -> NoReturn:
        raise _PickleOpcodePrefixResolutionBlocked(code)

    def persistent_load(self, pid: object) -> NoReturn:
        raise _PickleOpcodePrefixResolutionBlocked(pid)


def _pickle_prefix_bounded_read(stream: io.BytesIO, size: int) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise _PickleOpcodePrefixShortRead(size)
    return data


def _pickle_prefix_bounded_readline(stream: io.BytesIO) -> bytes:
    line = stream.readline()
    if not line.endswith(b"\n"):
        raise _PickleOpcodePrefixShortRead(-1)
    return line


def _pickle_prefix_bounded_readinto(stream: io.BytesIO, buf: bytearray) -> int:
    count = stream.readinto(buf)
    if count != len(buf):
        raise _PickleOpcodePrefixShortRead(len(buf))
    return count


def _pickle_prefix_load_frame(unpickler: _PickleOpcodePrefixUnpickler) -> None:
    frame_size = int.from_bytes(unpickler.read(8), "little")
    if frame_size > sys.maxsize:
        raise ValueError(f"frame size > sys.maxsize: {frame_size}")


def _pickle_prefix_walk_from_start(
    window: bytes, is_complete_prefix: bool
) -> bool | None:
    total = len(window)
    stream = io.BytesIO(window)
    unpickler = _PickleOpcodePrefixUnpickler(stream)
    unpickler.stack = []
    unpickler.metastack = []
    unpickler.append = unpickler.stack.append
    unpickler.read = lambda size: _pickle_prefix_bounded_read(stream, size)
    unpickler.readline = lambda: _pickle_prefix_bounded_readline(stream)
    unpickler.readinto = lambda buf: _pickle_prefix_bounded_readinto(stream, buf)
    try:
        while stream.tell() < total:
            key = unpickler.read(1)
            if key[0] == pickle.FRAME[0]:
                _pickle_prefix_load_frame(unpickler)
                continue
            handler = unpickler.dispatch.get(key[0])
            if handler is None:
                return False
            handler(unpickler)
    except _PickleOpcodePrefixShortRead:
        return False if is_complete_prefix else None
    except Exception:
        return False
    return True if is_complete_prefix else None


_PICKLE_SURROGATEESCAPE_LOW = 0xDC80
_PICKLE_SURROGATEESCAPE_HIGH = 0xDCFF


def _pickle_prefix_window_from_chars(chars: str) -> bytes | None:
    window = bytearray()
    for char in chars:
        code = ord(char)
        if code <= 0xFF:
            window.append(code)
        elif _PICKLE_SURROGATEESCAPE_LOW <= code <= _PICKLE_SURROGATEESCAPE_HIGH:
            window.append(code - _PICKLE_SURROGATEESCAPE_LOW + 0x80)
        else:
            return None
    return bytes(window)


def _pickle_opcode_scan_window(text: str, budget: int) -> tuple[bytes | None, bool]:
    is_complete = len(text) <= budget
    scan_slice = text if is_complete else text[:budget]
    return _pickle_prefix_window_from_chars(scan_slice), is_complete


_PICKLE_REPLACEMENT_CHAR = "\ufffd"
_PICKLE_REPLACEMENT_BYTE_CANDIDATES = (*range(0x80, 0x96), 0xFF)
_PICKLE_REPLACEMENT_MAX_CHARS = 8
_PICKLE_REPLACEMENT_WALK_BUDGET = 256


def _pickle_replacement_pieces(prefix: str) -> list[bytes] | None:
    scan_slice = prefix[:_PICKLE_OPCODE_WORK_BUDGET_BYTES]
    if scan_slice.count(_PICKLE_REPLACEMENT_CHAR) > _PICKLE_REPLACEMENT_MAX_CHARS:
        return None
    pieces: list[bytes] = []
    for chars in scan_slice.split(_PICKLE_REPLACEMENT_CHAR):
        piece = _pickle_prefix_window_from_chars(chars)
        if piece is None:
            return None
        pieces.append(piece)
    return pieces


def _pickle_prefix_with_replacement_chars_is_opcode_stream(prefix: str) -> bool:
    """A U+FFFD is a high byte the framework could not decode, so it stands for
    any of the high bytes a pickle opcode stream can hold (a protocol or frame
    opcode, or a filler for a data byte). The prefix counts as a stream when
    some choice of those bytes walks as one, the same test a surrogate-escaped
    high byte gets with the byte it carries."""
    pieces = _pickle_replacement_pieces(prefix)
    if pieces is None:
        return False
    is_complete = len(prefix) <= _PICKLE_OPCODE_WORK_BUDGET_BYTES
    walks = 0

    def resolve(window: bytes, next_piece: int) -> bool:
        nonlocal walks
        is_last = next_piece == len(pieces) - 1
        for byte in _PICKLE_REPLACEMENT_BYTE_CANDIDATES:
            walks += 1
            if walks > _PICKLE_REPLACEMENT_WALK_BUDGET:
                return False
            extended = window + bytes([byte]) + pieces[next_piece]
            if (
                _pickle_prefix_walk_from_start(extended, is_last and is_complete)
                is False
            ):
                continue
            if is_last or resolve(extended, next_piece + 1):
                return True
        return False

    return resolve(pieces[0], 1)


def _pickle_global_prefix_is_opcode_stream(prefix: str) -> bool:
    if not prefix or prefix[-1] == "\n":
        return True
    window, is_complete = _pickle_opcode_scan_window(
        prefix, _PICKLE_OPCODE_WORK_BUDGET_BYTES
    )
    if window is None:
        return _pickle_prefix_with_replacement_chars_is_opcode_stream(prefix)
    return _pickle_prefix_walk_from_start(window, is_complete) is not False


_PICKLE_REDUCE_OR_BUILD_KEYS = frozenset({ord("R"), ord("b")})


def _pickle_suffix_walk_reaches_reduce_or_build(
    window: bytes, is_complete_suffix: bool
) -> bool | None:
    total = len(window)
    stream = io.BytesIO(window)
    unpickler = _PickleOpcodePrefixUnpickler(stream)
    unpickler.stack = [object()]
    unpickler.metastack = []
    unpickler.append = unpickler.stack.append
    unpickler.read = lambda size: _pickle_prefix_bounded_read(stream, size)
    unpickler.readline = lambda: _pickle_prefix_bounded_readline(stream)
    unpickler.readinto = lambda buf: _pickle_prefix_bounded_readinto(stream, buf)
    try:
        while stream.tell() < total:
            key = unpickler.read(1)
            if key[0] in _PICKLE_REDUCE_OR_BUILD_KEYS:
                return True
            if key[0] == pickle.FRAME[0]:
                _pickle_prefix_load_frame(unpickler)
                continue
            handler = unpickler.dispatch.get(key[0])
            if handler is None:
                return False
            handler(unpickler)
    except _PickleOpcodePrefixShortRead:
        return False if is_complete_suffix else None
    except Exception:
        return False
    return False if is_complete_suffix else None


def _pickle_global_suffix_reaches_reduce_or_build(suffix: str) -> bool:
    window, is_complete = _pickle_opcode_scan_window(
        suffix, _PICKLE_OPCODE_WORK_BUDGET_BYTES
    )
    if window is None:
        return False
    return _pickle_suffix_walk_reaches_reduce_or_build(window, is_complete) is not False


def _pickle_global_candidate_is_injection(match: re.Match, _context: str) -> bool:
    if not _pickle_global_prefix_is_opcode_stream(match.string[: match.start()]):
        return False
    return _pickle_global_suffix_reaches_reduce_or_build(match.string[match.end(1) :])
