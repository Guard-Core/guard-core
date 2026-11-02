import queue
import random
import threading
import time
from io import StringIO

import pytest

from guard_core.sync._utils import body_form_scan
from guard_core.sync._utils.body_form_scan import (
    _MULTIPART_PARSE_SLOTS,
    _body_text,
    _HeaderThenBody,
    _multipart_text_parts,
)

_HEADER = "Content-Type: multipart/form-data; boundary=B\r\nMIME-Version: 1.0\r\n\r\n"
_CONTENT_TYPE = "multipart/form-data; boundary=B"
_BYTE_TOKENS = (
    b"x",
    b"\n",
    b"\r\n",
    b"\xc3\xa9",
    b"\xe2\x82\xac",
    b"\xf0\x9f\x98\x80",
    b"\xff",
    b"\xe2\x82",
    b"\xc0\xaf",
    b"\x80",
)


def _random_bytes(rng: random.Random, tokens: int) -> bytes:
    return b"".join(rng.choice(_BYTE_TOKENS) for _ in range(tokens))


def test_the_bytes_reader_returns_the_chunks_of_the_decoded_string() -> None:
    rng = random.Random(20261101)
    for tokens in (0, 1, 5, 400, 9000):
        body = _random_bytes(rng, tokens)
        for size in (1, 7, 8192, rng.randint(1, 500)):
            reference = StringIO(_HEADER + _body_text(body))
            reader = _HeaderThenBody(_HEADER, body)
            while True:
                expected = reference.read(size)
                assert reader.read(size) == expected
                if not expected:
                    break


def test_the_bytes_reader_without_a_size_returns_the_decoded_rest() -> None:
    body = b"caf\xc3\xa9 \xff"
    reader = _HeaderThenBody("head\r\n", body)
    assert reader.read(2) == "he"
    assert reader.read() == "ad\r\n" + _body_text(body)
    assert reader.read(8192) == ""


def test_a_multipart_body_parses_the_same_from_bytes_and_from_its_decoded_string() -> (
    None
):
    rng = random.Random(20261102)
    for tokens in (0, 3, 40, 9000):
        payload = _random_bytes(rng, tokens)
        body = (
            b'--B\r\nContent-Disposition: form-data; name="f"; filename="x"\r\n\r\n'
            + payload
            + b"\r\n--B--\r\n"
        )
        assert _multipart_text_parts(body, _CONTENT_TYPE) == _multipart_text_parts(
            _body_text(body), _CONTENT_TYPE
        )


def _hold_every_parse_open(
    monkeypatch: pytest.MonkeyPatch, release: threading.Event
) -> tuple[list[int], threading.Lock]:
    inside = [0, 0]
    lock = threading.Lock()

    def _blocking_leaf_parts(raw_body: str | bytes, content_type: str) -> None:
        with lock:
            inside[0] += 1
            inside[1] = max(inside[1], inside[0])
        release.wait(timeout=5)
        with lock:
            inside[0] -= 1

    monkeypatch.setattr(body_form_scan, "_multipart_leaf_parts", _blocking_leaf_parts)
    return inside, lock


def test_no_more_multipart_parses_run_at_once_than_the_slots_allow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = threading.Event()
    inside, lock = _hold_every_parse_open(monkeypatch, release)
    threads = [
        threading.Thread(target=_multipart_text_parts, args=(b"x", _CONTENT_TYPE))
        for _ in range(3 * _MULTIPART_PARSE_SLOTS)
    ]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with lock:
            if inside[0] == _MULTIPART_PARSE_SLOTS:
                break
        time.sleep(0.005)
    time.sleep(0.05)
    with lock:
        held_now = inside[0]
    release.set()
    for thread in threads:
        thread.join(timeout=10)

    assert held_now == _MULTIPART_PARSE_SLOTS
    assert inside[1] == _MULTIPART_PARSE_SLOTS
    assert inside[0] == 0


def test_a_failing_multipart_parse_gives_its_slot_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _failing_leaf_parts(raw_body: str | bytes, content_type: str) -> None:
        raise RuntimeError("parse failed")

    monkeypatch.setattr(body_form_scan, "_multipart_leaf_parts", _failing_leaf_parts)
    for _ in range(3 * _MULTIPART_PARSE_SLOTS):
        with pytest.raises(RuntimeError, match="parse failed"):
            _multipart_text_parts(b"x", _CONTENT_TYPE)


def test_a_forked_child_starts_with_every_parse_slot_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    taken_by_the_parents_threads: queue.SimpleQueue[None] = queue.SimpleQueue()
    monkeypatch.setattr(body_form_scan, "_parse_slots", taken_by_the_parents_threads)

    body_form_scan._forget_the_parents_parse_slots()

    slots = body_form_scan._parse_slots
    assert slots is not taken_by_the_parents_threads
    for _ in range(_MULTIPART_PARSE_SLOTS):
        slots.get(timeout=1)
    assert slots.empty()
