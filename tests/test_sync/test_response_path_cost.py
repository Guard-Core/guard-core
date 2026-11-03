import pytest

from guard_core.sync._utils import body_reader
from guard_core.sync._utils.body_reader import _safe_read


def _no_slot(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("a read with no concurrency limit must not enter a slot")


def test_a_read_with_no_concurrency_limit_enters_no_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(body_reader, "_body_read_slot", _no_slot)

    assert _safe_read(lambda: b"abc", 1.0) == b"abc"


def test_a_read_with_a_concurrency_limit_still_enters_a_slot() -> None:
    assert _safe_read(lambda: b"abc", 1.0, 2) == b"abc"


def test_a_reader_that_raises_is_unavailable() -> None:
    def raises() -> bytes:
        raise OSError("boom")

    assert _safe_read(raises, 1.0) is None
    assert _safe_read(raises, 1.0, 2) is None
