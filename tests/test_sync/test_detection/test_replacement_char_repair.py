import pytest

from guard_core.sync.detection_engine.encoding_decoders import (
    repair_lost_overlong_bytes,
)
from guard_core.sync.handlers import _suspatterns_pickle as pickle_rows
from guard_core.sync.handlers._suspatterns_state import _LEGACY_DETECTION_STATE
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

FFFD = "\ufffd"


@pytest.mark.parametrize(
    ("text", "repaired"),
    [
        ("..\ufffd/config.yaml", "../config.yaml"),
        ("..\ufffd\ufffdconfig.yaml", "../config.yaml"),
        ("\ufffd\ufffd\ufffd\ufffd/etc/passwd", "../etc/passwd"),
        ("/a/..\ufffd\ufffd..\ufffd\ufffdetc", "/a/../../etc"),
        ("..\udcc0/config.yaml", "../config.yaml"),
        ("..\udcc0\udcafconfig.yaml", "../config.yaml"),
        ("no lost byte ../x", "no lost byte ../x"),
        ("a..\ufffd\ufffdb", "a..\ufffd\ufffdb"),
        ("\ufffd..\ufffd/x", "\ufffd..\ufffd/x"),
        ("a\ufffd\ufffd\ufffd\ufffd/etc", "a\ufffd\ufffd\ufffd\ufffd/etc"),
        ("x..\ufffd\ufffd\ufffd\ufffd", "x..\ufffd\ufffd\ufffd\ufffd"),
        ("..\ufffd\ufffd\ufffd\ufffd", "..\ufffd\ufffd\ufffd\ufffd"),
    ],
)
def test_repair_lost_overlong_bytes_reads_only_a_segment_opening_traversal(
    text: str, repaired: str
) -> None:
    assert repair_lost_overlong_bytes(text) == repaired


def test_pickle_prefix_resolves_a_lost_byte_as_any_opcode_or_data_byte() -> None:
    walk = pickle_rows._pickle_prefix_with_replacement_chars_is_opcode_stream
    assert walk(f"{FFFD}\x04")
    assert walk(f"{FFFD}")
    assert walk(f"{FFFD}\x04{FFFD}\x1c\x00\x00\x00\x00\x00\x00\x00")
    assert not walk(f"{FFFD}zz")
    assert not walk("€")
    assert not walk(FFFD * (pickle_rows._PICKLE_REPLACEMENT_MAX_CHARS + 1))


def test_pickle_prefix_gives_up_after_its_walk_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pickle_rows, "_PICKLE_REPLACEMENT_WALK_BUDGET", 0)
    assert not pickle_rows._pickle_prefix_with_replacement_chars_is_opcode_stream(
        f"{FFFD}\x04"
    )


def test_lost_byte_view_is_skipped_without_a_preprocessor() -> None:
    manager = SusPatternsManager()
    skipped = manager._check_lost_overlong_bytes_view_patterns(
        "..\ufffd/config.yaml",
        "198.51.100.4",
        "query_param:q",
        None,
        None,
        _LEGACY_DETECTION_STATE,
    )
    assert skipped == ([], [], [])
