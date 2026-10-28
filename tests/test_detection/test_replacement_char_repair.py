import pytest

from guard_core.detection_engine.encoding_decoders import repair_lost_overlong_bytes
from guard_core.handlers import _suspatterns_pickle as pickle_rows
from guard_core.handlers._suspatterns_state import _LEGACY_DETECTION_STATE
from guard_core.handlers.suspatterns_handler import SusPatternsManager

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


async def test_lost_byte_view_is_skipped_without_a_preprocessor() -> None:
    manager = SusPatternsManager()
    skipped = await manager._check_lost_overlong_bytes_view_patterns(
        "..\ufffd/config.yaml",
        "198.51.100.4",
        "query_param:q",
        None,
        None,
        _LEGACY_DETECTION_STATE,
    )
    assert skipped == ([], [], [])


def test_pickle_suffix_resolves_a_lost_byte_and_stays_bounded() -> None:
    reach = pickle_rows._pickle_global_suffix_reaches_reduce_or_build
    assert reach("X\x06\x00\x00\x00/tmp/x" + FFFD + "R.")
    assert reach("\x8c\x06/tmp/x" + FFFD + "R.")
    assert reach(FFFD * 2 + "R")
    assert not reach("hello " + FFFD + " world")
    assert not reach(FFFD * (pickle_rows._PICKLE_REPLACEMENT_MAX_CHARS + 1) + "R")
    assert not reach("中" + FFFD + "R")


def test_pickle_suffix_gives_up_after_its_walk_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pickle_rows, "_PICKLE_REPLACEMENT_WALK_BUDGET", 0)
    assert not pickle_rows._pickle_global_suffix_reaches_reduce_or_build(
        "\x8c\x06/tmp/x" + FFFD + "R."
    )
