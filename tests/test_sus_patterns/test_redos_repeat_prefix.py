import re
import sys
import time
from dataclasses import replace

import pytest

from guard_core.detection_engine._redos_intervals import _IntervalSet
from guard_core.detection_engine._redos_parse_slots import _regex_parser
from guard_core.detection_engine._redos_prefixed_probe import (
    _prefixed_repeat_probe,
    _prefixed_unit_builders,
)
from guard_core.detection_engine._redos_repeat_lookbehind import (
    _check_mutation_budget,
    _negative_lookbehind,
)
from guard_core.detection_engine._redos_repeat_prefix import (
    _check_deadline,
    _PrefixWalk,
    _repeat_reaching_prefixes,
    _unique_states,
)
from guard_core.detection_engine._redos_repeat_prefix_state import (
    _capture_state,
    _consume_atom,
    _consume_piece,
    _merge_pending,
    _RepeatPrefixState,
)


def _walk(pattern: str) -> list[_RepeatPrefixState]:
    parsed = _regex_parser.parse(pattern, 0)
    return _PrefixWalk(parsed.state.flags, [], None, False, ["X", "Y"]).walk(
        parsed.data, [_RepeatPrefixState("")]
    )


@pytest.mark.parametrize(
    "pattern,prefix",
    [
        (r"\A(?!X)[XY]a+a+$", "Y"),
        (r"\A(?=XY)[XY][XY]a+a+$", "XY"),
        (r"\A(?!XX)[XY][XY]a+a+$", "XY"),
        (r"(?<=foo)a+a+$", "foo"),
        (r"(?<=(X))\1a+a+$", "XX"),
        (r"\A[XY](?<!X)a+a+$", "Y"),
        (r"\A[XY]XX(?<!XXX)a+a+$", "YXX"),
        (r"\A([XY])\1a+a+$", "XX"),
        (r"\A(?=([XY]))\1a+a+$", "X"),
        (r"\A(X)?\1a+a+$", "XX"),
        (r"\A(?:Xa+a+$)?", "X"),
        (r"\A(?=X)X?a+a+$", "X"),
        pytest.param(
            r"\A(?i:x)(?>Y)a+a+$",
            "XY",
            marks=pytest.mark.skipif(
                sys.version_info < (3, 11), reason="Python 3.11 syntax"
            ),
        ),
        (r"\A(?=f?oo)fooa+a+$", "foo"),
        (r"\Axf?(?<=f)a+a+$", "xf"),
        (r"\Axf?(?<!x)a+a+$", "xf"),
        (r"\A(?=foo).*oa+a+$", "foo"),
        (r"\A(?=foo).+fooa+a+$", "foofoo"),
        (r"\A(X)?(?(1)Y|Z)a+a+$", "XY"),
        (r"\A(X)?(?(1)Y|Z)a+a+$", "Z"),
    ],
)
def test_reaching_prefix_preserves_assertions_and_captures(
    pattern: str, prefix: str
) -> None:
    assert prefix in _repeat_reaching_prefixes(pattern, 0)
    assert re.search(pattern, prefix + "aa") is not None


@pytest.mark.parametrize("pattern", ["[", r"(?!)[XY]+", r"(?=X)Y[XY]+", r"[^\s\S]+"])
def test_impossible_or_invalid_prefix_has_no_candidate(pattern: str) -> None:
    assert _repeat_reaching_prefixes(pattern, 0) == []


@pytest.mark.parametrize(
    "pattern,expected",
    [
        (r"(?=XY)(?=X)XY", ["XY"]),
        (r"(?=X)(?=XY)XY", ["XY"]),
        (r"(?=X)(?=Y)X", []),
        (r"(?=XY)X", ["X"]),
        (r"(?!XY)XZ", ["XZ"]),
        (r"X(?<!Y)", ["X"]),
        (r"(?<!X)Y", ["Y"]),
        (r"X(?<!X)", []),
        (r"XX(?<!YY)", ["XX"]),
        (r"(?:){1000}X", ["X"]),
        (r"(?!){1}X", []),
        (r"X{0}Y", ["Y"]),
        (r"(?<=)X", ["X"]),
        (r"(X)?(?(1)Y)", ["", "XY"]),
        (r"(?:X|(?i:Y))?Z", ["Z", "XZ", "YZ"]),
        (r"(?=foo)(?:)*foo", ["foo"]),
        (r"(?=foo)x*foo", ["foo"]),
    ],
)
def test_prefix_walk_constraints(pattern: str, expected: list[str]) -> None:
    assert [state.text for state in _walk(pattern)] == expected


def test_empty_negative_lookbehind_walk_follows_how_the_interpreter_parses_it() -> None:
    # 3.14 parses (?<!) as FAILURE, earlier versions as an empty ASSERT_NOT; the
    # walk follows the parse, and re never matches the pattern on any of them.
    pattern = r"(?<!)X"
    first_op = _regex_parser.parse(pattern, 0).data[0][0]
    expected = [] if first_op is _regex_parser.FAILURE else ["X"]

    assert re.search(pattern, "X") is None
    assert [state.text for state in _walk(pattern)] == expected


def test_prefix_construction_limits_fail_closed() -> None:
    with pytest.raises(TimeoutError, match="deadline"):
        _check_deadline(time.monotonic() - 1)
    with pytest.raises(TimeoutError, match="deadline"):
        _repeat_reaching_prefixes("Xa+a+", 0, time.monotonic() - 1)
    with pytest.raises(TimeoutError, match="length budget"):
        _consume_piece(_RepeatPrefixState("a" * 24000), "b")
    with pytest.raises(TimeoutError, match="state budget"):
        _unique_states([_RepeatPrefixState(str(i)) for i in range(16385)])
    with pytest.raises(TimeoutError, match="text budget"):
        _unique_states([_RepeatPrefixState("x" * 2000001)])
    walker = _PrefixWalk(0, ["a"] * 4096, None, True)
    with pytest.raises(TimeoutError, match="candidate budget"):
        walker.record_prefixes(2, [_RepeatPrefixState("b")])
    with pytest.raises(TimeoutError, match="lookbehind state budget"):
        _check_mutation_budget(_RepeatPrefixState("X"), 1025)
    with pytest.raises(TimeoutError, match="capture-dependent"):
        _negative_lookbehind(
            _IntervalSet.single(ord("X")),
            _RepeatPrefixState("X", captures=((1, "X"),)),
        )


def test_prefix_state_consumption_rejects_conflicting_constraints() -> None:
    state = _RepeatPrefixState("a")
    assert _consume_piece(state, "") is state
    assert _capture_state(state, None, 0) is state
    assert _merge_pending("XY", "Z") is None
    excluded = replace(state, excluded=_IntervalSet.single(ord("X")))
    assert _consume_piece(excluded, "X") is None
    pending = replace(state, pending="X")
    assert _consume_piece(pending, "Y") is None
    assert _consume_atom(pending, _IntervalSet.single(ord("Y"))) is None
    forbidden = replace(state, forbidden=("XY",))
    assert _consume_piece(forbidden, "XYZ") is None
    assert (
        _consume_atom(replace(state, forbidden=("X",)), _IntervalSet.single(88)) is None
    )
    consumed = _consume_piece(replace(state, pending="XY"), "X")
    assert consumed is not None and consumed.pending == "Y"
    assert _capture_state(state, 1, 0).captures == ((1, "a"),)


def test_prefix_walker_unknown_node_fails_closed() -> None:
    walker = _PrefixWalk(0, [], None, False)
    assert walker.node(object(), None, [_RepeatPrefixState("")]) == []


def test_prefix_walker_atomic_node_preserves_consumed_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    atomic_op = object()
    monkeypatch.setattr(_regex_parser, "ATOMIC_GROUP", atomic_op, raising=False)
    walker = _PrefixWalk(0, [], None, False)
    states = walker.node(
        atomic_op, [(_regex_parser.LITERAL, ord("X"))], [_RepeatPrefixState("")]
    )
    assert [state.text for state in states] == ["X"]


@pytest.mark.parametrize("length", [0, 1, 2, 3, 9, 10])
@pytest.mark.parametrize("flood", [False, True])
def test_prefixed_probe_has_exact_length_and_failure_tail(
    length: int, flood: bool
) -> None:
    probe = _prefixed_repeat_probe("XY", "ab", "!", flood, length)
    assert len(probe) == length
    assert probe.startswith("XY"[:length])
    if length > 2:
        assert probe.endswith("!" * (max(1, (length - 2) // 2) if flood else 1))


def test_prefixed_builder_deduplication_and_budget() -> None:
    builders = _prefixed_unit_builders(["X"], [("a", "!"), ("a", "!")])
    assert [build(7) for build in builders] == ["Xaaaaa!", "Xaaa!!!"]
    assert _prefixed_unit_builders([], [("a", "!")]) == []
    with pytest.raises(TimeoutError, match="candidate budget"):
        _prefixed_unit_builders(["X"] * 2049, [("a", "!")])


@pytest.mark.parametrize(
    "pattern",
    [r"\A(?=(?=foo))fooa+a+$", r"\A(?=(?=f.o))fooa+a+$", r"\A(?=(?!foo))fooa+a+$"],
)
def test_unresolved_nested_assertions_fail_closed(pattern: str) -> None:
    with pytest.raises(TimeoutError, match="nested assertion"):
        _repeat_reaching_prefixes(pattern, 0)


@pytest.mark.parametrize(
    "suffix",
    [r"a+", r"(a+)", r"(?:Xa+|Yb+)", r"(?=a+)X", r"(?!a+)X", r"(?:a+)?", r"[a-z]{0,2}"],
)
def test_dead_prefix_before_quantified_suffix_fails_closed(suffix: str) -> None:
    with pytest.raises(TimeoutError, match="repeat-site prefixes"):
        _repeat_reaching_prefixes(r"\A(?=f.o)foo" + suffix, 0, require_reachable=True)


def test_dead_prefix_without_remaining_repeat_needs_no_adversarial_probe() -> None:
    assert _repeat_reaching_prefixes(r"(?=X)Y", 0, require_reachable=True) == []


def test_repeat_discovery_inside_atomic_group(monkeypatch: pytest.MonkeyPatch) -> None:
    from guard_core.detection_engine._redos_prefix_history import _contains_repeat

    atomic_op = object()
    monkeypatch.setattr(_regex_parser, "ATOMIC_GROUP", atomic_op, raising=False)
    assert _contains_repeat([(atomic_op, [(_regex_parser.MAX_REPEAT, (0, 2, []))])])


def test_group_probe_candidates_preserve_sites_and_memoize_strays() -> None:
    from guard_core.detection_engine._redos_prefixed_probe import _group_unit_builders

    calls = []

    def choose(unit: str) -> str:
        calls.append(unit)
        return "!"

    builders = _group_unit_builders([("X", "ab"), ("Y", "ab")], ["!", "?"], choose)
    values = [builder(7) for builder in builders]
    assert calls == ["ab"]
    assert len(values) == len(set(values)) == 12
    assert "Xababa!" in values and "Yabab??" not in values
    assert "Yaba???" in values and "ababab!" in values


def test_group_probe_candidate_expansion_has_a_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_core.detection_engine._redos_prefixed_probe import _group_unit_builders

    monkeypatch.setattr(
        "guard_core.detection_engine._redos_prefixed_probe._GROUP_PREFIX_CANDIDATE_LIMIT",
        4,
    )
    with pytest.raises(TimeoutError, match="group-probe candidate budget"):
        _group_unit_builders([("X", "ab"), ("Y", "ab")], ["!", "?"], lambda _unit: "!")
