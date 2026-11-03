import multiprocessing as mp
import random
import re
import time
from multiprocessing.queues import Queue
from queue import Empty
from typing import cast

import pytest

from guard_core.sync.detection_engine.compiler import PatternCompiler
from guard_core.sync.handlers._suspatterns_pattern_table import _PATTERN_DEFINITIONS
from guard_core.sync.handlers.suspatterns_handler import _BUILTIN_PATTERN_COMPILE_FLAGS

_ORIGINAL_SQLI_PATTERN = (
    r"(?i)('\s*(?:OR|AND)\s*[\(\s]*'?(?:[@:$][A-Za-z_]\w*|[\d\w]+)\s*"
    r"(?:=|LIKE|<|>|<=|>=)\s*[\(\s]*'?(?:[@:$][A-Za-z_]\w*|[\d\w]+))"
)
_ORIGINAL_LDAP_PATTERN = r"\(\s*[|&]\s*\(\s*[^)(]+=[*]"


def _pattern_for(category: str, marker: str) -> str:
    return next(
        pattern
        for pattern, _context, pattern_category in _PATTERN_DEFINITIONS
        if pattern_category == category and marker in pattern
    )


_REWRITTEN_SQLI_PATTERN = _pattern_for("sqli", r"(?:LIKE|[<>]=?|=)")
_REWRITTEN_LDAP_PATTERN = _pattern_for("ldap", r"\([^)(]+=[*]")


def _matches(
    pattern: str, value: str
) -> list[tuple[tuple[int, int], str, tuple[str, ...]]]:
    compiled = re.compile(pattern, _BUILTIN_PATTERN_COMPILE_FLAGS)
    return [
        (match.span(), match.group(), match.groups())
        for match in compiled.finditer(value)
    ]


def _generated_cases(seed: int, alphabet: str, count: int) -> list[str]:
    generator = random.Random(seed)
    return [
        "".join(generator.choice(alphabet) for _ in range(generator.randrange(96)))
        for _ in range(count)
    ]


def _structured_sqli_cases(seed: int, count: int) -> list[str]:
    generator = random.Random(seed)
    conjunctions = ["OR", "AND", "or", "and"]
    leading_padding = ["", " ", "\t", "\n", " \t"]
    operator_padding = ["", " ", "(", " (", "\t((", " \n("]
    atoms = ["0", "1", "abc", "a1", "$user", "@name", ":value"]
    operators = ["=", "LIKE", "<", ">", "<=", ">="]
    quote = ["", "'"]
    between_padding = ["", " ", "\t", "\n"]
    return [
        "'"
        + generator.choice(leading_padding)
        + generator.choice(conjunctions)
        + generator.choice(operator_padding)
        + generator.choice(quote)
        + generator.choice(atoms)
        + generator.choice(between_padding)
        + generator.choice(operators)
        + generator.choice(operator_padding)
        + generator.choice(quote)
        + generator.choice(atoms)
        for _ in range(count)
    ]


_SQLI_CASES = [
    "' OR 1=1",
    "prefix ' AND ( 1 <= (2 suffix",
    "'OR $user>=:other",
    "'and fooLIKEbar",
    "' OR 'value' LIKE 'other",
    "before ' OR (((@left) < ((right after",
    "'(OR 1=1",
    "'( AND 1=1",
]
_LDAP_CASES = [
    "(|(uid=*))",
    "prefix (& (cn=alice*)) suffix",
    "(&(uid=*))(|(mail=*))",
    "before (| (cn===*)) after",
    "(&(cn=alice=*))",
]


@pytest.mark.parametrize(
    ("rewritten", "original", "cases"),
    [
        (_REWRITTEN_SQLI_PATTERN, _ORIGINAL_SQLI_PATTERN, _SQLI_CASES),
        (_REWRITTEN_LDAP_PATTERN, _ORIGINAL_LDAP_PATTERN, _LDAP_CASES),
    ],
)
def test_rewritten_builtin_matches_and_spans_match_original(
    rewritten: str, original: str, cases: list[str]
) -> None:
    values = list(cases)
    prefixes = ["", "x", " " * 7, "padding/" * 3]
    suffixes = ["", "y", " " * 7, "/suffix" * 3]
    values.extend(
        prefix + case + suffix
        for case in cases
        for prefix in prefixes
        for suffix in suffixes
    )
    values.extend(
        _structured_sqli_cases(2024, 2000) if original == _ORIGINAL_SQLI_PATTERN else []
    )
    values.extend(_generated_cases(1307, "abcXYZ012 ()[]'\"=<>:&|*\n\t", 2000))

    for value in values:
        assert _matches(rewritten, value) == _matches(original, value), value


@pytest.mark.parametrize("pattern", [_REWRITTEN_SQLI_PATTERN, _REWRITTEN_LDAP_PATTERN])
@pytest.mark.redos_timing
def test_rewritten_builtin_patterns_pass_safety_budget(pattern: str) -> None:
    safe, reason = PatternCompiler().validate_pattern_safety(
        pattern, flags=_BUILTIN_PATTERN_COMPILE_FLAGS
    )
    assert safe, reason


def _measure_ldap_scaling(
    payload_kind: str, sizes: list[int], repeats: int
) -> list[float]:
    context = mp.get_context("fork")
    result_queue = context.Queue()
    process = context.Process(
        target=_measure_ldap_scaling_child,
        args=(payload_kind, sizes, repeats, result_queue),
    )
    try:
        process.start()
        process.join(8.0)
        if process.is_alive():
            process.terminate()
            process.join(1.0)
            if process.is_alive():
                process.kill()
                process.join(1.0)
            pytest.fail(f"LDAP scaling worker timed out for {payload_kind}")
        assert process.exitcode == 0
        try:
            return cast(list[float], result_queue.get(timeout=1.0))
        except Empty as exc:
            raise AssertionError(
                "LDAP scaling worker returned no measurements"
            ) from exc
    finally:
        result_queue.close()
        result_queue.join_thread()
        process.close()


def _measure_ldap_scaling_child(
    payload_kind: str,
    sizes: list[int],
    repeats: int,
    result_queue: "Queue[list[float]]",
) -> None:
    pattern = re.compile(_REWRITTEN_LDAP_PATTERN, _BUILTIN_PATTERN_COMPILE_FLAGS)
    measurements = []
    for size in sizes:
        if payload_kind == "whitespace":
            value = "(|(" + " " * size + "X"
        elif payload_kind == "equals":
            value = "(|(" + "=" * size + "X"
        else:
            value = "(|(" + (" " * (size // 2) + "=" * (size // 2)) + "X"
        started = time.process_time()
        for _ in range(repeats):
            assert pattern.search(value) is None
        measurements.append(time.process_time() - started)
    result_queue.put(measurements)


@pytest.mark.parametrize("payload_kind", ["whitespace", "equals", "mixed"])
@pytest.mark.redos_timing
def test_ldap_rewrite_scales_linearly_for_hostile_padding(payload_kind: str) -> None:
    measurements = _measure_ldap_scaling(payload_kind, [2048, 4096, 8192, 16384], 20)
    assert measurements[-1] / max(measurements[0], 1e-6) < 24, measurements
