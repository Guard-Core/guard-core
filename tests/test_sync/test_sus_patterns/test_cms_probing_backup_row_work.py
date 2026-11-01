import itertools
import re
import time

import pytest

from guard_core.sync.detection_engine._redos_work_counter import WORK_COUNTER_SOURCE
from guard_core.sync.handlers.suspatterns_handler import (
    _BUILTIN_PATTERN_COMPILE_FLAGS,
    SusPatternsManager,
)

_FACTORED = "(?:b(?:ak|ackup)|old|"
_FLAT = "(?:bak|backup|old|"
_PROBE_LENGTH = 32000
_CPU_SAMPLES = 15


def _backup_rows() -> tuple[str, str]:
    (factored,) = [
        pattern
        for pattern, _context, name in SusPatternsManager._pattern_definitions
        if name == "cms_probing" and _FACTORED in pattern
    ]
    return factored.replace(_FACTORED, _FLAT), factored


def _work_of(compiled: re.Pattern[str], probe: str) -> float:
    namespace: dict[str, object] = {"re": re}
    exec(WORK_COUNTER_SOURCE, namespace)
    build_work_counter = namespace["build_work_counter"]
    assert callable(build_work_counter)
    counter = build_work_counter()
    if callable(counter):
        return float(counter(compiled, probe))
    samples = []
    for _ in range(_CPU_SAMPLES):
        start = time.process_time()
        compiled.search(probe)
        samples.append(time.process_time() - start)
    return min(samples)


@pytest.mark.redos_timing
def test_the_factored_backup_extension_costs_less_than_the_flat_alternation() -> None:
    flat, factored = _backup_rows()
    probe = "." * _PROBE_LENGTH
    flat_work = _work_of(re.compile(flat, _BUILTIN_PATTERN_COMPILE_FLAGS), probe)
    factored_work = _work_of(
        re.compile(factored, _BUILTIN_PATTERN_COMPILE_FLAGS), probe
    )
    assert factored_work < 0.95 * flat_work


def test_the_factored_backup_extension_matches_the_flat_alternation_language() -> None:
    flat, factored = _backup_rows()
    flat_compiled = re.compile(flat, _BUILTIN_PATTERN_COMPILE_FLAGS)
    factored_compiled = re.compile(factored, _BUILTIN_PATTERN_COMPILE_FLAGS)
    inputs = [
        "".join(letters)
        for length in range(1, 8)
        for letters in itertools.product("./bakcuBK", repeat=length)
        if length < 6 or letters.count(".") <= 1
    ]
    inputs += ["x/.bak?q=1", "a/b/.backup", ".BACKUP", ".bac", ".baK", "K"]
    assert all(
        bool(flat_compiled.match(text)) == bool(factored_compiled.match(text))
        for text in inputs
    )
    assert factored_compiled.match(".bak") and factored_compiled.match(".backup")
