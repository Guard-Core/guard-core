import sys
import types

import pytest

from guard_core.sync.detection_engine._redos_engine_normalizer import (
    ENGINE_NORMALIZER_SOURCE,
)
from guard_core.sync.detection_engine.compiler import PatternCompiler

_COMPLETE_CLASS_COUNTS = [4000, 4060, 4095, 4096, 4100, 4150, 4200]
_COMPLETE_CLASS_TAILS = [r"[^☃]", r"[^x]", r"[^☃]\d", r"[^a-c]z"]


def _validate(pattern: str) -> tuple[bool, str]:
    return PatternCompiler().validate_pattern_safety(pattern)


def test_normalizer_source_runs_on_an_interpreter_without_the_shortcut() -> None:
    namespace: dict[str, object] = {"re": types.SimpleNamespace()}
    exec(ENGINE_NORMALIZER_SOURCE, namespace)
    assert "_NeverTheCompleteCharset" in namespace


def test_normalizer_source_keeps_the_complete_class_a_class() -> None:
    charset_all = [("NEGATE", None)]
    fake_re = types.SimpleNamespace(
        _compiler=types.SimpleNamespace(_CHARSET_ALL=charset_all)
    )
    exec(ENGINE_NORMALIZER_SOURCE, {"re": fake_re})
    normalized = fake_re._compiler._CHARSET_ALL
    assert list(normalized) == charset_all
    assert normalized != charset_all
    assert charset_all != normalized
    assert not normalized == normalized


@pytest.mark.redos_timing
@pytest.mark.parametrize("count", _COMPLETE_CLASS_COUNTS)
@pytest.mark.parametrize("tail", _COMPLETE_CLASS_TAILS)
def test_a_complete_class_repeated_to_the_large_bounds_is_refused_on_every_python(
    count: int, tail: str
) -> None:
    safe, reason = _validate(r"[\s\S]{" + str(count) + "}" + tail)
    assert not safe, (sys.version.split()[0], reason)


@pytest.mark.redos_timing
@pytest.mark.parametrize("complete_class", [r"[\d\D]", r"[\w\W]", r"[\s\S]"])
def test_every_spelling_of_the_complete_class_is_refused(complete_class: str) -> None:
    safe, reason = _validate(complete_class + r"{4095}[^☃]")
    assert not safe, reason


@pytest.mark.redos_timing
def test_the_dotall_any_character_spelling_stays_accepted() -> None:
    safe, reason = _validate(r"(?s:.){4095}[^☃]")
    assert safe, reason
