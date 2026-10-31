import importlib
from collections.abc import Callable
from types import ModuleType

import pytest

from guard_core.detection_engine import _redos_parse_slots


def _importer_that_lacks(
    missing: str, stand_in: ModuleType
) -> Callable[[str, str | None], ModuleType]:
    real = importlib.import_module

    def fake(name: str, package: str | None = None) -> ModuleType:
        if name == missing:
            raise ImportError(name)
        if name == stand_in.__name__:
            return stand_in
        return real(name, package)

    return fake


def test_the_parser_module_falls_back_to_sre_parse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stand_in = ModuleType("sre_parse")
    monkeypatch.setattr(
        importlib, "import_module", _importer_that_lacks("re._parser", stand_in)
    )

    assert _redos_parse_slots._import_regex_parser_module() is stand_in


def test_the_compiler_module_falls_back_to_sre_compile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stand_in = ModuleType("sre_compile")
    monkeypatch.setattr(
        importlib, "import_module", _importer_that_lacks("re._compiler", stand_in)
    )

    assert _redos_parse_slots._import_regex_compiler_module() is stand_in
