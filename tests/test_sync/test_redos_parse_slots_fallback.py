import importlib
from collections.abc import Callable
from types import ModuleType

import pytest

from guard_core.sync.detection_engine import _redos_parse_slots as slots


def _fail_the_preferred_import(
    monkeypatch: pytest.MonkeyPatch, preferred: str, fallback: str
) -> ModuleType:
    fallback_module = ModuleType(fallback)
    real_import_module = importlib.import_module

    def import_module(name: str, package: str | None = None) -> ModuleType:
        if name == preferred:
            raise ImportError(name)
        if name == fallback:
            return fallback_module
        return real_import_module(name, package)

    monkeypatch.setattr(slots.importlib, "import_module", import_module)
    return fallback_module


@pytest.mark.parametrize(
    ("loader", "preferred", "fallback"),
    [
        (slots._import_regex_parser_module, "re._parser", "sre_parse"),
        (slots._import_regex_compiler_module, "re._compiler", "sre_compile"),
    ],
)
def test_a_python_without_the_private_re_modules_falls_back_to_the_sre_names(
    monkeypatch: pytest.MonkeyPatch,
    loader: Callable[[], ModuleType],
    preferred: str,
    fallback: str,
) -> None:
    fallback_module = _fail_the_preferred_import(monkeypatch, preferred, fallback)
    assert loader() is fallback_module
