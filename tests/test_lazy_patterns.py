import importlib
import pkgutil
import re
import subprocess
import sys

import pytest

import guard_core
from guard_core._lazy_patterns import (
    CompiledOnDemand,
    LazyPatterns,
    module_attribute_lookup,
)


def _modules_with_lazy_patterns() -> list[str]:
    names = []
    for info in pkgutil.walk_packages(guard_core.__path__, "guard_core."):
        module = importlib.import_module(info.name)
        if isinstance(module.__dict__.get("_PATTERNS"), LazyPatterns):
            names.append(info.name)
    return sorted(names)


LAZY_MODULES = _modules_with_lazy_patterns()


def test_both_trees_have_modules_with_lazy_patterns() -> None:
    assert any(name.startswith("guard_core.sync.") for name in LAZY_MODULES)
    assert any(not name.startswith("guard_core.sync.") for name in LAZY_MODULES)


@pytest.mark.parametrize("module_name", LAZY_MODULES)
def test_every_lazy_name_compiles_on_lookup_and_stays_importable(
    module_name: str,
) -> None:
    module = importlib.import_module(module_name)
    table = module._PATTERNS

    for name in table._definitions:
        source, flags = table._definitions[name]
        compiled = getattr(module, name)

        assert isinstance(compiled, re.Pattern)
        assert compiled is table[name]
        assert compiled.pattern == source
        assert compiled.flags == re.compile(source, flags).flags


@pytest.mark.parametrize("module_name", LAZY_MODULES)
def test_a_name_that_is_not_a_lazy_pattern_is_still_an_attribute_error(
    module_name: str,
) -> None:
    module = importlib.import_module(module_name)
    missing = "_no_such_pattern_name"

    with pytest.raises(AttributeError):
        getattr(module, missing)


def test_a_table_compiles_a_name_once_and_only_when_asked() -> None:
    table = LazyPatterns({"digits": (r"\d+", 0), "word": (r"\w+", re.IGNORECASE)})

    assert len(table) == 0
    first = table["digits"]
    assert table["digits"] is first
    assert list(table) == ["digits"]


def test_the_lookup_tries_each_table_in_turn() -> None:
    first = LazyPatterns({"a": (r"a", 0)})
    second = LazyPatterns({"b": (r"b", 0)})
    lookup = module_attribute_lookup(first, second)

    assert lookup("a") is first["a"]
    assert lookup("b") is second["b"]
    with pytest.raises(AttributeError):
        lookup("c")


def test_compiled_on_demand_keeps_its_flags_and_compiles_once() -> None:
    table = CompiledOnDemand(re.IGNORECASE)

    compiled = table[r"abc"]

    assert compiled.flags & re.IGNORECASE
    assert table[r"abc"] is compiled


def test_importing_the_engine_leaves_most_lazy_patterns_uncompiled() -> None:
    code = (
        "import importlib, pkgutil, sys\n"
        "import guard_core\n"
        "from guard_core.models import SecurityConfig\n"
        "from guard_core.utils import detect_penetration_attempt\n"
        "from guard_core._lazy_patterns import LazyPatterns\n"
        "total = compiled = 0\n"
        "for name, module in list(sys.modules.items()):\n"
        "    table = getattr(module, '__dict__', {}).get('_PATTERNS')\n"
        "    if name.startswith('guard_core') and isinstance(table, LazyPatterns):\n"
        "        total += len(table._definitions); compiled += len(table)\n"
        "print(total, compiled)\n"
    )

    result = subprocess.run(
        [sys.executable, "-W", "ignore", "-c", code],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    total, compiled = map(int, result.stdout.split())
    assert total > 100, result.stdout + result.stderr
    assert compiled <= total // 10, result.stdout + result.stderr
