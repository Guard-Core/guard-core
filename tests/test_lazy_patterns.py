import importlib
import pkgutil
import re
import subprocess
import sys
from collections.abc import Callable
from types import FrameType

import pytest

import guard_core
from guard_core._lazy_patterns import (
    CompiledOnDemand,
    LazyPatternMap,
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


@pytest.mark.parametrize("module_name", LAZY_MODULES)
def test_every_name_a_module_exports_still_resolves(module_name: str) -> None:
    module = importlib.import_module(module_name)

    unresolved = [
        name for name in getattr(module, "__all__", []) if not hasattr(module, name)
    ]

    assert unresolved == []


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


def test_a_pattern_map_compiles_its_values_on_read_and_lists_every_key() -> None:
    compiled = CompiledOnDemand(re.IGNORECASE)
    sources = {"one": "a+", "two": "b+"}
    patterns = LazyPatternMap(sources, compiled)

    assert len(compiled) == 0
    assert list(patterns) == ["one", "two"]
    assert len(patterns) == 2
    assert patterns["one"] is compiled["a+"]
    assert len(compiled) == 1
    sources["three"] = "c+"
    assert patterns["three"].search("CC")


@pytest.mark.parametrize("tree", ["guard_core", "guard_core.sync"])
def test_the_named_floor_keeps_its_token_pattern_names(tree: str) -> None:
    floor = importlib.import_module(f"{tree}.handlers._suspatterns_named_floor")

    cms = floor.CMS_TOKEN_PATTERN

    assert isinstance(cms, re.Pattern)
    assert cms is floor.NAMED_FLOOR_TOKEN_PATTERNS[floor.V440_CMS_ROW]
    assert set(floor.NAMED_FLOOR_TOKEN_PATTERNS) == set(floor.NAMED_FLOOR_TOKEN_SOURCES)
    missing = "_no_such_name"
    with pytest.raises(AttributeError):
        getattr(floor, missing)


_NAMES_AN_IMPORTING_MODULE_STILL_ANSWERS = (
    [
        ("handlers._suspatterns_shell_validators", name)
        for name in (
            "_BACKTICK_WINDOW_DELIMITER_RE",
            "_GLUED_BACKTICK_ASCII_WORD_RE",
            "_IMPLAUSIBLE_DOLLAR_PAREN_TOKEN_CHARS_RE",
            "_IMPLAUSIBLE_SQL_IDENTIFIER_CHARS_RE",
            "_SHELL_BRACE_SLICE_RE",
            "_SHELL_CHAIN_OPERATOR_RE",
            "_SHELL_KNOWN_COMMAND_RE",
            "_SHELL_PLAIN_IDENTIFIER_RE",
            "_SHELL_SELECTOR_STRING_RE",
            "_STRONG_SQL_KEYWORD_GLUED_PREFIX_RE",
            "_STRONG_SQL_KEYWORD_GLUED_SUFFIX_RE",
        )
    ]
    + [
        ("handlers._suspatterns_ldap_ipv4", name)
        for name in (
            "_LDAP_BREAKOUT_ATTACK_TOKEN_RE",
            "_LDAP_BREAKOUT_WILDCARD_CLAUSE_END_RE",
            "_LDAP_FILTER_EXPRESSION_STRUCTURE_RE",
            "_LDAP_PAREN_CONJUNCTION_FOLLOWUP_ATTR_RE",
            "_LDAP_PAREN_CONJUNCTION_FOLLOWUP_SYMBOL_RE",
        )
    ]
    + [
        ("handlers._suspatterns_windowed_finders", name)
        for name in (
            "_CMD_INJECTION_NEWLINE_SHELL_DASH_C_COMPILED_RE",
            "_DESERIALIZATION_PICKLE_GLOBAL_GENERIC_COMPILED_RE",
            "_QUOTE_SPLICE_CANDIDATE_COMPILED_RE",
            "_LDAP_NULL_BYTE_ATTR_COMPILED_RE",
            "_LDAP_NULL_BYTE_DECODED_ATTR_COMPILED_RE",
            "_LDAP_NULL_BYTE_DECODED_TAIL_RE",
            "_LDAP_NULL_BYTE_TAIL_RE",
            "_XML_XXE_PUBLIC_EXTERNAL_DTD_COMPILED_RE",
        )
    ]
    + [
        ("handlers._suspatterns_matchers", name)
        for name in (
            "_FILE_UPLOAD_BENIGN_TERMINAL_EXTENSION_RE",
            "_FILE_UPLOAD_DANGEROUS_EXTENSION_MARKER_RE",
            "_FILE_UPLOAD_DANGEROUS_TERMINAL_EXTENSION_RE",
            "_FILE_UPLOAD_DECODED_TRUNCATION_MARKER_RE",
            "_FILE_UPLOAD_DOUBLE_EXT_PREFIX_RE",
            "_FILE_UPLOAD_QUOTE_RE",
            "_FILE_UPLOAD_TRUNCATION_MARKER_RE",
            "_FILE_UPLOAD_VALIDATED_SPAN_RE",
            "_LDAP_NULL_BYTE_ATTR_CONTINUATION_CHAR_RE",
            "_LDAP_NULL_BYTE_ATTR_LEAD_CHAR_RE",
            "_LDAP_NULL_BYTE_VALUE_CHAR_RE",
        )
    ]
    + [
        ("handlers._suspatterns_named_floor", "_PLAIN_SOURCE_OR_MAP_PATH_END_RE"),
        ("_utils.pair_redaction", "_PERCENT_ESCAPE_RE"),
    ]
)


@pytest.mark.parametrize("tree", ["guard_core", "guard_core.sync"])
@pytest.mark.parametrize(("module", "name"), _NAMES_AN_IMPORTING_MODULE_STILL_ANSWERS)
def test_a_module_that_imported_a_pattern_still_answers_to_its_name(
    tree: str, module: str, name: str
) -> None:
    holder = importlib.import_module(f"{tree}.{module}")

    assert isinstance(getattr(holder, name), re.Pattern)


def _python_frames_while(action: Callable[[], None]) -> list[str]:
    frames: list[str] = []

    def profiler(frame: FrameType, event: str, arg: object) -> None:
        if event == "call" and frame.f_code is not action.__code__:
            frames.append(f"{frame.f_code.co_filename}:{frame.f_code.co_name}")

    sys.setprofile(profiler)
    try:
        action()
    finally:
        sys.setprofile(None)
    return frames


def test_a_probe_for_an_unknown_name_runs_no_python_code() -> None:
    lookup = module_attribute_lookup(LazyPatterns({"a": ("a", 0)}))

    def probe() -> None:
        try:
            lookup("__path__")
        except AttributeError:
            pass

    assert _python_frames_while(probe) == []


def test_a_module_probe_for_its_path_runs_no_lookup_code() -> None:
    module = importlib.import_module("guard_core.handlers.suspatterns_handler")

    def probe() -> None:
        try:
            module.__getattr__("__path__")
        except AttributeError:
            pass

    assert [f for f in _python_frames_while(probe) if "_lazy_patterns" in f] == []
