import ast
import sys
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

import guard_core
from guard_core.models import SyncSecurityConfig
from tests.test_sync.conftest import (
    _GUARD_AGENT_FINDER_ATTR,
    _calling_module_name,
    _guard_agent_import_is_allowed,
    _GuardAgentImportFinder,
    _is_guard_core_module,
    _unmuted_guard_agent_telemetry_models,
)

PACKAGE_ROOT = Path(guard_core.__file__).resolve().parent
_CONFTEST_MODULE = sys.modules[_GuardAgentImportFinder.__module__]
ALLOWED_MODULES = frozenset(
    {
        PACKAGE_ROOT / "_pydantic_plugin_mute.py",
        PACKAGE_ROOT / "models.py",
    }
)
INDIRECTION_CALL_NAMES = frozenset({"__import__", "import_module"})


def _is_type_checking_guard(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _names_guard_agent(dotted_name: str | None) -> bool:
    return dotted_name is not None and (
        dotted_name == "guard_agent" or dotted_name.startswith("guard_agent.")
    )


def _indirection_call_target(node: ast.Call) -> str | None:
    func = node.func
    is_indirection_call = (
        isinstance(func, ast.Name) and func.id in INDIRECTION_CALL_NAMES
    ) or (isinstance(func, ast.Attribute) and func.attr == "import_module")
    if not is_indirection_call:
        return None
    if not node.args or not isinstance(node.args[0], ast.Constant):
        return None
    value = node.args[0].value
    return value if isinstance(value, str) else None


def _runtime_guard_agent_references(source: str, label: str) -> list[str]:
    tree = ast.parse(source, filename=label)
    violations: list[str] = []

    def visit(node: ast.AST) -> None:
        if isinstance(node, ast.If) and _is_type_checking_guard(node.test):
            for sibling in node.orelse:
                visit(sibling)
            return
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _names_guard_agent(alias.name):
                    violations.append(f"{label}:{node.lineno} imports {alias.name}")
        elif isinstance(node, ast.ImportFrom) and _names_guard_agent(node.module):
            violations.append(f"{label}:{node.lineno} imports from {node.module}")
        elif isinstance(node, ast.Call):
            target = _indirection_call_target(node)
            if target is not None and _names_guard_agent(target):
                violations.append(
                    f"{label}:{node.lineno} calls {ast.unparse(node.func)}({target!r})"
                )
        for child in ast.iter_child_nodes(node):
            visit(child)

    visit(tree)
    return violations


def _guard_core_source_files() -> list[Path]:
    return [
        path
        for path in sorted(PACKAGE_ROOT.rglob("*.py"))
        if path not in ALLOWED_MODULES
        and "sync" not in path.relative_to(PACKAGE_ROOT).parts
    ]


def test_no_module_outside_the_allowlist_uses_a_known_guard_agent_import_shape() -> (
    None
):
    """`guard_core._pydantic_plugin_mute.get_telemetry_model` is the supported
    way to reach a guard-agent telemetry model. This test rejects the import
    shapes anyone has actually used to reach `guard_agent` directly -- a plain
    import, an aliased import, a submodule import followed by attribute
    access, and the `importlib.import_module`/`__import__` indirection
    builtins -- for every module outside the two-file allowlist.

    It cannot catch a dynamically constructed module name (built from string
    concatenation, a variable, or anything else a static scan cannot resolve
    to a literal), and it only sees source that exists on disk, not source a
    coverage run actually executes. This is a lint on the known shapes at edit
    time, not a proof.

    `_GuardAgentImportFinder` in `tests/conftest.py` (exercised below and
    installed for the whole test session) is not that proof either: `sys.
    meta_path` is consulted only on a `sys.modules` cache miss, and the
    allowlisted mute module is normally the first thing in a session to
    import `guard_agent` legitimately, so the finder only reliably catches
    the *first* importer of `guard_agent` in a session -- every import after
    that, dynamic or not, is served from the cache and invisible to it.

    The check that actually proves the property users depend on --
    `SecurityEvent`/`SecurityMetric`/`EventBatch` end up muted whenever
    `guard_agent` was imported at all, regardless of how -- is the
    `pytest_sessionfinish` assertion in `tests/conftest.py`, backed by
    `_unmuted_guard_agent_telemetry_models` (exercised directly below). It
    reads the models out of `sys.modules` instead of importing them, so it
    cannot itself cause the import it is testing for. All three checks are
    complementary: the AST scan catches an unexercised bypass this session's
    coverage never runs through, the finder still names a first-time
    offender when one shows up, and the outcome assertion is the one whose
    pass or fail actually tracks whether a user's telemetry models ended up
    muted."""
    violations = [
        violation
        for path in _guard_core_source_files()
        for violation in _runtime_guard_agent_references(path.read_text(), str(path))
    ]
    assert violations == []


def test_type_checking_guarded_guard_agent_import_is_not_flagged() -> None:
    """A `guard_agent` import that only exists for type checkers, never at
    runtime, is not a bypass and must not be flagged."""
    source = (
        "from typing import TYPE_CHECKING\n\n"
        "if TYPE_CHECKING:\n"
        "    from guard_agent import AgentConfig\n"
    )
    assert _runtime_guard_agent_references(source, "<type-checking>") == []


def test_scanner_catches_every_synthetic_guard_agent_bypass_shape() -> None:
    """Each shape reaches `guard_agent` at runtime without a plain
    `from guard_agent import SecurityEvent`; the scanner must flag all six."""
    bypass_shapes = {
        "bare attribute access": "import guard_agent\n\nguard_agent.SecurityEvent()\n",
        "getattr indirection": (
            "import guard_agent\n\ngetattr(guard_agent, 'SecurityEvent')()\n"
        ),
        "submodule import then attribute access": (
            "from guard_agent import models\n\nmodels.SecurityEvent()\n"
        ),
        "aliased import": "import guard_agent as ga\n\nga.SecurityEvent()\n",
        "importlib.import_module indirection": (
            "import importlib\n\nimportlib.import_module('guard_agent')\n"
        ),
        "dunder-import indirection": "__import__('guard_agent')\n",
    }
    for label, source in bypass_shapes.items():
        assert _runtime_guard_agent_references(source, label), label


def test_is_guard_core_module() -> None:
    assert _is_guard_core_module("guard_core") is True
    assert _is_guard_core_module("guard_core.models") is True
    assert _is_guard_core_module("guard_core.decorators.base") is True
    assert _is_guard_core_module("guard_agent") is False
    assert _is_guard_core_module("tests.test_telemetry_model_access") is False
    assert _is_guard_core_module(None) is False


def test_guard_agent_import_is_allowed() -> None:
    assert _guard_agent_import_is_allowed(
        "guard_core._pydantic_plugin_mute", "guard_agent"
    )
    assert _guard_agent_import_is_allowed(
        "guard_core._pydantic_plugin_mute", "guard_agent.models"
    )
    assert _guard_agent_import_is_allowed("guard_core.models", "guard_agent")
    assert not _guard_agent_import_is_allowed("guard_core.models", "guard_agent.models")
    assert not _guard_agent_import_is_allowed(
        "guard_core.decorators.base", "guard_agent"
    )


def test_calling_module_name_returns_none_for_a_none_frame() -> None:
    assert _calling_module_name(None) is None


def test_calling_module_name_resolves_the_immediate_caller() -> None:
    assert _calling_module_name(sys._getframe(0)) == __name__


def test_finder_ignores_imports_that_are_not_guard_agent() -> None:
    finder = _GuardAgentImportFinder()

    assert finder.find_spec("json", None) is None
    assert finder.find_spec("guard_agent_lookalike", None) is None
    assert finder.violations == []


def test_finder_records_a_violation_for_a_disallowed_guard_core_caller() -> None:
    finder = _GuardAgentImportFinder()

    with patch.object(
        _CONFTEST_MODULE,
        "_calling_module_name",
        return_value="guard_core.decorators.base",
    ):
        assert finder.find_spec("guard_agent", None) is None
        assert finder.find_spec("guard_agent.models", None) is None

    assert finder.violations == [
        "guard_core.decorators.base imports guard_agent",
        "guard_core.decorators.base imports guard_agent.models",
    ]


def test_finder_ignores_a_non_guard_core_caller() -> None:
    finder = _GuardAgentImportFinder()

    with patch.object(
        _CONFTEST_MODULE,
        "_calling_module_name",
        return_value="tests.test_agent.test_models_agent_integration",
    ):
        assert finder.find_spec("guard_agent", None) is None

    assert finder.violations == []


def test_finder_allows_the_mute_module_for_any_guard_agent_submodule() -> None:
    finder = _GuardAgentImportFinder()

    with patch.object(
        _CONFTEST_MODULE,
        "_calling_module_name",
        return_value="guard_core._pydantic_plugin_mute",
    ):
        assert finder.find_spec("guard_agent", None) is None
        assert finder.find_spec("guard_agent.models", None) is None

    assert finder.violations == []


def test_finder_allows_models_only_for_the_bare_guard_agent_package() -> None:
    finder = _GuardAgentImportFinder()

    with patch.object(
        _CONFTEST_MODULE, "_calling_module_name", return_value="guard_core.models"
    ):
        assert finder.find_spec("guard_agent", None) is None
        assert finder.find_spec("guard_agent.models", None) is None

    assert finder.violations == ["guard_core.models imports guard_agent.models"]


@contextmanager
def _isolated_import_finder() -> Generator[_GuardAgentImportFinder, None, None]:
    session_finder = getattr(sys, _GUARD_AGENT_FINDER_ATTR, None)
    if session_finder is not None and session_finder in sys.meta_path:
        sys.meta_path.remove(session_finder)
    original_guard_agent = sys.modules.pop("guard_agent", None)
    finder = _GuardAgentImportFinder()
    sys.meta_path.insert(0, finder)
    try:
        yield finder
    finally:
        sys.meta_path.remove(finder)
        if original_guard_agent is not None:
            sys.modules["guard_agent"] = original_guard_agent
        else:
            sys.modules.pop("guard_agent", None)
        if session_finder is not None:
            sys.meta_path.insert(0, session_finder)


def test_finder_allows_to_agent_config_through_real_import_machinery() -> None:
    with _isolated_import_finder() as finder:
        config = SyncSecurityConfig(enable_agent=True, agent_api_key="test-key")
        config.to_agent_config()

    assert finder.violations == []


def test_finder_catches_a_disallowed_caller_through_real_import_machinery() -> None:
    with _isolated_import_finder() as finder:
        exec(
            compile("import guard_agent\n", "<fake-bypass>", "exec"),
            {"__name__": "guard_core._test_fake_bypass"},
        )

    assert finder.violations == ["guard_core._test_fake_bypass imports guard_agent"]


def _fake_guard_agent_module(
    plugin_settings_by_model: dict[str, dict[str, Any] | None],
) -> ModuleType:
    module = ModuleType("guard_agent")
    for name, plugin_settings in plugin_settings_by_model.items():
        setattr(
            module,
            name,
            SimpleNamespace(model_config={"plugin_settings": plugin_settings}),
        )
    return module


def test_unmuted_guard_agent_telemetry_models_is_empty_when_guard_agent_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delitem(sys.modules, "guard_agent", raising=False)

    assert _unmuted_guard_agent_telemetry_models() == []


def test_unmuted_guard_agent_telemetry_models_is_empty_when_all_three_are_muted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    muted = {"logfire": {"record": "off"}}
    fake_guard_agent = _fake_guard_agent_module(
        {"SecurityEvent": muted, "SecurityMetric": muted, "EventBatch": muted}
    )
    monkeypatch.setitem(sys.modules, "guard_agent", fake_guard_agent)

    assert _unmuted_guard_agent_telemetry_models() == []


def test_unmuted_guard_agent_telemetry_models_names_every_unmuted_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_guard_agent = _fake_guard_agent_module(
        {
            "SecurityEvent": None,
            "SecurityMetric": {"logfire": {"record": "all"}},
            "EventBatch": {"logfire": {"record": "off"}},
        }
    )
    monkeypatch.setitem(sys.modules, "guard_agent", fake_guard_agent)

    assert _unmuted_guard_agent_telemetry_models() == [
        "SecurityEvent",
        "SecurityMetric",
    ]
