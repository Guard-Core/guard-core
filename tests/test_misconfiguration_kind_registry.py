import ast
from pathlib import Path
from typing import TypeGuard

import guard_core._misconfiguration_kinds as registry
from guard_core._misconfiguration_kinds import ALL_KINDS, KINDS

_SOURCE = Path(registry.__file__).resolve().parent
_REPORT_CALLS = frozenset(
    {
        "report_misconfiguration",
        "_report_misconfiguration",
        "report_misconfigurations",
        "_report_misconfigurations",
    }
)
# A name, a list or a comprehension is checked by mypy: the reporters take Problem.
_TYPED_BY_MYPY = (ast.Name, ast.List, ast.ListComp)
_PRODUCERS = ("config_misconfigurations", "unreachable_ban_threshold_problems")
_CONSTANTS = {
    name: value
    for name, value in vars(registry).items()
    if name.startswith("K_") and isinstance(value, str)
}


def _async_tree_files() -> list[Path]:
    return [
        path
        for path in sorted(_SOURCE.rglob("*.py"))
        if "sync" not in path.relative_to(_SOURCE).parts
    ]


def _called_name(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    return func.attr if isinstance(func, ast.Attribute) else None


def _calls_named(names: frozenset[str]) -> list[tuple[Path, ast.Call]]:
    return [
        (path, node)
        for path in _async_tree_files()
        for node in ast.walk(ast.parse(path.read_text()))
        if isinstance(node, ast.Call) and _called_name(node) in names
    ]


def _is_problem_call(node: ast.AST) -> TypeGuard[ast.Call]:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Problem"
    )


def test_every_report_call_passes_a_problem_never_text() -> None:
    calls = _calls_named(_REPORT_CALLS)
    assert len(calls) >= 10
    for path, call in calls:
        name = _called_name(call) or ""
        argument = call.args[0 if name.startswith("_") else 1]
        produced_by_a_known_producer = (
            isinstance(argument, ast.Call) and _called_name(argument) in _PRODUCERS
        )
        assert (
            _is_problem_call(argument)
            or produced_by_a_known_producer
            or isinstance(argument, _TYPED_BY_MYPY)
        ), f"{path.name}:{call.lineno} passes {type(argument).__name__}, not a Problem"


def test_every_problem_is_built_with_a_registry_constant_and_never_joined_text() -> (
    None
):
    calls = [
        (path, node)
        for path in _async_tree_files()
        for node in ast.walk(ast.parse(path.read_text()))
        if _is_problem_call(node) and path.name != "_misconfiguration_kinds.py"
    ]
    assert len(calls) >= 45
    for path, call in calls:
        kinds = [k.value for k in call.keywords if k.arg == "kind"]
        assert len(kinds) == 1, f"{path.name}:{call.lineno} has no kind"
        kind = kinds[0]
        assert isinstance(kind, ast.Name) and (
            kind.id in _CONSTANTS or kind.id == "kind"
        ), f"{path.name}:{call.lineno} names its kind by a literal"
        first = call.args[0]
        assert not (
            isinstance(first, ast.Call)
            and isinstance(first.func, ast.Attribute)
            and first.func.attr == "join"
        ), f"{path.name}:{call.lineno} builds a Problem from a joined string"


def test_the_registry_and_the_code_name_the_same_kinds() -> None:
    referenced = {
        node.id
        for path in _async_tree_files()
        if path.name != "_misconfiguration_kinds.py"
        for node in ast.walk(ast.parse(path.read_text()))
        if isinstance(node, ast.Name) and node.id in _CONSTANTS
    }
    assert referenced == set(_CONSTANTS)
    assert {_CONSTANTS[name] for name in referenced} == ALL_KINDS == set(KINDS)
