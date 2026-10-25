import ast
from pathlib import Path

_PACKAGE = Path(__file__).resolve().parent.parent / "guard_core"
_REDACTORS = frozenset(
    {
        "_redact_pattern_source",
        "_redact_pattern_source_of_app",
        "_redact_pattern_list",
        "_redact_rejected_patterns",
    }
)
_LOG_METHODS = frozenset({"debug", "info", "warning", "error", "critical", "exception"})
_PATTERN_NAME_FRAGMENTS = ("pattern", "user_agents", "suspicious_patterns")

ALLOWED_UNREDACTED_SITES: dict[str, str] = {}


def _is_pattern_name(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        ident = node.id.lower()
    elif isinstance(node, ast.Attribute):
        ident = node.attr.lower()
    else:
        return False
    return any(fragment in ident for fragment in _PATTERN_NAME_FRAGMENTS)


def _is_redactor_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _REDACTORS
    )


def _unredacted_pattern_refs(node: ast.AST) -> list[ast.AST]:
    found: list[ast.AST] = []
    stack: list[ast.AST] = [node]
    while stack:
        current = stack.pop()
        if _is_redactor_call(current):
            continue
        if _is_pattern_name(current):
            found.append(current)
            continue
        stack.extend(ast.iter_child_nodes(current))
    return found


def _is_log_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in _LOG_METHODS:
        base = func.value
        return (isinstance(base, ast.Name) and base.id == "logger") or (
            isinstance(base, ast.Attribute) and base.attr == "logger"
        )
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "warn"
        and isinstance(func.value, ast.Name)
        and func.value.id == "warnings"
    )


def _message_nodes(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.Call) and _is_log_call(node):
        return [*node.args, *(kw.value for kw in node.keywords)]
    if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
        return list(node.exc.args)
    return []


def _enclosing_function_names(tree: ast.Module) -> dict[int, str]:
    names: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for line in range(node.lineno, (node.end_lineno or node.lineno) + 1):
                names.setdefault(line, node.name)
    return names


def _unredacted_sites() -> list[str]:
    sites: list[str] = []
    for path in sorted(_PACKAGE.rglob("*.py")):
        if "/sync/" in path.as_posix() or "/.agents/" in path.as_posix():
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        functions = _enclosing_function_names(tree)
        rel = path.relative_to(_PACKAGE).as_posix()
        for node in ast.walk(tree):
            for message in _message_nodes(node):
                if not _unredacted_pattern_refs(message):
                    continue
                line = getattr(node, "lineno", 0)
                site = f"{rel}:{functions.get(line, '<module>')}"
                if site not in ALLOWED_UNREDACTED_SITES:
                    sites.append(f"{site} (line {line})")
    return sites


def test_every_pattern_interpolated_into_a_log_or_exception_is_redacted() -> None:
    assert _unredacted_sites() == []


def test_allowed_unredacted_sites_still_exist() -> None:
    present = set()
    for path in sorted(_PACKAGE.rglob("*.py")):
        if "/sync/" in path.as_posix():
            continue
        rel = path.relative_to(_PACKAGE).as_posix()
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                present.add(f"{rel}:{node.name}")
    stale = sorted(site for site in ALLOWED_UNREDACTED_SITES if site not in present)
    assert stale == []
