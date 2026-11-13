import ast
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import guard_core
import guard_core._misconfiguration_kinds as registry
from tests.warning_site_registry import EXCLUSION_REASONS, KINDED, SITES

_LOG_METHODS = frozenset({"warning", "warn", "error", "exception", "critical", "log"})
_KIND_EXTRAS = frozenset(
    {"problem_log_extra", "kinds_log_extra", "listed_problems_log_extra"}
)
_KIND_CONSTANTS = frozenset(name for name in vars(registry) if name.startswith("K_"))
# re.error and zlib.error are exception classes, not logger methods.
_EXCEPTION_MODULES = frozenset({"re", "zlib"})
_ROOT = Path(guard_core.__file__).resolve().parent
_Key = tuple[str, str]


@dataclass(frozen=True)
class Site:
    key: _Key
    line: int
    kinded: bool
    kind_arguments: tuple[str, ...]


def _called_name(node: ast.expr) -> str | None:
    return node.id if isinstance(node, ast.Name) else None


def _kind_extra(call: ast.Call) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == "extra":
            return keyword.value
    return None


def _kind_arguments(
    call: ast.Call, problem_names: set[str]
) -> tuple[bool, tuple[str, ...]]:
    extra = _kind_extra(call)
    if isinstance(extra, ast.Call) and _called_name(extra.func) in _KIND_EXTRAS:
        names = tuple(a.id for a in extra.args[:1] if isinstance(a, ast.Name))
        return True, names if _called_name(extra.func) == "kinds_log_extra" else ()
    if isinstance(extra, ast.Dict):
        keys = [k.value for k in extra.keys if isinstance(k, ast.Constant)]
        return "problems" in keys, ()
    first = call.args[0] if call.args else None
    warns_a_problem = (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "warn"
        and (
            (isinstance(first, ast.Call) and _called_name(first.func) == "Problem")
            or (isinstance(first, ast.Name) and first.id in problem_names)
        )
    )
    return warns_a_problem, ()


def _log_method_called(call: ast.Call) -> bool:
    """A call of a logger method, also when the level is picked by a conditional:
    ``(logger.warning if cond else logger.debug)(...)``."""
    callees = [call.func]
    if isinstance(call.func, ast.IfExp):
        callees = [call.func.body, call.func.orelse]
    return any(
        isinstance(callee, ast.Attribute) and callee.attr in _LOG_METHODS
        for callee in callees
    )


class _SiteWalker(ast.NodeVisitor):
    def __init__(self, relpath: str) -> None:
        self._relpath = relpath
        self._scope: list[str] = []
        self._problem_names: set[str] = set()
        self.sites: list[Site] = []

    def _enter(
        self, node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        outer_problems, self._problem_names = self._problem_names, set()
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()
        self._problem_names = outer_problems

    visit_ClassDef = visit_FunctionDef = visit_AsyncFunctionDef = _enter

    def visit_Assign(self, node: ast.Assign) -> None:
        value = node.value
        if isinstance(value, ast.Call) and _called_name(value.func) == "Problem":
            self._problem_names.update(
                t.id for t in node.targets if isinstance(t, ast.Name)
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if _log_method_called(node):
            kinded, arguments = _kind_arguments(node, self._problem_names)
            key = (self._relpath, ".".join(self._scope) or "<module>")
            self.sites.append(Site(key, node.lineno, kinded, arguments))
        self.generic_visit(node)


def _sites_of(tree_root: Path, skipped: frozenset[str]) -> list[Site]:
    sites: list[Site] = []
    for path in sorted(tree_root.rglob("*.py")):
        relative = path.relative_to(tree_root)
        if relative.parts[0] in skipped:
            continue
        walker = _SiteWalker(relative.as_posix())
        walker.visit(ast.parse(path.read_text(encoding="utf-8")))
        sites.extend(walker.sites)
    return sites


def _async_sites() -> list[Site]:
    return _sites_of(_ROOT, frozenset({"sync"}))


def _sync_sites() -> list[Site]:
    return _sites_of(_ROOT / "sync", frozenset())


def _by_function(sites: list[Site]) -> dict[_Key, list[Site]]:
    grouped: dict[_Key, list[Site]] = defaultdict(list)
    for site in sorted(sites, key=lambda s: (s.key, s.line)):
        grouped[site.key].append(site)
    return grouped


def _dispositions(sites: list[Site]) -> dict[_Key, tuple[bool, ...]]:
    return {
        key: tuple(s.kinded for s in found)
        for key, found in _by_function(sites).items()
    }


def test_every_logging_and_warning_site_of_either_tree_is_registered() -> None:
    for tree, sites in (("async", _async_sites()), ("sync", _sync_sites())):
        found = _by_function(sites)
        unregistered = sorted(set(found) - set(SITES))
        wrong_count = sorted(
            key for key in found if key in SITES and len(found[key]) != len(SITES[key])
        )
        assert unregistered == [], f"{tree} tree: sites missing from the registry"
        assert wrong_count == [], f"{tree} tree: a function gained or lost a site"


def test_every_registered_function_still_has_its_sites() -> None:
    existing = set(_by_function(_async_sites())) | set(_by_function(_sync_sites()))

    assert sorted(set(SITES) - existing) == []


def test_every_registered_disposition_is_kinded_or_a_written_reason() -> None:
    allowed = {KINDED, *EXCLUSION_REASONS}
    used = {disposition for found in SITES.values() for disposition in found}

    assert used <= allowed
    assert used - {KINDED} == set(EXCLUSION_REASONS), "a reason no site uses"
    assert all(len(reason) >= 20 for reason in EXCLUSION_REASONS.values())


def test_a_site_carries_a_kind_exactly_where_the_registry_says_kinded() -> None:
    for tree, sites in (("async", _async_sites()), ("sync", _sync_sites())):
        for key, kinded in _dispositions(sites).items():
            expected = tuple(d == KINDED for d in SITES[key])
            assert kinded == expected, f"{tree} tree {key}: kinded sites differ"


def test_the_two_trees_have_the_same_sites_where_both_have_the_function() -> None:
    asynchronous = _dispositions(_async_sites())
    synchronous = _dispositions(_sync_sites())

    assert [
        key
        for key in asynchronous.keys() & synchronous.keys()
        if asynchronous[key] != synchronous[key]
    ] == []


def test_every_kinded_site_names_a_registered_kind_constant() -> None:
    named = {
        argument
        for site in _async_sites() + _sync_sites()
        for argument in site.kind_arguments
    }

    assert named
    assert named <= _KIND_CONSTANTS


def test_no_logging_method_is_reached_through_an_alias() -> None:
    aliased: list[str] = []
    for path in sorted(_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        called = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
        called |= {
            id(branch)
            for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.IfExp)
            for branch in (n.func.body, n.func.orelse)
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                flagged = (
                    node.attr in _LOG_METHODS
                    and _called_name(node.value) not in _EXCEPTION_MODULES
                    and id(node) not in called
                )
            elif isinstance(node, ast.Call):
                flagged = _called_name(node.func) == "getattr" and any(
                    isinstance(a, ast.Constant) and a.value in _LOG_METHODS
                    for a in node.args[1:2]
                )
            else:
                continue
            if flagged:
                aliased.append(f"{path.relative_to(_ROOT)}:{node.lineno}")

    assert aliased == []
