import importlib
import importlib.util
import inspect
from pathlib import Path
from types import ModuleType
from typing import cast

import pytest

import guard_core
import guard_core.handlers
import guard_core.handlers.ratelimit_handler
import guard_core.sync
import guard_core.sync.handlers
import guard_core.sync.handlers.ratelimit_handler
import guard_core.utils

_HANDLERS_SUBMODULES = (
    "behavior_handler",
    "cloud_handler",
    "cloud_ip_stores",
    "cors_handler",
    "dynamic_rule_handler",
    "ipban_handler",
    "ipinfo_handler",
    "ratelimit_handler",
    "redis_handler",
    "security_headers_handler",
    "suspatterns_handler",
)

_GUARD_CORE_SUBMODULES = (
    "core",
    "decorators",
    "detection_engine",
    "detection_result",
    "exceptions",
    "handlers",
    "models",
    "protocols",
    "scripts",
    "sync",
    "utils",
)

_GUARD_CORE_SYNC_SUBMODULES = (
    "core",
    "decorators",
    "detection_engine",
    "detection_result",
    "handlers",
    "protocols",
    "scripts",
    "utils",
)


def _getattr_forcing_lazy_resolution(module: ModuleType, name: str) -> ModuleType:
    if name in vars(module):
        delattr(module, name)
    return cast(ModuleType, getattr(module, name))


@pytest.mark.parametrize("name", _HANDLERS_SUBMODULES)
def test_handlers_submodule_attribute_access_works(name: str) -> None:
    submodule = _getattr_forcing_lazy_resolution(guard_core.handlers, name)
    assert submodule.__name__ == f"{guard_core.handlers.__name__}.{name}"


def test_handlers_submodule_attribute_access_raises_for_absent_name() -> None:
    with pytest.raises(AttributeError):
        _ = guard_core.handlers.this_submodule_does_not_exist


@pytest.mark.parametrize("name", _GUARD_CORE_SUBMODULES)
def test_guard_core_submodule_attribute_access_works(name: str) -> None:
    submodule = _getattr_forcing_lazy_resolution(guard_core, name)
    assert submodule.__name__ == f"{guard_core.__name__}.{name}"


def test_guard_core_submodule_attribute_access_raises_for_absent_name() -> None:
    with pytest.raises(AttributeError):
        _ = guard_core.this_submodule_does_not_exist


@pytest.mark.parametrize("name", _GUARD_CORE_SYNC_SUBMODULES)
def test_guard_core_sync_submodule_attribute_access_works(name: str) -> None:
    submodule = _getattr_forcing_lazy_resolution(guard_core.sync, name)
    assert submodule.__name__ == f"{guard_core.sync.__name__}.{name}"


def test_guard_core_sync_submodule_attribute_access_raises_for_absent_name() -> None:
    with pytest.raises(AttributeError):
        _ = guard_core.sync.this_submodule_does_not_exist


@pytest.mark.parametrize("name", _HANDLERS_SUBMODULES)
def test_sync_handlers_submodule_attribute_access_works(name: str) -> None:
    submodule = _getattr_forcing_lazy_resolution(guard_core.sync.handlers, name)
    assert submodule.__name__ == f"{guard_core.sync.handlers.__name__}.{name}"


def test_sync_handlers_submodule_attribute_access_raises_for_absent_name() -> None:
    with pytest.raises(AttributeError):
        _ = guard_core.sync.handlers.this_submodule_does_not_exist


def test_every_handlers_all_name_importable_directly() -> None:
    for name in guard_core.handlers.__all__:
        module = importlib.import_module("guard_core.handlers")
        assert hasattr(module, name)


def test_every_handlers_all_name_resolves_via_getattr() -> None:
    for name in guard_core.handlers.__all__:
        assert getattr(guard_core.handlers, name) is not None


def test_every_handlers_all_name_appears_in_dir() -> None:
    listed = dir(guard_core.handlers)
    for name in guard_core.handlers.__all__:
        assert name in listed


def test_every_guard_core_all_name_importable_directly() -> None:
    for name in guard_core.__all__:
        module = importlib.import_module("guard_core")
        assert hasattr(module, name)


def test_every_guard_core_all_name_resolves_via_getattr() -> None:
    for name in guard_core.__all__:
        assert getattr(guard_core, name) is not None


def test_every_guard_core_all_name_appears_in_dir() -> None:
    listed = dir(guard_core)
    for name in guard_core.__all__:
        assert name in listed


def test_every_sync_handlers_all_name_importable_directly() -> None:
    for name in guard_core.sync.handlers.__all__:
        module = importlib.import_module("guard_core.sync.handlers")
        assert hasattr(module, name)


def test_every_sync_handlers_all_name_resolves_via_getattr() -> None:
    for name in guard_core.sync.handlers.__all__:
        assert getattr(guard_core.sync.handlers, name) is not None


def test_every_sync_handlers_all_name_appears_in_dir() -> None:
    listed = dir(guard_core.sync.handlers)
    for name in guard_core.sync.handlers.__all__:
        assert name in listed


def test_every_guard_core_sync_all_name_importable_directly() -> None:
    for name in guard_core.sync.__all__:
        module = importlib.import_module("guard_core.sync")
        assert hasattr(module, name)


def test_every_guard_core_sync_all_name_resolves_via_getattr() -> None:
    for name in guard_core.sync.__all__:
        assert getattr(guard_core.sync, name) is not None


def test_every_guard_core_sync_all_name_appears_in_dir() -> None:
    listed = dir(guard_core.sync)
    for name in guard_core.sync.__all__:
        assert name in listed


def test_unknown_attribute_raises_on_guard_core() -> None:
    with pytest.raises(AttributeError):
        guard_core.__getattr__("does_not_exist")


def test_unknown_attribute_raises_on_handlers() -> None:
    with pytest.raises(AttributeError):
        guard_core.handlers.__getattr__("does_not_exist")


def test_unknown_attribute_raises_on_sync() -> None:
    with pytest.raises(AttributeError):
        guard_core.sync.__getattr__("does_not_exist")


def test_unknown_attribute_raises_on_sync_handlers() -> None:
    with pytest.raises(AttributeError):
        guard_core.sync.handlers.__getattr__("does_not_exist")


def _find_unasync_script() -> Path:
    for candidate in Path(__file__).resolve().parents:
        script_path = candidate / "scripts" / "unasync.py"
        if script_path.is_file():
            return script_path
    raise FileNotFoundError("scripts/unasync.py not found above this test file")


def _load_unasync_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("unasync", _find_unasync_script())
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _shared_source_module_names() -> set[str]:
    unasync = _load_unasync_generator()
    skip_src: set[str] = unasync.__dict__["SKIP_SRC"]
    return {f"guard_core.{Path(filename).stem}" for filename in skip_src}


def test_every_guard_core_sync_all_name_sources_from_sync_or_shared_module() -> None:
    shared_modules = _shared_source_module_names()
    module_by_name = guard_core.sync._MODULE_BY_NAME
    for name in guard_core.sync.__all__:
        source_module = module_by_name[name]
        assert (
            source_module.startswith("guard_core.sync")
            or source_module in shared_modules
        ), f"{name} sources from {source_module}"


def _public_callables(obj: object) -> list[tuple[str, object]]:
    if inspect.isfunction(obj) or inspect.ismethod(obj):
        return [(obj.__name__, obj)]
    target = obj if inspect.isclass(obj) else type(obj)
    return [
        (member_name, member)
        for member_name, member in inspect.getmembers(
            target, predicate=inspect.isfunction
        )
        if not member_name.startswith("_")
    ]


def test_is_ip_allowed_and_check_ip_access_import_from_top_level() -> None:
    from guard_core import check_ip_access, is_ip_allowed

    assert is_ip_allowed is guard_core.utils.is_ip_allowed
    assert check_ip_access is guard_core.utils.check_ip_access


def test_is_ip_allowed_and_check_ip_access_listed_in_guard_core_all() -> None:
    assert "is_ip_allowed" in guard_core.__all__
    assert "check_ip_access" in guard_core.__all__


def test_is_ip_allowed_and_check_ip_access_appear_in_dir_guard_core() -> None:
    listed = dir(guard_core)
    assert "is_ip_allowed" in listed
    assert "check_ip_access" in listed


def test_check_rate_limit_by_ip_imports_from_top_level() -> None:
    from guard_core import check_rate_limit_by_ip

    assert (
        check_rate_limit_by_ip
        is guard_core.handlers.ratelimit_handler.check_rate_limit_by_ip
    )


def test_check_rate_limit_by_ip_listed_in_guard_core_all() -> None:
    assert "check_rate_limit_by_ip" in guard_core.__all__


def test_check_rate_limit_by_ip_appears_in_dir_guard_core() -> None:
    listed = dir(guard_core)
    assert "check_rate_limit_by_ip" in listed


def test_check_rate_limit_by_ip_imports_from_guard_core_sync_top_level() -> None:
    from guard_core.sync import check_rate_limit_by_ip

    assert (
        check_rate_limit_by_ip
        is guard_core.sync.handlers.ratelimit_handler.check_rate_limit_by_ip
    )


def test_check_rate_limit_by_ip_listed_in_guard_core_sync_all() -> None:
    assert "check_rate_limit_by_ip" in guard_core.sync.__all__


def test_check_rate_limit_by_ip_appears_in_dir_guard_core_sync() -> None:
    listed = dir(guard_core.sync)
    assert "check_rate_limit_by_ip" in listed


def test_guard_core_sync_exports_have_no_coroutine_function_callables() -> None:
    for name in guard_core.sync.__all__:
        obj = getattr(guard_core.sync, name)
        for member_name, member in _public_callables(obj):
            assert not inspect.iscoroutinefunction(member), (
                f"{name}.{member_name} is a coroutine function"
            )


def _mock_import_line(indent: str, names: str) -> str:
    """
    Assembles the line from fragments instead of a single literal because this
    file's own sync mirror is produced by scripts/unasync.py, and the function
    under test in these cases below scans raw file text for this exact phrase
    at the start of a line; a literal occurrence here would risk the generator
    silently stripping it out of the fixture data while producing that mirror.
    """
    return indent + "from unittest." + "mock import " + names


def test_dedupe_local_mock_imports_unchanged_without_module_import() -> None:
    """
    Covers the early-return branch: no module-level unittest.mock import line
    means there is nothing to compare a local import against, so the content
    passes through untouched even though it does contain a local import line.
    """
    unasync = _load_unasync_generator()
    content = "\n".join(
        [
            "def test_example():",
            _mock_import_line("    ", "MagicMock"),
            "    return MagicMock()",
            "",
        ]
    )
    result = unasync._dedupe_redundant_local_unittest_mock_imports(content)
    assert result == content


def test_dedupe_local_mock_imports_strips_a_subset_local_import() -> None:
    """
    A local import whose names are a subset of the module-level import's names
    is redundant and gets stripped from the generated sync mirror.
    """
    unasync = _load_unasync_generator()
    content = "\n".join(
        [
            _mock_import_line("", "MagicMock, patch"),
            "",
            "def test_example():",
            _mock_import_line("    ", "MagicMock"),
            "    return MagicMock()",
            "",
        ]
    )
    expected = "\n".join(
        [
            _mock_import_line("", "MagicMock, patch"),
            "",
            "def test_example():",
            "    return MagicMock()",
            "",
        ]
    )
    result = unasync._dedupe_redundant_local_unittest_mock_imports(content)
    assert result == expected


def test_dedupe_local_mock_imports_keeps_a_non_subset_local_import() -> None:
    """
    A local import naming something the module-level import does not is not
    redundant and must be kept; an earlier implementation stripped it anyway
    and broke three ipban test files, so this case is pinned deliberately.
    """
    unasync = _load_unasync_generator()
    content = "\n".join(
        [
            _mock_import_line("", "MagicMock"),
            "",
            "def test_example():",
            _mock_import_line("    ", "patch"),
            "    return patch",
            "",
        ]
    )
    result = unasync._dedupe_redundant_local_unittest_mock_imports(content)
    assert result == content


def test_dedupe_local_mock_imports_does_not_strip_a_mid_line_occurrence() -> None:
    """
    Pins the anchoring fix in scripts/unasync.py: the phrase can appear with
    leading whitespace on a line, such as inside a docstring, without sitting
    at the start of that line. The fixture is assembled from fragments, and
    the docstring line specifically is built to have other content ahead of
    the phrase, for the same reason documented on `_mock_import_line` above.
    """
    unasync = _load_unasync_generator()
    docstring_line = "    " + '"""Example usage: ' + _mock_import_line("", "patch")
    content = "\n".join(
        [
            _mock_import_line("", "MagicMock, patch"),
            "",
            "def test_example():",
            docstring_line,
            '    """',
            "    return MagicMock()",
            "",
        ]
    )
    result = unasync._dedupe_redundant_local_unittest_mock_imports(content)
    assert result == content


def test_endpoint_rate_limit_key_problems_imports_from_both_packages() -> None:
    from guard_core import endpoint_rate_limit_key_problems as async_form
    from guard_core.sync import endpoint_rate_limit_key_problems as sync_form

    assert async_form is not sync_form
    assert async_form({"/a/../b": (5, 60)}) == sync_form({"/a/../b": (5, 60)})
    assert "endpoint_rate_limit_key_problems" in guard_core.__all__
    assert "endpoint_rate_limit_key_problems" in guard_core.sync.__all__


def test_release_app_imports_from_both_packages() -> None:
    from guard_core import release_app as async_form
    from guard_core.sync import release_app as sync_form

    assert async_form is not sync_form
    assert "release_app" in guard_core.__all__
    assert "release_app" in guard_core.sync.__all__


@pytest.mark.parametrize(
    "package", ["guard_core.protocols", "guard_core.sync.protocols"]
)
def test_a_protocols_package_lists_every_lazy_name_before_it_is_loaded(
    package: str,
) -> None:
    module = importlib.import_module(package)

    assert set(module.__all__) <= set(dir(module))
    assert dir(module) == sorted(dir(module))
