import ast
import importlib
import inspect
import pathlib
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

import guard_core.handlers as handlers_package
from tests.test_sync.conftest import (
    SINGLETON_RESET_HELPERS,
)

_HANDLERS_DIR = pathlib.Path(next(iter(handlers_package.__path__)))


def _defines_reset_global_state(source_path: pathlib.Path) -> bool:
    tree = ast.parse(source_path.read_text())
    return any(
        isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef)
        and node.name == "reset_global_state"
        for node in tree.body
    )


def _modules_defining_reset_global_state() -> list[str]:
    return sorted(
        f"guard_core.sync.handlers.{source_path.stem}"
        for source_path in _HANDLERS_DIR.glob("*.py")
        if source_path.name != "__init__.py"
        and _defines_reset_global_state(source_path)
    )


def _singleton_classes_in_module(module: object, module_name: str) -> list[type]:
    return [
        obj
        for obj in vars(module).values()
        if isinstance(obj, type)
        and obj.__module__ == module_name
        and hasattr(obj, "_instance")
    ]


def _handler_reference_attribute_names(instance: object) -> list[str]:
    return [
        name
        for name in vars(instance)
        if name == "redis_handler" or name.endswith(("_handler", "_manager"))
    ]


def _working_handler_reference_mock() -> MagicMock:
    def scan_iter(*_args: object, **_kwargs: object) -> object:
        no_keys: list[str] = []
        for key in no_keys:
            yield str(key)

    mock = MagicMock()
    mock.get_connection.return_value.__enter__.return_value.scan_iter = scan_iter
    return mock


def _instantiate_singleton(cls: type) -> object:
    try:
        return cls()
    except TypeError:
        pass
    try:
        from guard_core.models import SyncSecurityConfig

        return cls(SyncSecurityConfig())
    except TypeError:
        return cls("reset-completeness-test-token")


_RESET_GLOBAL_STATE_MODULES = _modules_defining_reset_global_state()


def test_at_least_one_singleton_module_exposes_reset_global_state() -> None:
    assert _RESET_GLOBAL_STATE_MODULES


@pytest.mark.parametrize("module_name", _RESET_GLOBAL_STATE_MODULES)
def test_reset_global_state_drops_every_handler_reference(
    module_name: str,
) -> None:
    module = importlib.import_module(module_name)
    reset_global_state = module.reset_global_state

    singleton_classes = _singleton_classes_in_module(module, module_name)
    assert singleton_classes, (
        f"{module_name} defines reset_global_state but no singleton class "
        "with an _instance attribute was found"
    )

    for cls in singleton_classes:
        instance = _instantiate_singleton(cls)
        attribute_names = _handler_reference_attribute_names(instance)
        assert attribute_names, (
            f"{module_name}.{cls.__name__} has no *_handler/*_manager attribute "
            "to exercise"
        )

        for name in attribute_names:
            setattr(instance, name, _working_handler_reference_mock())

        reset_global_state()

        live_instance = _instantiate_singleton(cls)
        for name in attribute_names:
            assert getattr(live_instance, name) is None, (
                f"{module_name}.{cls.__name__}.{name} survived reset_global_state()"
            )


def _public_handler_module_names() -> list[str]:
    return sorted(
        f"guard_core.sync.handlers.{source_path.stem}"
        for source_path in _HANDLERS_DIR.glob("*.py")
        if source_path.name != "__init__.py" and not source_path.stem.startswith("_")
    )


def _singleton_classes_with_instance_reset() -> list[tuple[str, type]]:
    found: list[tuple[str, type]] = []
    seen: set[type] = set()
    for module_name in _public_handler_module_names():
        module = importlib.import_module(module_name)
        for obj in vars(module).values():
            if (
                isinstance(obj, type)
                and obj.__module__ == module_name
                and hasattr(obj, "_instance")
                and callable(getattr(obj, "reset", None))
                and obj not in seen
            ):
                seen.add(obj)
                found.append((module_name, obj))
    return found


_INSTANCE_RESET_SINGLETONS = _singleton_classes_with_instance_reset()


def test_at_least_one_singleton_class_exposes_instance_reset() -> None:
    assert _INSTANCE_RESET_SINGLETONS


@pytest.mark.parametrize(
    ("module_name", "cls"),
    _INSTANCE_RESET_SINGLETONS,
    ids=[f"{m}.{c.__name__}" for m, c in _INSTANCE_RESET_SINGLETONS],
)
def test_instance_reset_drops_every_handler_reference(
    module_name: str, cls: type
) -> None:
    instance: Any = _instantiate_singleton(cls)
    attribute_names = _handler_reference_attribute_names(instance)
    assert attribute_names, (
        f"{module_name}.{cls.__name__} has no *_handler/*_manager attribute to exercise"
    )

    for name in attribute_names:
        setattr(instance, name, _working_handler_reference_mock())

    try:
        instance.reset()
    except Exception as exc:
        pytest.fail(
            f"{module_name}.{cls.__name__}.reset() raised {exc!r} while "
            f"exercising handler attributes {attribute_names}; reset() must "
            "tolerate being called with those attributes set"
        )

    if module_name in _RESET_GLOBAL_STATE_MODULES:
        return

    live_instance = cast(Any, cls)._instance
    for name in attribute_names:
        assert getattr(live_instance, name) is None, (
            f"{module_name}.{cls.__name__}.{name} survived instance reset()"
        )


def _all_handler_module_names() -> list[str]:
    return sorted(
        f"guard_core.sync.handlers.{source_path.stem}"
        for source_path in _HANDLERS_DIR.glob("*.py")
        if source_path.name != "__init__.py"
    )


def _singleton_classes_with_handler_reference() -> list[tuple[str, type]]:
    found: list[tuple[str, type]] = []
    seen: set[type] = set()
    for module_name in _all_handler_module_names():
        module = importlib.import_module(module_name)
        for obj in vars(module).values():
            if not (
                isinstance(obj, type)
                and obj.__module__ == module_name
                and hasattr(obj, "_instance")
                and obj not in seen
            ):
                continue
            seen.add(obj)
            try:
                instance = _instantiate_singleton(obj)
            except TypeError:
                continue
            if _handler_reference_attribute_names(instance):
                found.append((module_name, obj))
    return found


def _singleton_class_named(class_name: str) -> type:
    for _module_name, cls in _singleton_classes_with_handler_reference():
        if cls.__name__ == class_name:
            return cls
    pytest.fail(
        f"{class_name} is registered in SINGLETON_RESET_HELPERS but no singleton "
        "class with that name and a handler reference exists under guard_core.handlers"
    )


@pytest.mark.parametrize("class_name", sorted(SINGLETON_RESET_HELPERS))
def test_conftest_reset_helper_drops_every_handler_reference(
    class_name: str,
) -> None:
    cls = _singleton_class_named(class_name)
    instance = _instantiate_singleton(cls)
    attribute_names = _handler_reference_attribute_names(instance)
    assert attribute_names, (
        f"{class_name} has no *_handler/*_manager attribute to exercise"
    )

    for name in attribute_names:
        setattr(instance, name, _working_handler_reference_mock())

    outcome = SINGLETON_RESET_HELPERS[class_name]()
    if inspect.isawaitable(outcome):
        outcome = outcome

    for name in attribute_names:
        assert getattr(instance, name) is None, (
            f"{class_name}.{name} survived its conftest reset helper"
        )


def test_every_handler_reference_singleton_has_a_reset_path() -> None:
    orphaned = [
        f"{module_name}.{cls.__name__}"
        for module_name, cls in _singleton_classes_with_handler_reference()
        if module_name not in _RESET_GLOBAL_STATE_MODULES
        and not callable(getattr(cls, "reset", None))
        and cls.__name__ not in SINGLETON_RESET_HELPERS
    ]
    assert not orphaned, (
        f"singleton classes with a handler reference but no reset path: {orphaned}"
    )
