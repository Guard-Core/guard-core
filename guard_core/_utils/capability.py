from collections.abc import Iterable


def has_callable(value: object, name: str) -> bool:
    # A runtime_checkable Protocol isinstance looks members up with hasattr on 3.10
    # and 3.11 and with getattr_static from 3.12, which ignores what __getattr__ or
    # a Mock serves. The call site does a normal attribute lookup, so the check does
    # the same on every interpreter.
    return callable(getattr(value, name, None))


def has_callables(value: object, names: Iterable[str]) -> bool:
    return all(has_callable(value, name) for name in names)


def serves_attributes_dynamically(cls: type) -> bool:
    # Two instances of such a class can differ in what they provide, so a verdict
    # for one is not a verdict for the class.
    return (
        hasattr(cls, "__getattr__")
        or cls.__getattribute__ is not object.__getattribute__
    )
