import importlib.util
from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guard_core.sync.core.events.enricher import EnrichmentContext, EventEnricher
    from guard_core.sync.core.events.metrics import MetricsCollector
    from guard_core.sync.core.events.middleware_events import SecurityEventBus

__all__ = [
    "SecurityEventBus",
    "MetricsCollector",
    "EventEnricher",
    "EnrichmentContext",
]

_MODULE_BY_NAME: dict[str, str] = {
    "SecurityEventBus": "guard_core.sync.core.events.middleware_events",
    "MetricsCollector": "guard_core.sync.core.events.metrics",
    "EventEnricher": "guard_core.sync.core.events.enricher",
    "EnrichmentContext": "guard_core.sync.core.events.enricher",
}


def __getattr__(name: str) -> object:
    module_name = _MODULE_BY_NAME.get(name)
    if module_name is not None:
        value = getattr(import_module(module_name), name)
        globals()[name] = value
        return value

    submodule_name = f"{__name__}.{name}"
    if importlib.util.find_spec(submodule_name) is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    submodule = import_module(submodule_name)
    globals()[name] = submodule
    return submodule


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
