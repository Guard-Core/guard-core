import logging
from typing import Literal

_applied = False

TelemetryModelName = Literal["SecurityEvent", "SecurityMetric", "EventBatch"]


def _mute_pydantic_plugin_instrumentation() -> None:
    """Opt guard-agent's hot-path telemetry models out of pydantic plugin
    instrumentation (e.g. logfire.instrument_pydantic()).

    SecurityEvent/SecurityMetric are validated per request and EventBatch
    re-validates every buffered event on each flush, so an instrumented host
    app would otherwise emit a span per security event, hundreds of
    thousands a day under real traffic. plugin_settings is only read while
    building a model's validator, hence the forced rebuild.

    Idempotent: every guard-core path that can end up constructing one of
    these models calls this on its way there, so it may run once per
    SecurityConfig construction in a test suite. The applied flag is only
    set once all three models are confirmed muted (or guard-agent is
    confirmed absent), so a partial rebuild failure leaves it unset and the
    next call retries all three rather than silently leaving some of them
    permanently unmuted.
    """
    global _applied
    if _applied:
        return

    try:
        from guard_agent.models import EventBatch, SecurityEvent, SecurityMetric
    except ImportError:
        _applied = True
        return

    try:
        for model in (SecurityEvent, SecurityMetric, EventBatch):
            plugin_settings = model.model_config.get("plugin_settings") or {}
            plugin_settings["logfire"] = {"record": "off"}
            model.model_config["plugin_settings"] = plugin_settings
            model.model_rebuild(force=True)
    except Exception:
        logging.getLogger("guard_core").warning(
            "Could not opt guard-agent telemetry models out of pydantic "
            "plugin instrumentation",
            exc_info=True,
        )
    else:
        _applied = True


def get_telemetry_model(name: TelemetryModelName) -> type:
    """The supported way for guard-core to obtain a guard-agent telemetry
    model class. Always mutes pydantic plugin instrumentation first, so a
    caller using this accessor cannot construct
    SecurityEvent/SecurityMetric/EventBatch ahead of the mute.
    `tests/test_telemetry_model_access.py` is a lint, not a proof: it rejects
    the known ways of reaching `guard_agent` directly (plain import, aliased
    import, submodule import plus attribute access, and the
    `importlib.import_module`/`__import__` indirection builtins) from any
    module outside this one and `models.py`. A dynamically constructed
    module name would not be caught.
    """
    _mute_pydantic_plugin_instrumentation()
    import guard_agent

    model = getattr(guard_agent, name)
    if not isinstance(model, type):
        raise TypeError(f"guard_agent.{name} is not a class")
    return model
