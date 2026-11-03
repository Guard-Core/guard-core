import json
import subprocess
import sys
from typing import cast

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.events.composite_handler import CompositeAgentHandler
from guard_core.sync.core.events.event_types import EventFilter
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from tests.test_sync.conftest import SyncMockGuardRequest

_ORDERING_SCRIPT = """
import json
import sys

import guard_core

result = {}
result["guard_agent_absent_after_bare_import"] = "guard_agent" not in sys.modules

from guard_core import _pydantic_plugin_mute

result["mute_unapplied_after_bare_import"] = _pydantic_plugin_mute._applied is False

from guard_agent.models import EventBatch, SecurityEvent, SecurityMetric

from guard_core.models import SecurityConfig, SyncSecurityConfig

config = SyncSecurityConfig(enable_agent=True, agent_api_key="a" * 10)
config.to_agent_config()

result["mute_applied_after_to_agent_config"] = _pydantic_plugin_mute._applied is True

result["muted_after_to_agent_config"] = all(
    m.model_config.get("plugin_settings") == {"logfire": {"record": "off"}}
    for m in (SecurityEvent, SecurityMetric, EventBatch)
)

print(json.dumps(result))
"""


def test_bare_import_leaves_telemetry_unmuted_until_to_agent_config_runs() -> None:
    """`import guard_core` alone must not import guard-agent or apply the mute;
    only a telemetry entry point such as `SecurityConfig.to_agent_config()` may.

    The mute is observed through guard-core's own `_applied` flag rather than
    through the models' `plugin_settings`, because guard-agent 2.8.0 and later
    apply the identical mute from their own `__init__`, so importing the models
    in order to inspect them would itself mute them.
    """
    completed = subprocess.run(
        [sys.executable, "-c", _ORDERING_SCRIPT],
        capture_output=True,
        text=True,
        check=True,
    )
    payload = cast(dict[str, bool], json.loads(completed.stdout))
    assert payload == {
        "guard_agent_absent_after_bare_import": True,
        "mute_unapplied_after_bare_import": True,
        "mute_applied_after_to_agent_config": True,
        "muted_after_to_agent_config": True,
    }


def test_otel_only_config_mutes_telemetry_before_first_security_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`enable_otel=True` with no agent still wires a real telemetry-capable
    handler into the event bus; the mute must land before that handler's
    first `SecurityEvent` is constructed, not just before `import guard_core`."""
    from guard_agent.models import SecurityEvent

    from guard_core import _pydantic_plugin_mute

    monkeypatch.setattr(_pydantic_plugin_mute, "_applied", False)
    saved_plugin_settings = SecurityEvent.model_config.get("plugin_settings")
    SecurityEvent.model_config.pop("plugin_settings", None)
    SecurityEvent.model_rebuild(force=True)

    observed: dict[str, bool] = {}
    original_init = SecurityEvent.__init__

    def spy_init(self: SecurityEvent, **data: object) -> None:
        observed.setdefault(
            "muted_before_construction",
            SecurityEvent.model_config.get("plugin_settings")
            == {"logfire": {"record": "off"}},
        )
        original_init(self, **data)

    monkeypatch.setattr(SecurityEvent, "__init__", spy_init)

    try:
        config = SyncSecurityConfig(enable_otel=True)
        initializer = HandlerInitializer(config=config, agent_handler=None)
        monkeypatch.setattr(
            initializer,
            "build_composite_handler",
            lambda: CompositeAgentHandler(
                [], event_filter=EventFilter(), enricher=None
            ),
        )

        initializer.initialize_agent_integrations()
        bus = initializer.build_event_bus()

        bus.send_middleware_event(
            event_type="ip_blocked",
            request=SyncMockGuardRequest(),
            action_taken="blocked",
            reason="test",
        )
    finally:
        if saved_plugin_settings is not None:
            SecurityEvent.model_config["plugin_settings"] = saved_plugin_settings
            SecurityEvent.model_rebuild(force=True)

    assert observed == {"muted_before_construction": True}
