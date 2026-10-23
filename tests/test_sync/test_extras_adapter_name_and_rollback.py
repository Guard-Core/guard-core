import pytest

from guard_core import _config_capabilities
from guard_core._config_capabilities import install_hint, register_adapter
from guard_core.models import SecurityConfig


def test_the_registered_adapter_is_named_in_the_install_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_config_capabilities, "_ADAPTER_FOR_MESSAGES", None)
    assert install_hint("redis") == "pip install guard-core[redis]"
    register_adapter("example-guard")
    assert (
        install_hint("redis")
        == "pip install guard-core[redis] (or example-guard[redis])"
    )


def test_a_refused_assignment_leaves_the_config_exactly_as_it_was(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(enable_redis=False, redis_url="redis://configured:6379")
    before_dict = dict(config.__dict__)
    before_fields_set = set(config.__pydantic_fields_set__)
    monkeypatch.setattr(
        "guard_core._config_capabilities._extra_installed", lambda *names: False
    )
    with pytest.raises(ValueError, match="redis"):
        config.enable_redis = True
    assert dict(config.__dict__) == before_dict
    assert set(config.__pydantic_fields_set__) == before_fields_set
    assert config.enable_redis is False
