import copy
import pickle
import subprocess
import sys
from pathlib import Path
from types import MappingProxyType

import pytest

from guard_core._security_config_batch import apply_config_batch
from guard_core._security_config_fields import RequestT
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

WsgiConfig = SecurityConfig[SyncGuardRequest]
AnyConfig = SecurityConfig | WsgiConfig


def _configs() -> list[AnyConfig]:
    return [
        SecurityConfig(enable_redis=False, rate_limit=7),
        WsgiConfig(enable_redis=False, rate_limit=7),
    ]


@pytest.mark.parametrize("config", _configs(), ids=["plain", "wsgi"])
def test_every_copy_keeps_the_class_and_every_field(config: AnyConfig) -> None:
    copies = [
        copy.copy(config),
        copy.deepcopy(config),
        config.model_copy(),
        config.model_copy(deep=True),
        pickle.loads(pickle.dumps(config)),
    ]
    for copied in copies:
        assert type(copied) is type(config)
        assert copied.model_dump() == config.model_dump()
        assert isinstance(copied.threat_ban_config, MappingProxyType)


def _batch_keeps_the_class_and_the_other_fields(
    config: SecurityConfig[RequestT],
) -> None:
    before = config.model_dump()
    apply_config_batch(config, {"rate_limit": 9})
    after = config.model_dump()
    assert after.pop("rate_limit") == 9
    assert before.pop("rate_limit") == 7
    assert after == before


def test_the_dynamic_rules_batch_path_keeps_the_class_and_the_other_fields() -> None:
    plain = SecurityConfig(enable_redis=False, rate_limit=7)
    wsgi = WsgiConfig(enable_redis=False, rate_limit=7)
    _batch_keeps_the_class_and_the_other_fields(plain)
    _batch_keeps_the_class_and_the_other_fields(wsgi)
    assert type(plain) is SecurityConfig
    assert type(wsgi) is WsgiConfig


def test_a_wsgi_config_pickled_here_loads_in_a_fresh_interpreter(
    tmp_path: Path,
) -> None:
    dump = tmp_path / "wsgi.pkl"
    dump.write_bytes(pickle.dumps(WsgiConfig(enable_redis=False, rate_limit=7)))
    script = (
        "import pickle, sys, guard_core\n"
        "config = pickle.load(open(sys.argv[1], 'rb'))\n"
        "print(type(config).__name__, config.rate_limit)\n"
    )
    result = subprocess.run(
        [sys.executable, "-W", "ignore", "-c", script, str(dump)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "SecurityConfig[SyncGuardRequest] 7"


def test_both_forms_list_the_same_fields_with_the_same_defaults() -> None:
    plain = SecurityConfig.model_fields
    wsgi = WsgiConfig.model_fields
    assert list(plain) == list(wsgi)
    assert {name: field.description for name, field in plain.items()} == {
        name: field.description for name, field in wsgi.items()
    }
    assert {name: field.default for name, field in plain.items()} == {
        name: field.default for name, field in wsgi.items()
    }


def test_the_wsgi_form_is_a_security_config() -> None:
    assert issubclass(WsgiConfig, SecurityConfig)
    assert isinstance(WsgiConfig(enable_redis=False), SecurityConfig)
