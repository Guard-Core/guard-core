import multiprocessing
import os
import pickle
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import guard_core
from guard_core import models
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

REPO_ROOT = Path(guard_core.__file__).resolve().parent.parent
# What `from guard_core.models import *` exported at 7025a112, plus the six names
# the landing-6e-stack10 refactor imports into the module (LEDGER 6.523).
_STAR_NAMES_AT_7025A112 = [
    "ALL_DETECTION_CATEGORIES",
    "AgentPackageNotInstalledError",
    "BehaviorRuleConfig",
    "ClassVar",
    "CloudIpStoreFactory",
    "CloudIpStoreProtocol",
    "CloudProvider",
    "ConfigDict",
    "DynamicRules",
    "GeoIPHandler",
    "GuardRequest",
    "GuardResponse",
    "Mapping",
    "MappingProxyType",
    "ModelWrapValidatorHandler",
    "Path",
    "PrivateAttr",
    "RequestT",
    "SecurityConfig",
    "SecurityConfig[SyncGuardRequest]",
    "Self",
    "SyncGuardRequest",
    "SyncSecurityConfig",
    "TYPE_CHECKING",
    "ThreatBanConfig",
    "VALID_BYPASS_CHECKS",
    "VALID_CLOUD_PROVIDERS",
    "ValidationInfo",
    "changed_copy_fields",
    "cloud_blocking_enabled",
    "contextvars",
    "deepcopy",
    "difflib",
    "field_validator",
    "logger",
    "logging",
    "misconfigurations_now",
    "model_validator",
    "report_config_misconfigurations",
    "require_agent_config",
    "require_cross_field_rules",
    "require_field_constraints",
    "return_pattern_requires_response_body",
    "signal_changed_defaults",
    "warn_agent_endpoint_in_clear",
    "warn_redis_prefix_left_default",
]


def _fresh(code: str) -> str:
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}"
    return subprocess.run(
        [sys.executable, "-W", "ignore", "-c", code],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    ).stdout.strip()


_UNUSABLE_NAME = "SecurityConfig[SyncGuardRequest]"
_EXPECTED_STAR_NAMES = [n for n in _STAR_NAMES_AT_7025A112 if n != _UNUSABLE_NAME]


def test_a_star_import_exports_what_it_exported_at_7025a112() -> None:
    namespace: dict[str, object] = {}
    exec("from guard_core.models import *", namespace)
    namespace.pop("__builtins__")

    assert sorted(namespace) == _EXPECTED_STAR_NAMES
    assert namespace["SyncSecurityConfig"] is models.SyncSecurityConfig
    assert namespace["SyncGuardRequest"] is SyncGuardRequest
    assert getattr(models, _UNUSABLE_NAME) is models.SyncSecurityConfig


def test_all_is_every_public_identifier_of_a_fresh_module() -> None:
    code = (
        "import guard_core.models as m\n"
        "m.SyncSecurityConfig\n"
        "print(sorted(n for n in vars(m) if n.isidentifier() "
        "and not n.startswith('_')))\n"
    )
    in_a_fresh_module = eval(_fresh(code))

    assert sorted(models.__all__) == in_a_fresh_module, (
        "guard_core.models.__all__ must list every public name of the module "
        "(a star import exported them before __all__ existed): add the new public "
        "name to __all__"
    )


def test_dir_lists_the_lazy_names_before_the_first_access() -> None:
    code = (
        "import guard_core.models as m\n"
        "print('SyncSecurityConfig' in dir(m), 'SyncSecurityConfig' in vars(m))\n"
    )

    assert _fresh(code) == "True False"


def test_a_fresh_interpreter_imports_the_sync_config_by_name() -> None:
    code = (
        "from guard_core.models import SyncSecurityConfig\n"
        "print(SyncSecurityConfig.__name__)\n"
    )

    assert _fresh(code) == "SecurityConfig[SyncGuardRequest]"


@pytest.mark.parametrize("threads", [4, 8, 16])
def test_threads_reading_the_name_first_get_one_class_that_pickles(
    threads: int,
) -> None:
    code = (
        "import pickle, threading\n"
        "import guard_core.models as m\n"
        "got = []\n"
        f"barrier = threading.Barrier({threads})\n"
        "def read():\n"
        "    barrier.wait()\n"
        "    got.append(m.SyncSecurityConfig)\n"
        f"workers = [threading.Thread(target=read) for _ in range({threads})]\n"
        "[w.start() for w in workers]\n"
        "[w.join() for w in workers]\n"
        "config = got[0](enable_redis=False, rate_limit=3)\n"
        "back = pickle.loads(pickle.dumps(config))\n"
        "print(len({id(c) for c in got}), back.rate_limit)\n"
    )

    assert all(_fresh(code) == "1 3" for _ in range(6))


def _rate_limit_of(config: SecurityConfig[SyncGuardRequest], queue: Any) -> None:
    queue.put((type(config).__name__, config.rate_limit))


def test_a_spawned_child_unpickles_a_sync_config_instance() -> None:
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    config = SecurityConfig[SyncGuardRequest](enable_redis=False, rate_limit=7)
    assert pickle.loads(pickle.dumps(config)).rate_limit == 7

    child = context.Process(target=_rate_limit_of, args=(config, queue))
    child.start()
    answer = queue.get(timeout=120)
    child.join(timeout=60)

    assert answer == ("SecurityConfig[SyncGuardRequest]", 7)


def test_an_unknown_attribute_still_raises() -> None:
    with pytest.raises(AttributeError):
        getattr(models, "no such name")


def test_the_lazy_hook_answers_again_without_building_twice_and_dir_lists_it() -> None:
    first = models.__getattr__("SyncSecurityConfig")
    assert models.__getattr__("SyncSecurityConfig") is first
    assert models.__getattr__("SecurityConfig[SyncGuardRequest]") is first
    assert models.__getattr__("SyncGuardRequest") is SyncGuardRequest
    assert {"SyncSecurityConfig", "SyncGuardRequest"} <= set(models.__dir__())
    with pytest.raises(AttributeError):
        models.__getattr__(_UNUSABLE_NAME + " ")
