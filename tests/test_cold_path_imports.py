import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

_COLD_PATH = (
    "import sys\n"
    "from guard_core.handlers.suspatterns_handler import SusPatternsManager\n"
    "from guard_core.models import SecurityConfig\n"
    "SecurityConfig()\n"
    "heavy = [\n"
    "    name for name in ('redis', 'guard_core.core.events.enricher',\n"
    "                      'guard_core.handlers.behavior_handler',\n"
    "                      'guard_core.core.validation.validator')\n"
    "    if name in sys.modules\n"
    "]\n"
    "print(','.join(heavy))\n"
)


def test_building_a_config_loads_neither_redis_nor_the_event_bus() -> None:
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [sys.executable, "-W", "ignore", "-c", _COLD_PATH],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )

    assert result.stdout.strip() == ""


_ATTRIBUTION_IMPORT = (
    "import sys\n"
    "import guard_core.{tree}_utils.rule_attribution as attribution\n"
    "from guard_core.{tree}core.checks.implementations.ip_security import (\n"
    "    IpSecurityCheck,\n"
    ")\n"
    "leaked = [\n"
    "    name for name in sys.modules\n"
    "    if name.endswith(('.dynamic_rule_handler', '._dynamic_rule_attribution'))\n"
    "]\n"
    "print(','.join(leaked))\n"
)

_ATTRIBUTION_VIEW = (
    "import guard_core.{tree}_utils.rule_attribution as attribution\n"
    "import guard_core.{tree}handlers.dynamic_rule_handler as handler\n"
    "assert attribution._APP_RULE_MANAGERS is handler._APP_RULE_MANAGERS\n"
    "assert attribution._process_default_manager() is "
    "handler.DynamicRuleManager._instance\n"
)

_PIPELINE_IMPORT = (
    "import sys\n"
    "from guard_core.{tree}core.checks.pipeline import SecurityCheckPipeline\n"
    "from guard_core.{tree}core.checks import SecurityCheck\n"
    "leaked = [\n"
    "    name for name in sys.modules\n"
    "    if '.checks.implementations.' in name or name.endswith('.checks.factory')\n"
    "]\n"
    "print(','.join(leaked))\n"
)

_CHECKS_BY_NAME = (
    "from guard_core.{tree}core.checks import DEFAULT_CHECK_CLASSES, IpSecurityCheck\n"
    "from guard_core.{tree}core.checks.implementations import RateLimitCheck\n"
    "from guard_core.{tree}core.checks import factory\n"
    "assert IpSecurityCheck in DEFAULT_CHECK_CLASSES\n"
    "assert RateLimitCheck in DEFAULT_CHECK_CLASSES\n"
    "assert factory.DEFAULT_CHECK_CLASSES is DEFAULT_CHECK_CLASSES\n"
)


def _run_python(source: str) -> str:
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}"
    return subprocess.run(
        [sys.executable, "-W", "ignore", "-c", source],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout.strip()


@pytest.mark.parametrize("tree", ["", "sync."])
def test_importing_a_check_loads_no_rule_manager(tree: str) -> None:
    assert _run_python(_ATTRIBUTION_IMPORT.format(tree=tree)) == ""


@pytest.mark.parametrize("tree", ["", "sync."])
def test_the_rule_attribution_reads_the_registry_the_rule_manager_fills(
    tree: str,
) -> None:
    assert _run_python(_ATTRIBUTION_VIEW.format(tree=tree)) == ""


@pytest.mark.parametrize("tree", ["", "sync."])
def test_importing_the_pipeline_loads_no_check_implementation(tree: str) -> None:
    assert _run_python(_PIPELINE_IMPORT.format(tree=tree)) == ""


@pytest.mark.parametrize("tree", ["", "sync."])
def test_the_check_names_resolve_from_their_packages(tree: str) -> None:
    assert _run_python(_CHECKS_BY_NAME.format(tree=tree)) == ""
