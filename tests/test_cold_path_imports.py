import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_COLD_PATH = (
    "import sys\n"
    "from guard_core.handlers.suspatterns_handler import SusPatternsManager\n"
    "from guard_core.models import SecurityConfig\n"
    "SecurityConfig()\n"
    "heavy = [\n"
    "    name for name in ('redis', 'guard_core.core.events',\n"
    "                      'guard_core.handlers.behavior_handler',\n"
    "                      'guard_core.core.validation')\n"
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
