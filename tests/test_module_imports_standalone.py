import os
import pkgutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import guard_core

REPO_ROOT = Path(__file__).resolve().parent.parent
_MAX_WORKERS = 8
_IMPORT_TIMEOUT_SECONDS = 30


def _discover_module_names() -> list[str]:
    module_names = [guard_core.__name__]
    module_names.extend(
        module_info.name
        for module_info in pkgutil.walk_packages(
            guard_core.__path__, prefix=f"{guard_core.__name__}."
        )
    )
    return module_names


def _subprocess_env() -> dict[str, str]:
    env = dict(os.environ)
    existing_path = env.get("PYTHONPATH", "")
    # A runner that layers packages over its environment (uv run --with) hands
    # them to this process through sys.path only.
    env["PYTHONPATH"] = os.pathsep.join(
        [str(REPO_ROOT), *sys.path, *([existing_path] if existing_path else [])]
    )
    return env


def _interpreter_report() -> str:
    site_packages = [entry for entry in sys.path if entry.endswith("site-packages")]
    return (
        f"sys.executable={sys.executable} sys.prefix={sys.prefix} "
        f"site-packages={[(entry, os.path.isdir(entry)) for entry in site_packages]}"
    )


def _import_standalone(module_name: str) -> tuple[str, int, str]:
    try:
        result = subprocess.run(
            [sys.executable, "-c", f"import {module_name}"],
            cwd=REPO_ROOT,
            env=_subprocess_env(),
            capture_output=True,
            text=True,
            timeout=_IMPORT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        return module_name, 1, str(exc)
    return module_name, result.returncode, result.stderr


def test_every_guard_core_module_imports_standalone() -> None:
    module_names = _discover_module_names()

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
        results = list(executor.map(_import_standalone, module_names))

    failures = {name: stderr for name, code, stderr in results if code != 0}

    assert not failures, (
        _interpreter_report()
        + "\n\n"
        + "\n\n".join(f"{name}:\n{stderr}" for name, stderr in sorted(failures.items()))
    )
