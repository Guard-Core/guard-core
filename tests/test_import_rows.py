import os
import re
import subprocess
import sys
from pathlib import Path

import guard_core
from guard_core._builtin_import_rows import IMPORT_COMPILED_ROWS
from guard_core.handlers._suspatterns_pattern_table import _PATTERN_DEFINITIONS

REPO_ROOT = Path(guard_core.__file__).resolve().parent.parent
_SCRIPT = REPO_ROOT / "scripts" / "generate_import_rows.py"


def _run(*arguments: str, code: str | None = None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}"
    command = [sys.executable, "-W", "ignore"]
    command += ["-c", code] if code else [str(_SCRIPT), *arguments]
    return subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def test_the_import_row_table_is_what_the_generator_chooses() -> None:
    result = _run("--check")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "up to date" in result.stdout


def test_the_generator_check_fails_on_a_stale_table() -> None:
    code = (
        "import runpy, sys\n"
        "import guard_core._builtin_import_rows as t\n"
        "t.IMPORT_COMPILED_ROWS = t.IMPORT_COMPILED_ROWS[1:]\n"
        "sys.argv = ['generate_import_rows.py', '--check']\n"
        f"runpy.run_path({str(_SCRIPT)!r}, run_name='__main__')\n"
    )

    result = _run(code=code)

    assert result.returncode == 1
    assert "stale" in result.stdout


def test_the_table_holds_builtin_rows_once_inside_the_budget() -> None:
    builtin = {source for source, _contexts, _category in _PATTERN_DEFINITIONS}

    assert IMPORT_COMPILED_ROWS
    assert len(set(IMPORT_COMPILED_ROWS)) == len(IMPORT_COMPILED_ROWS)
    assert set(IMPORT_COMPILED_ROWS) <= builtin
    assert sum(map(len, IMPORT_COMPILED_ROWS)) <= 4500


def test_importing_the_package_compiles_exactly_those_rows() -> None:
    code = (
        "import guard_core.handlers._suspatterns_lazy_rows as m\n"
        "from guard_core._builtin_import_rows import IMPORT_COMPILED_ROWS as rows\n"
        "print(list(m.COMPILED_BUILTIN_PATTERNS) == list(rows), "
        "all(p.flags == m.re.compile('', m._BUILTIN_PATTERN_COMPILE_FLAGS).flags "
        "for p in m.COMPILED_BUILTIN_PATTERNS.values()))\n"
    )

    result = _run(code=code)

    assert result.stdout.strip() == "True True", result.stdout + result.stderr


def test_a_row_outside_the_table_still_compiles_when_first_searched() -> None:
    from guard_core.handlers._suspatterns_lazy_rows import COMPILED_BUILTIN_PATTERNS

    outside = next(
        source
        for source, _contexts, _category in _PATTERN_DEFINITIONS
        if source not in IMPORT_COMPILED_ROWS
    )
    COMPILED_BUILTIN_PATTERNS.pop(outside, None)

    assert isinstance(COMPILED_BUILTIN_PATTERNS[outside], re.Pattern)


def test_one_compiled_table_per_process_seeds_both_trees() -> None:
    code = (
        "import re\n"
        "import guard_core.sync.core.checks.pipeline\n"
        "import guard_core.handlers._suspatterns_lazy_rows as a\n"
        "import guard_core.sync.handlers._suspatterns_lazy_rows as s\n"
        "import guard_core._builtin_import_table as t\n"
        "orig = re.compile\n"
        "print(len(t.IMPORT_COMPILED_TABLE), list(a.COMPILED_BUILTIN_PATTERNS) == "
        "list(s.COMPILED_BUILTIN_PATTERNS) == list(t.IMPORT_COMPILED_TABLE), "
        "all(a.COMPILED_BUILTIN_PATTERNS[k] is s.COMPILED_BUILTIN_PATTERNS[k] is v "
        "for k, v in t.IMPORT_COMPILED_TABLE.items()), "
        "a.COMPILED_BUILTIN_PATTERNS is not s.COMPILED_BUILTIN_PATTERNS)\n"
    )

    result = _run(code=code)

    assert result.stdout.strip() == f"{len(IMPORT_COMPILED_ROWS)} True True True", (
        result.stdout + result.stderr
    )


def test_importing_both_trees_compiles_each_table_row_once() -> None:
    code = (
        "import re\n"
        "engine = getattr(re, '_compiler', None) or re.sre_compile\n"
        "calls = []\n"
        "orig = engine.compile\n"
        "def counting(pattern, flags=0):\n"
        "    calls.append(pattern)\n"
        "    return orig(pattern, flags)\n"
        "engine.compile = counting\n"
        "import guard_core.sync.core.checks.pipeline\n"
        "import guard_core.core.checks.pipeline\n"
        "import guard_core._builtin_import_table as t\n"
        "print(max(calls.count(row) for row in t.IMPORT_COMPILED_TABLE))\n"
    )

    result = _run(code=code)

    assert result.stdout.strip() == "1", result.stdout + result.stderr
