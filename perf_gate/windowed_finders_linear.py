"""CPU time of each windowed builtin finder at 1 MiB and 10 MiB on adversarial shapes.

usage: python -m perf_gate.windowed_finders_linear [sizes_mib ...]    (default: 1 10)

A finder is linear when ten times the input costs about ten times the CPU. Prints one
JSON line per finder and shape with the CPU seconds at each size and the growth ratio
(linear is 10); the exit code is 1 when any ratio is above 14.
"""

import json
import sys
import time

from guard_core.handlers._suspatterns_windowed_finders import (
    _WINDOWED_PATTERN_FINDERS,
)

_MIB = 1024 * 1024
_RATIO_LIMIT = 14.0


def _repeat(unit: str, size: int) -> str:
    return (unit * (size // len(unit) + 1))[:size]


def _shapes(size: int) -> dict[str, str]:
    return {
        "newlines": "\n" * size,
        "assignment-chain": "\n" + _repeat("a=b ", size),
        "assignment-lines": _repeat("\nx=y z=w ", size),
        "dash-c-lines": _repeat("\n  bash -c x", size),
        "ldap-long-value": "a=" + "b" * size + "*)%00",
        "ldap-tails": _repeat("=*)%00", size),
        "ldap-attr-tails": _repeat("a=1*)%00", size),
        "ldap-decoded-tails": _repeat("a=1*)\x00", size),
        "ldap-stars": "a=" + "*)" * (size // 2),
        "quote-word-quote": _repeat("a'b", size),
        "quote-run": "'" * size,
        "quote-after-word": "a" * size + "'b",
        "quote-pairs": _repeat("a'", size),
        "pickle-newlines-ident": _repeat("\nos.path\n", size),
        "pickle-chain": _repeat("\nos\nsystem\n", size),
        "pickle-dots": _repeat("a.", size),
        "pickle-long-line": "\n" + "a" * size + "\n",
        "xxe-doctype-public": _repeat('<!DOCTYPE x PUBLIC "a" "b">', size),
        "xxe-public-run": "<!DOCTYPE x " + _repeat('PUBLIC "a" ', size),
        "xxe-quotes": "<!DOCTYPE x PUBLIC " + '"' * size,
        "xxe-doctypes": _repeat("<!DOCTYPE ", size),
        "benign": _repeat("quarterly onboarding metrics for the regional team ", size),
    }


def _cpu(finder_text: tuple[object, str]) -> float:
    finder, text = finder_text
    start = time.thread_time()
    list(finder(text))  # type: ignore[operator]
    return time.thread_time() - start


def main() -> int:
    sizes = [int(float(arg) * _MIB) for arg in sys.argv[1:]] or [_MIB, 10 * _MIB]
    texts = {size: _shapes(size) for size in sizes}
    worst = 0.0
    for index, finder in enumerate(_WINDOWED_PATTERN_FINDERS.values()):
        for shape in texts[sizes[0]]:
            cpu = [_cpu((finder, texts[size][shape])) for size in sizes]
            ratio = cpu[-1] / max(cpu[0], 1e-6) / (sizes[-1] / sizes[0]) * 10
            worst = max(worst, ratio if cpu[0] > 0.005 else 0.0)
            print(
                json.dumps(
                    {
                        "finder": index,
                        "shape": shape,
                        "cpu_seconds": [round(value, 4) for value in cpu],
                        "growth_for_10x": round(ratio, 1),
                    }
                ),
                flush=True,
            )
    return 1 if worst > _RATIO_LIMIT else 0


if __name__ == "__main__":
    raise SystemExit(main())
