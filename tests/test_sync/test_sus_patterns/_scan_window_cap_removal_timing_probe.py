import json
import statistics
from collections.abc import Callable
from functools import partial

from guard_core.sync.handlers.suspatterns_handler import (
    _LDAP_NULL_BYTE_ATTR_COMPILED_RE,
    _LDAP_NULL_BYTE_DECODED_ATTR_COMPILED_RE,
    _LDAP_NULL_BYTE_DECODED_TAIL_RE,
    _LDAP_NULL_BYTE_TAIL_RE,
    _QUOTE_SPLICE_CANDIDATE_COMPILED_RE,
    _ldap_null_byte_attr_finditer,
    _quote_splice_finditer,
)
from tests.host_load_factor import timed_normalized

_SIZES = (32768, 65536, 131072, 262144)
_RUNS_PER_SIZE = 5


def _ldap_dense_attack_reach_probe(n: int) -> str:
    unit = "uid=alice*) "
    return (unit * (n // len(unit) + 1))[:n]


def _quote_splice_dense_reach_probe(n: int) -> str:
    return ("a'" * (n // 2))[:n]


_CASES: dict[str, tuple] = {
    "ldap_null_byte_attr": (
        _ldap_dense_attack_reach_probe,
        lambda text: list(
            _ldap_null_byte_attr_finditer(
                text, _LDAP_NULL_BYTE_ATTR_COMPILED_RE, _LDAP_NULL_BYTE_TAIL_RE
            )
        ),
    ),
    "ldap_null_byte_decoded_attr": (
        _ldap_dense_attack_reach_probe,
        lambda text: list(
            _ldap_null_byte_attr_finditer(
                text,
                _LDAP_NULL_BYTE_DECODED_ATTR_COMPILED_RE,
                _LDAP_NULL_BYTE_DECODED_TAIL_RE,
            )
        ),
    ),
    "quote_splice": (
        _quote_splice_dense_reach_probe,
        lambda text: list(
            _quote_splice_finditer(text, _QUOTE_SPLICE_CANDIDATE_COMPILED_RE)
        ),
    ),
}


def _cpu_time_runs(run: Callable[[str], object], text: str, runs: int) -> list[float]:
    samples = []
    for _ in range(runs):
        samples.append(timed_normalized(partial(run, text))[1])
    return samples


def _measure(sizes: tuple[int, ...]) -> dict[str, dict[str, list[float]]]:
    results: dict[str, dict[str, list[float]]] = {}
    for name, (make_text, run) in _CASES.items():
        mins: list[float] = []
        medians: list[float] = []
        for size in sizes:
            text = make_text(size)
            samples = _cpu_time_runs(run, text, _RUNS_PER_SIZE)
            mins.append(min(samples))
            medians.append(statistics.median(samples))
        results[name] = {"min": mins, "median": medians}
    return results


if __name__ == "__main__":
    print(json.dumps(_measure(_SIZES)))
