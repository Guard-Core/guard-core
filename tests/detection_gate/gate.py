"""Base-diff wire gate.

Usage: gate.py <base_dc.json> <candidate_dc.json> [candidate_tree_for_control]
Runs defect_corpus deltas AND a control invariant. Fails on any regression.
"""

import asyncio
import json
import sys
from typing import Any


def load(path: str) -> dict[str, dict[str, Any]]:
    with open(path) as f:
        return {r["name"]: r for r in json.load(f)["rows"]}


def anyhit(row: dict[str, Any]) -> bool:
    return any(v is True for v in row["verdicts"].values())


class _St:
    def __getattr__(self, _key: str) -> object:
        return None


class _Req:
    def __init__(self, body: bytes) -> None:
        self._b = body
        self._h: dict[str, str] = {
            "content-type": "text/plain",
            "content-length": str(len(body)),
        }

    url_path: str = "/"
    url_scheme: str = "https"
    url_full: str = "https://t/"
    method: str = "POST"
    client_host: str | None = "203.0.113.7"
    query_params: dict[str, str] = {}
    scope: dict[str, Any] = {}

    @property
    def headers(self) -> dict[str, str]:
        return self._h

    @property
    def state(self) -> object:
        return _St()

    def url_replace_scheme(self, _scheme: str) -> str:
        return "https://t/"

    async def body(self) -> bytes:
        return self._b


async def control(tree: str) -> tuple[bool, bool]:
    sys.path.insert(0, tree)
    import guard_core

    _file = guard_core.__file__
    assert _file is not None and tree in _file, _file
    from guard_core.handlers.suspatterns_handler import sus_patterns_handler
    from guard_core.models import SecurityConfig
    from guard_core.utils import detect_penetration_attempt

    sus_patterns_handler.configure(SecurityConfig())
    if sus_patterns_handler._preprocessor is None:
        print(
            "CONTROL FAILED: enhanced detection state not built; "
            "measuring LEGACY mode. ABORT."
        )
        sys.exit(2)
    cfg = SecurityConfig()
    atk = (
        await detect_penetration_attempt(_Req(b"<script>alert(1)</script>"), cfg)
    ).is_threat
    ben = (
        await detect_penetration_attempt(_Req(b"the quick brown fox"), cfg)
    ).is_threat
    return bool(atk), bool(ben)


_base = json.load(open(sys.argv[1]))
_cand = json.load(open(sys.argv[2]))

if _cand.get("tree") == _base.get("tree"):
    print(
        "CANDIDATE INVALID: candidate was generated on the same tree "
        "as the baseline. ABORT."
    )
    sys.exit(2)

print(f"baseline tree OK ({_base['tree']}), candidate tree {_cand.get('tree')}")
base = {r["name"]: r for r in _base["rows"]}
cand = {r["name"]: r for r in _cand["rows"]}

if len(sys.argv) > 3:
    atk, ben = asyncio.run(control(sys.argv[3]))
    if not atk or ben:
        print(
            f"CONTROL FAILED: canonical-attack-detected={atk} (want True), "
            f"benign-flagged={ben} (want False)"
        )
        print(
            "HARNESS INVALID - body likely not scanned. ABORT, do not trust this delta."
        )
        sys.exit(2)
    print(f"control OK (attack={atk}, benign={ben})")

nm = [
    n
    for n in base
    if base[n]["kind"] == "attack" and anyhit(base[n]) and not anyhit(cand[n])
]
nf = [
    n
    for n in base
    if base[n]["kind"] == "benign" and not anyhit(base[n]) and anyhit(cand[n])
]
fx = [
    n
    for n in base
    if base[n]["kind"] == "attack" and not anyhit(base[n]) and anyhit(cand[n])
]
er = [
    n
    for n in cand
    if cand[n]["kind"] in ("attack", "benign")
    and any(isinstance(v, str) for v in cand[n]["verdicts"].values())
]
pm = [
    f"{n}:{k}"
    for n in base
    if base[n]["kind"] == "attack"
    for k, v in base[n]["verdicts"].items()
    if v is True and cand[n]["verdicts"].get(k) is not True
]
pf = [
    f"{n}:{k}"
    for n in base
    if base[n]["kind"] == "benign"
    for k, v in base[n]["verdicts"].items()
    if v is not True and cand[n]["verdicts"].get(k) is True
]
partial = [
    n + "(" + ",".join(k for k, v in cand[n]["verdicts"].items() if v is not True) + ")"
    for n in cand
    if cand[n]["kind"] == "attack"
    and anyhit(cand[n])
    and not all(v is True for v in cand[n]["verdicts"].values())
]
print(f"REGRESSION new-miss ({len(nm)}): {nm}")
print(f"REGRESSION new-FP  ({len(nf)}): {nf}")
print(f"REGRESSION per-mechanism miss ({len(pm)}): {pm}")
print(f"REGRESSION per-mechanism FP ({len(pf)}): {pf}")
print(f"gains fixed (+{len(fx)}): {fx}")
print(f"partial (detected on some mechanisms, missed on the listed ones): {partial}")
print(f"errors: {er}")
nm = nm + pm
nf = nf + pf
lim = [n for n in cand if cand[n]["kind"] == "limitation"]


def limstate(row: dict[str, Any]) -> str:
    if any(isinstance(v, str) for v in row["verdicts"].values()):
        return "ERRORED"
    return "detected" if anyhit(row) else "undetected"


if lim:
    print(
        "documented limitations (not gated): "
        + ", ".join(f"{n}={limstate(cand[n])}" for n in lim)
    )
print("GATE:", "PASS (clean delta)" if not nm and not nf and not er else "FAIL")
sys.exit(1 if (nm or nf or er) else 0)
