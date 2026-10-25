import ast
import re
from pathlib import Path

import pytest
from generate_safety_gates import classify

_REPO_ROOT = next(
    path for path in Path(__file__).resolve().parents if (path / "guard_core").is_dir()
)
_ENGINE_DIR = _REPO_ROOT / "guard_core" / "detection_engine"
_REASON_TEXT = re.compile(
    r"""Pattern (?:validation|timed out|appears|extrapolated|contains)[^'"\\\n]*"""
)
_NOT_A_VERDICT_REASON = ("Pattern validation cache not trusted",)
_SAFETY_CHAIN_FILES = sorted(_ENGINE_DIR.glob("_redos_*.py")) + [
    _ENGINE_DIR / "compiler.py"
]


def _constant_text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            part.value
            if isinstance(part, ast.Constant) and isinstance(part.value, str)
            else "{}"
            for part in node.values
        )
    return None


def _engine_reason_texts() -> set[str]:
    reasons: set[str] = set()
    for path in _SAFETY_CHAIN_FILES:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            text = _constant_text(node)
            if text is None:
                continue
            reasons.update(
                found.rstrip()
                for found in _REASON_TEXT.findall(text)
                if not found.startswith(_NOT_A_VERDICT_REASON)
            )
    return reasons


def test_the_walk_finds_the_reasons_the_engine_raises() -> None:
    reasons = _engine_reason_texts()
    assert len(reasons) >= 30
    assert "Pattern validation alphabet exceeded its deadline" in reasons
    assert (
        "Pattern validation repeat-prefix construction exceeded its deadline" in reasons
    )
    assert any(reason.startswith("Pattern appears safe") for reason in reasons)


def test_no_reason_the_engine_can_produce_classifies_as_other() -> None:
    unclassified = sorted(
        reason for reason in _engine_reason_texts() if classify(reason) == "other"
    )
    assert unclassified == []


@pytest.mark.parametrize(
    "reason",
    [
        "Pattern validation probe construction exceeded its deadline",
        "Pattern validation repeat-prefix construction exceeded its deadline",
        "Pattern validation alphabet exceeded its deadline",
    ],
)
def test_every_exceeded_its_deadline_reason_is_builder_deadline(reason: str) -> None:
    assert classify(reason) == "builder_deadline"
