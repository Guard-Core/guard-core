import json
from pathlib import Path

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_TESTS = next(p for p in Path(__file__).resolve().parents if p.name == "tests")
_DIR = _TESTS / "wordlists" / "sqli_recall"
_RECORD = json.loads((_DIR / "v440_flagged.json").read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


def _unflagged(texts: list[str]) -> list[str]:
    config = SyncSecurityConfig(enable_redis=False, rate_limit=10_000_000)
    missed = []
    for text in texts:
        request = SyncMockGuardRequest(path="/x", query_params={"q": text})
        if not (detect_penetration_attempt(request, config)).is_threat:
            missed.append(text)
    return missed


@pytest.mark.parametrize("name", sorted(_RECORD["corpus"]))
def test_every_corpus_line_v440_flags_is_still_flagged(name: str) -> None:
    assert _unflagged(_RECORD["corpus"][name]) == []


def test_every_generated_variant_v440_flags_is_still_flagged() -> None:
    assert _unflagged(_RECORD["variants"]) == []


def test_the_vendored_corpus_matches_its_pinned_blob_shas() -> None:
    import hashlib

    sources = json.loads((_DIR / "SOURCES.json").read_text(encoding="utf-8"))
    for name, meta in sources["files"].items():
        data = (_DIR / name).read_bytes()
        digest = hashlib.sha1(
            b"blob " + str(len(data)).encode() + b"\0" + data, usedforsecurity=False
        ).hexdigest()
        assert digest == meta["git_blob_sha"], name
