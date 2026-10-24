import json
import urllib.parse
from collections.abc import Callable

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_NAMES = [
    "/wp-config.php",
    "/.env",
    "/.git/config",
    "/.htpasswd",
    "/.htaccess",
    "/web.config",
    "/config.json",
    "/app.py",
    "/index.asp",
    "/.ssh/id_rsa",
    "/.ssh/id_ed25519",
    "/.aws/credentials",
    "/.netrc",
    "/.pgpass",
    "/.kube/config",
    "/terraform.tfstate",
    "/etc/shadow",
    "/etc/passwd",
]
_TAILS = [".txt", ".php", ".bin", ""]
_NUL_TEXTS = ["%00", "\\u0000", "\\x00"]
_DELETED_CONTROLS = ["\x01", "\x0b", "\x1c", "\x1f"]


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


def _run(request: SyncMockGuardRequest) -> bool:
    config = SyncSecurityConfig(enable_redis=False, rate_limit=10_000_000)
    return (detect_penetration_attempt(request, config)).is_threat


def _json_request(payload: object) -> SyncMockGuardRequest:
    body = json.dumps(payload).encode()
    return SyncMockGuardRequest(
        path="/w",
        method="POST",
        headers={"content-type": "application/json", "content-length": str(len(body))},
        body_content=body,
    )


_SURFACES: dict[str, Callable[[str], SyncMockGuardRequest]] = {
    "url path": lambda value: SyncMockGuardRequest(path=value, query_params={}),
    "query": lambda value: SyncMockGuardRequest(
        path="/w", query_params={"file": value}
    ),
    "json": lambda value: _json_request({"file": value}),
}


@pytest.mark.parametrize("surface", _SURFACES)
@pytest.mark.parametrize("tail", _TAILS)
@pytest.mark.parametrize("name", _NAMES)
def test_a_percent_encoded_nul_tail_decoded_by_the_server_is_flagged(
    surface: str, tail: str, name: str
) -> None:
    decoded = urllib.parse.unquote(f"{name}%00{tail}")
    assert "\x00" in decoded
    assert _run(_SURFACES[surface](decoded)) is True


@pytest.mark.parametrize("surface", _SURFACES)
@pytest.mark.parametrize("nul", _NUL_TEXTS)
@pytest.mark.parametrize("name", _NAMES)
def test_the_literal_text_of_a_nul_tail_is_flagged(
    surface: str, nul: str, name: str
) -> None:
    assert _run(_SURFACES[surface](f"{name}{nul}.txt")) is True


@pytest.mark.parametrize("surface", _SURFACES)
@pytest.mark.parametrize("control", _DELETED_CONTROLS)
@pytest.mark.parametrize("name", ["/wp-config.php", "/.ssh/id_rsa", "/.netrc"])
def test_the_other_deleted_control_characters_after_a_name_are_flagged(
    surface: str, control: str, name: str
) -> None:
    assert _run(_SURFACES[surface](f"{name}{control}.txt")) is True


@pytest.mark.parametrize("surface", _SURFACES)
@pytest.mark.parametrize(
    "value",
    [
        "hello\x00world",
        "notes\x00.txt",
        "/wp-config-docs\x00.txt",
        "/images\x00.txt",
        "my.netrc.example\x00.txt",
        "id_rsa pub\x00x",
    ],
)
def test_a_nul_that_does_not_follow_a_listed_name_stays_unflagged(
    surface: str, value: str
) -> None:
    assert _run(_SURFACES[surface](value)) is False


@pytest.mark.parametrize("surface", ["query", "json"])
def test_a_tab_after_a_name_keeps_its_v440_verdict(surface: str) -> None:
    assert _run(_SURFACES[surface]("/wp-config.php\t.txt")) is False
