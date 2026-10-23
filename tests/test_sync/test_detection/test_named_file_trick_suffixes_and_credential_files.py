import json
from collections.abc import Callable
from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_TRICK_SUFFIXES = [";.jpg", "%00.jpg", ".", "..", "::$DATA", ".jpg"]
_NAMED_ROWS = [
    ".env",
    ".git/config",
    ".htaccess",
    ".htpasswd",
    ".npmrc",
    ".dockerenv",
    "web.config",
    "config.json",
    "database.yml",
    "appsettings.json",
    "wp-admin",
    "xmlrpc",
    "wp-content",
    "wp-login",
]
_CREDENTIAL_FILES = [
    ".ssh/id_rsa",
    ".ssh/id_dsa",
    ".ssh/id_ecdsa",
    ".ssh/id_ed25519",
    ".ssh/id_ecdsa_sk",
    ".ssh/id_ed25519_sk",
    ".ssh/authorized_keys",
    ".aws/credentials",
    ".docker/config.json",
    ".kube/config",
    ".azure/accessTokens.json",
    ".azure/msal_token_cache.json",
    ".config/gh/hosts.yml",
    ".config/gcloud/credentials.db",
    ".config/gcloud/application_default_credentials.json",
    ".terraform.d/credentials.tfrc.json",
    ".m2/settings.xml",
    ".gradle/gradle.properties",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".gem/credentials",
    ".composer/auth.json",
    ".config/composer/auth.json",
    ".git-credentials",
    ".netrc",
    "_netrc",
    ".pgpass",
    ".pypirc",
    ".vault-token",
    ".s3cfg",
    ".boto",
    "terraform.tfstate",
    ".bash_history",
    ".zsh_history",
]
_BARE_KEYS = [
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_ecdsa_sk",
    "id_ed25519_sk",
]
_BARE_GENERIC = ["config", "credentials", "settings.xml", "auth.json"]


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


def _run(request: SyncMockGuardRequest) -> bool:
    config = SyncSecurityConfig(enable_redis=False, rate_limit=10_000_000)
    return (detect_penetration_attempt(request, config)).is_threat


def _json_request(payload: Any) -> SyncMockGuardRequest:
    body = json.dumps(payload).encode()
    return SyncMockGuardRequest(
        path="/w",
        method="POST",
        headers={"content-type": "application/json", "content-length": str(len(body))},
        body_content=body,
    )


_SURFACES: dict[str, Callable[[str], SyncMockGuardRequest]] = {
    "url path": lambda value: SyncMockGuardRequest(
        path=value if value.startswith("/") else f"/{value}", query_params={}
    ),
    "query": lambda value: SyncMockGuardRequest(path="/w", query_params={"q": value}),
    "json": lambda value: _json_request({"name": value}),
}


@pytest.mark.parametrize("surface", _SURFACES)
@pytest.mark.parametrize("suffix", ["", *_TRICK_SUFFIXES])
@pytest.mark.parametrize("name", _NAMED_ROWS)
def test_a_trick_suffix_on_a_named_sensitive_file_row_is_flagged(
    surface: str, suffix: str, name: str
) -> None:
    assert _run(_SURFACES[surface](name + suffix)) is True


@pytest.mark.parametrize("surface", _SURFACES)
@pytest.mark.parametrize("suffix", ["", ";.jpg", "%00.jpg", ".", "..", "::$DATA"])
@pytest.mark.parametrize("prefix", ["", "../", "/home/u/"])
@pytest.mark.parametrize("name", _CREDENTIAL_FILES)
def test_a_credential_file_is_flagged_plain_under_a_directory_and_with_a_suffix(
    surface: str, suffix: str, prefix: str, name: str
) -> None:
    assert _run(_SURFACES[surface](prefix + name + suffix)) is True


@pytest.mark.parametrize("name", _CREDENTIAL_FILES)
def test_a_credential_file_with_a_jpg_suffix_is_flagged(name: str) -> None:
    for surface in _SURFACES.values():
        assert _run(surface(name + ".jpg")) is True


@pytest.mark.parametrize("key", _BARE_KEYS)
def test_a_bare_private_key_name_is_flagged_as_the_last_url_path_segment_only(
    key: str,
) -> None:
    for path in (f"/{key}", f"/backup/{key}", f"/api/keys/{key}", f"/{key};.jpg"):
        assert _run(_SURFACES["url path"](path)) is True
    assert _run(_SURFACES["query"](key)) is False
    assert _run(_json_request({"name": key})) is False
    for value in (f"/{key}", f"/backup/{key}", f"backup/{key}"):
        assert _run(_SURFACES["query"](value)) is False
        assert _run(_json_request({"name": value})) is False
    assert _run(_SURFACES["query"](f"{key}.pub")) is False
    assert _run(_SURFACES["url path"](f"/{key}.pub")) is False
    assert _run(_SURFACES["url path"](f".ssh/{key}.pub")) is False
    assert _run(_SURFACES["query"](f"../.ssh/{key}")) is True


@pytest.mark.parametrize("name", _BARE_GENERIC)
def test_a_bare_generic_name_never_matches_as_a_query_or_json_value(
    name: str,
) -> None:
    assert _run(_SURFACES["query"](name)) is False
    assert _run(_json_request({"name": name})) is False


@pytest.mark.parametrize("path", ["/config", "/settings.xml", "/auth.json"])
def test_a_bare_generic_url_path_keeps_its_v440_verdict(path: str) -> None:
    assert _run(_SURFACES["url path"](path)) is False


@pytest.mark.parametrize("suffix", _TRICK_SUFFIXES[:5])
@pytest.mark.parametrize(
    "name", ["wp-admin", ".git/config", ".htpasswd", ".kube/config"]
)
def test_a_push_list_does_not_clear_a_suffixed_name(suffix: str, name: str) -> None:
    assert _run(_json_request({"commits": [{"added": [name + suffix]}]})) is True


@pytest.mark.parametrize("name", [".htpasswd", ".kube/config", ".aws/credentials"])
def test_a_push_list_clears_a_plain_named_file_and_the_scalar_stays_flagged(
    name: str,
) -> None:
    assert _run(_json_request({"commits": [{"added": [name]}]})) is False
    assert _run(_json_request({"file": name})) is True


@pytest.mark.parametrize("suffix", ["", ";.jpg", "%00.jpg"])
def test_a_stack_frame_clears_a_plain_credential_name_and_not_a_suffixed_one(
    suffix: str,
) -> None:
    frame = {"frames": [{"filename": ".netrc" + suffix, "lineno": 3, "function": "f"}]}
    assert _run(_json_request(frame)) is bool(suffix)


@pytest.mark.parametrize("surface", ["query", "json"])
@pytest.mark.parametrize(
    "name",
    [name for name in _CREDENTIAL_FILES if name != ".docker/config.json"],
)
def test_a_home_tilde_reference_to_a_credential_file_stays_unflagged_as_at_v440(
    surface: str, name: str
) -> None:
    assert _run(_SURFACES[surface](f"~/{name}")) is False


@pytest.mark.parametrize("surface", ["query", "json"])
@pytest.mark.parametrize(
    "value",
    [
        "~/.env",
        "~/.aws/credentials;.jpg",
        "~/.aws/credentials%00.jpg",
        "~/../.aws/credentials",
        "~/.aws/credentials/x",
        "~root/.aws/credentials",
    ],
)
def test_a_home_tilde_clearing_does_not_cover_other_shapes(
    surface: str, value: str
) -> None:
    assert _run(_SURFACES[surface](value)) is True
