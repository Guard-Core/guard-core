from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_FILE_WATCH_EVENT = (
    '{"event": "file_watch", "changed": true, "path": "/opt/app/worker.py"}'
)
_FORM = {"content-type": "application/x-www-form-urlencoded"}


def _threat_categories(request: SyncMockGuardRequest) -> list[str]:
    result = detect_penetration_attempt(request)
    return list(result.threat_categories) if result.is_threat else []


def test_source_path_json_leaf_in_a_form_field_is_not_a_probe() -> None:
    request = SyncMockGuardRequest(
        path="/upload",
        method="POST",
        headers=_FORM,
        body_content=f"payload={_FILE_WATCH_EVENT}".encode(),
    )
    assert _threat_categories(request) == []


def test_source_path_json_leaf_in_a_query_param_is_not_a_probe() -> None:
    request = SyncMockGuardRequest(
        path="/events", query_params={"v": _FILE_WATCH_EVENT}
    )
    assert _threat_categories(request) == []


def test_source_path_as_the_url_path_is_still_a_sensitive_file_probe() -> None:
    request = SyncMockGuardRequest(path="/worker.py")
    assert "sensitive_file" in _threat_categories(request)


def test_env_file_json_leaf_in_a_form_field_is_still_a_sensitive_file_probe() -> None:
    request = SyncMockGuardRequest(
        path="/upload",
        method="POST",
        headers=_FORM,
        body_content=b'payload={"path": "/var/www/.env"}',
    )
    assert "sensitive_file" in _threat_categories(request)


def test_bare_source_path_as_a_form_field_value_is_still_a_probe() -> None:
    request = SyncMockGuardRequest(
        path="/download",
        method="POST",
        headers=_FORM,
        body_content=b"file=/app/settings.py",
    )
    assert "sensitive_file" in _threat_categories(request)


def test_bare_source_path_as_a_json_body_leaf_is_still_a_probe() -> None:
    request = SyncMockGuardRequest(
        path="/download",
        method="POST",
        headers={"content-type": "application/json"},
        body_content=b'{"v": "/app/settings.py"}',
    )
    assert "sensitive_file" in _threat_categories(request)
