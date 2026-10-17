import pytest

from guard_core._utils.request_path import has_routing_anomaly


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/login",
        "/login/",
        "/static/js/app.js",
        "/a.b/c..d/.hidden",
        "/orders;customer=42/items",
        "/static/..,foo/etc",
        "/100%25/x",
        "/%41bc",
    ],
)
def test_ordinary_paths_have_no_routing_anomaly(path: str) -> None:
    assert has_routing_anomaly(path) is False


@pytest.mark.parametrize(
    "path",
    [
        "/.",
        "/..",
        "/./login",
        "/x/../login",
        "/login/.",
        "/admin/../static/x",
        "/static/..;/etc",
        "/static/.;x/js",
        "//login",
        "///.env",
        "/a//b",
        "//",
        "/login\\",
        "/a\\b",
        "/login%2f",
        "/login%2F",
        "/login%5c",
        "/login%5C",
        "/admin/..%2fstatic%2fx",
        "/admin/%2e%2e/health",
        "/admin/%2E%2E/health",
        "/%2e/x",
    ],
)
def test_dot_empty_backslash_and_encoded_separator_paths_are_anomalies(
    path: str,
) -> None:
    assert has_routing_anomaly(path) is True
