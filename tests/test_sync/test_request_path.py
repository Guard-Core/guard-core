import pytest

from guard_core.sync._utils.request_path import resolve_dot_and_empty_segments


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/", "/"),
        ("//", "/"),
        ("/.", "/"),
        ("/..", "/"),
        ("/a/b", "/a/b"),
        ("//a///b", "/a/b"),
        ("/a/./b", "/a/b"),
        ("/a/../b", "/b"),
        ("/../../a", "/a"),
        ("/a/b/", "/a/b/"),
        ("//a//", "/a/"),
        ("/a/b/..", "/a"),
        ("/a/b/../", "/a/"),
    ],
)
def test_resolve_dot_and_empty_segments(path: str, expected: str) -> None:
    assert resolve_dot_and_empty_segments(path) == expected
