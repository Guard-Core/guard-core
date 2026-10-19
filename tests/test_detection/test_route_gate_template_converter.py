import pytest

from tests.detection_gate.route_gate_real_templates import (
    _matcher,
    declared_template,
)


@pytest.mark.parametrize(
    ("hono", "declared"),
    [
        ("/shop/cart", "/shop/cart"),
        ("/user/:name", "/user/{name}"),
        ("/user/:name?", "/user/{name}"),
        ("/file/:path{.+}", "/file/{path}"),
        ("/news/:suffix{.+}?", "/news/{suffix}"),
        ("/x/:year{[0-9]{4}}/:slug", "/x/{year}/{slug}"),
        ("/a.php", "/a.php"),
    ],
)
def test_hono_syntax_becomes_the_starlette_form(hono: str, declared: str) -> None:
    assert declared_template(hono) == declared


@pytest.mark.parametrize(
    ("hono", "path", "matches"),
    [
        ("/user/:name", "/user/ann", True),
        ("/user/:name", "/user", False),
        ("/user/:name?", "/user", True),
        ("/user/:name?", "/user/ann", True),
        ("/file/:path{.+}", "/file/a/b/c.md", True),
        ("/x/:year{[0-9]{4}}/:slug", "/x/2024/post", True),
        ("/x/:year{[0-9]{4}}/:slug", "/x/24/post", False),
        ("/shop/cart", "/shop/cart/", True),
        ("/shop/cart", "/shop/cart2", False),
    ],
)
def test_the_matcher_follows_the_hono_route_rules(
    hono: str, path: str, matches: bool
) -> None:
    assert bool(_matcher(hono).match(path)) is matches
