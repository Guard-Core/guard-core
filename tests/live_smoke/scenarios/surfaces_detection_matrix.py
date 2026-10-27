from tests.live_smoke.driver import ScenarioContext
from tests.live_smoke.registry import scenario

_BASE = {
    "auto_ban_threshold": 1000,
    "rate_limit": 1000,
    "excluded_detection_headers": ["x-real-ip", "x-forwarded-for"],
    "detection_semantic_threshold": 1.0,
}

FAMILY_PAYLOADS: dict[str, tuple[str, str]] = {
    "cmd_injection": ("foo; rm -rf /tmp/x", "list files with the ls command"),
    "cms_probing": ("/wp-admin/admin-ajax.php", "a wordpress blog about gardening"),
    "code_injection": (
        "System.Diagnostics.Process.Start('cmd.exe')",
        "the system process started on time",
    ),
    "deserialization": ('O:8:"stdClass":1:{s:1:"a";s:1:"b";}', "serial number 12345"),
    "dir_traversal": ("../../../../etc/shadow", "../up one level"),
    "file_inclusion": (
        "php://filter/convert.base64-encode/resource=index",
        "include a summary paragraph",
    ),
    "file_upload": ("evil.php.jpg", "holiday.jpg"),
    "http_split": ("a%0d%0aSet-Cookie: x=1", "a line of text"),
    "ldap": ("*)(uid=*))(|(uid=*", "a directory of names"),
    "nosql": ('{"$ne": null}', "price not equal to ten"),
    "path_traversal": (
        "..%2f..%2f..%2fwindows%2fwin.ini",
        "a folder path docs",
    ),
    "proto_pollution": ("__proto__[admin]=1", "prototype design review"),
    "recon": ("/.git/HEAD", "git workflow notes"),
    "sensitive_file": ("/root/.bash_history", "the passwd reset page"),
    "sqli": ("' UNION SELECT password FROM admin--", "union station schedule"),
    "ssrf": ("http://169.254.169.254/latest/meta-data/", "http://example.com/page"),
    "template": ("{{7*7}}", "seven times seven"),
    "xml": (
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        "<note>hello</note>",
    ),
    "xss": ("<script>alert(1)</script>", "script writing tips"),
}

_FOREIGN_FAMILY = {"xss": "sqli"}
_DEFAULT_FOREIGN_FAMILY = "xss"


def _post(ctx: ScenarioContext, note: str) -> int:
    return ctx.client.post("/basic/echo", json={"note": note}).status_code


@scenario(
    covers={"surface:detection_family_matrix"},
    config={**_BASE, "enabled_detection_categories": ["xss"]},
)
def every_detection_family_flags_its_attack_and_admits_its_benign_twin(
    ctx: ScenarioContext,
) -> None:
    failures: list[str] = []
    for family, (attack, benign) in FAMILY_PAYLOADS.items():
        ctx.stack.restart_with({**_BASE, "enabled_detection_categories": [family]})
        foreign = FAMILY_PAYLOADS[_FOREIGN_FAMILY.get(family, _DEFAULT_FOREIGN_FAMILY)][
            0
        ]
        verdicts = (_post(ctx, attack), _post(ctx, benign), _post(ctx, foreign))
        expected = (400, 200, 200)
        if verdicts != expected:
            failures.append(
                f"{family}: (attack, benign, other family's attack) answered "
                f"{verdicts}, expected {expected}"
            )
    assert not failures, "\n" + "\n".join(failures)


@scenario(
    covers={"surface:default_security_headers"},
    config={
        "enable_redis": False,
        "security_headers": {"enabled": True},
        "excluded_detection_headers": ["x-real-ip", "x-forwarded-for"],
    },
)
def default_security_headers_reach_a_plain_response(ctx: ScenarioContext) -> None:
    headers = ctx.client.get("/basic/ip").headers
    expected = {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "permissions-policy": "geolocation=(), microphone=(), camera=()",
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-resource-policy": "same-site",
        "x-permitted-cross-domain-policies": "none",
        "x-download-options": "noopen",
        "x-content-type-options": "nosniff",
    }
    wrong = {
        name: headers.get(name)
        for name, value in expected.items()
        if headers.get(name) != value
    }
    assert not wrong, f"default security header values differ: {wrong}"
    assert "content-security-policy" not in headers, (
        "no CSP is configured, yet one was sent: "
        f"{headers.get('content-security-policy')}"
    )
