import pytest

from guard_core.sync.core.checks.helpers import is_referrer_domain_allowed

ALLOWED = ["example.com"]


@pytest.mark.parametrize(
    "referrer",
    [
        "https://evil.com\\.example.com/",
        "https://evil.com\\@example.com/",
        "https://evil.com\\.example.com:8443/",
        "https://notexample.com/",
        "https://example.com.evil.com/",
        "https://example.com:notaport/",
        "not a url",
        "",
    ],
)
def test_lookalike_and_malformed_referrers_are_rejected(referrer: str) -> None:
    assert is_referrer_domain_allowed(referrer, ALLOWED) is False
