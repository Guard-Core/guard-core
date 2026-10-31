import re
from collections.abc import Collection
from functools import lru_cache

from guard_core._lazy_patterns import LazyPatterns, module_attribute_lookup

SENSITIVE_NAME_TOKENS: frozenset[str] = frozenset(
    {"pass", "pwd", "token", "secret", "session", "sid", "auth", "key", "otp"}
)

SENSITIVE_COMPOUND_NAMES: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "passcode",
        "authorization",
        "apikey",
        "sessionid",
    }
)

_NAME_PARTS = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")


@lru_cache(maxsize=1024)
def has_sensitive_name_token(name: str) -> bool:
    for part in _NAME_PARTS.findall(name):
        lowered = part.lower()
        if lowered in SENSITIVE_NAME_TOKENS or lowered in SENSITIVE_COMPOUND_NAMES:
            return True
    return False


_PLAIN_NAME = re.compile(r"[\w.\-]+")


def name_is_sensitive(name: str, names: Collection[str]) -> bool:
    stripped = name.strip()
    if stripped.lower() in names:
        return True
    return _PLAIN_NAME.fullmatch(stripped) is not None and has_sensitive_name_token(
        stripped
    )


_PATTERNS = LazyPatterns(
    {
        "_EMAIL_VALUE": (r"[^@\s/]+@[^@\s/]+\.[A-Za-z]{2,}", 0),
        "_TOKEN_VALUE": (r"[A-Za-z0-9_\-.~+=]{20,}", 0),
        "_TOKEN_CLASS_BOUNDARY": (
            r"(?<=[a-z])(?=[A-Z])|(?<=[0-9])(?=[A-Za-z])|(?<=[A-Za-z])(?=[0-9])",
            0,
        ),
    }
)
_lookup = module_attribute_lookup(_PATTERNS)


def __getattr__(name: str) -> re.Pattern[str]:
    return _lookup(name)


_MIN_TOKEN_CLASS_BOUNDARIES = 4


def value_is_email_or_secret_token(value: str) -> bool:
    """An email address, or a long run of letters and digits that changes class
    (lower to upper, letter to digit) the way a random token does and a word,
    slug or file name does not."""
    if _PATTERNS["_EMAIL_VALUE"].fullmatch(value):
        return True
    return (
        _PATTERNS["_TOKEN_VALUE"].fullmatch(value) is not None
        and len(_PATTERNS["_TOKEN_CLASS_BOUNDARY"].findall(value))
        >= _MIN_TOKEN_CLASS_BOUNDARIES
    )
