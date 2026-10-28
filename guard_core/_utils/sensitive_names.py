import re
from collections.abc import Collection
from functools import lru_cache

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


_EMAIL_VALUE = re.compile(r"[^@\s/]+@[^@\s/]+\.[A-Za-z]{2,}")
_TOKEN_VALUE = re.compile(r"[A-Za-z0-9_\-.~+=]{20,}")
_TOKEN_CLASS_BOUNDARY = re.compile(
    r"(?<=[a-z])(?=[A-Z])|(?<=[0-9])(?=[A-Za-z])|(?<=[A-Za-z])(?=[0-9])"
)
_MIN_TOKEN_CLASS_BOUNDARIES = 4


def value_is_email_or_secret_token(value: str) -> bool:
    """An email address, or a long run of letters and digits that changes class
    (lower to upper, letter to digit) the way a random token does and a word,
    slug or file name does not."""
    if _EMAIL_VALUE.fullmatch(value):
        return True
    return (
        _TOKEN_VALUE.fullmatch(value) is not None
        and len(_TOKEN_CLASS_BOUNDARY.findall(value)) >= _MIN_TOKEN_CLASS_BOUNDARIES
    )
