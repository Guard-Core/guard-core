import re
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
