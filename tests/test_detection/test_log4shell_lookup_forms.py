import json

import pytest

from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

LOOKUP_FORMS_BLOCKED_AT_V440 = [
    "${jndi:ldap://x/a}",
    "${jndi:ldaps://x/a}",
    "${jndi:iiop://x/a}",
    "${jndi:nis://x/a}",
    "${jndi:corba://x/a}",
    "${jndi:http://x/a}",
    "${${::-j}${::-n}di:ldap://x/a}",
    "${j${::-n}di:ldap://x/a}",
    "${${lower:jndi}:ldap://x/a}",
    "${${env:NaN:-j}ndi:ldap://x/a}",
    "${jndi:${lower:l}dap://x/a}",
    "${jn${::-d}i:ldap://x/a}",
    "${${lower:j}${lower:n}${lower:d}i:${lower:l}dap://x/a}",
    "${env:AWS_SECRET_ACCESS_KEY}",
    "${sys:java.version}",
    "${ctx:user}",
    "${java:os}",
    "${bundle:app:key}",
]
OTHER_LOOKUP_PREFIXES = [
    "main",
    "date",
    "base64",
    "lower",
    "upper",
    "marker",
    "sd",
    "map",
    "k8s",
    "docker",
    "spring",
    "web",
    "log4j",
]
OTHER_PREFIX_FORMS = [f"${{{name}:x}}" for name in OTHER_LOOKUP_PREFIXES]
OBFUSCATED_FORMS = [
    "${${upper:j}ndi:ldap://x/a}",
    "${$lower:j}ndi",
    "${${lower:${lower:j}}ndi:ldap://x/a}",
    "${jndi${::-:}ldap://x/a}",
    "${JnDi:LDAP://x/a}",
]
BLOCKED_FORMS = LOOKUP_FORMS_BLOCKED_AT_V440 + OTHER_PREFIX_FORMS + OBFUSCATED_FORMS

BENIGN_FORMS = [
    "${name}",
    "Use ${var} in shell scripts",
    "${HOME}",
    "${HOME}/bin",
    "$(CC)",
    "$(RM)",
    "cc $(CFLAGS) -o x",
    "${server.port:8080}",
    "${PATH:-/usr/bin}",
    "price is $5 {a}",
    "${a}${b}",
    "${1}",
]


async def _flagged(value: str, surface: str) -> bool:
    if surface == "query":
        request = MockGuardRequest(path="/s", query_params={"q": value})
    elif surface == "header":
        request = MockGuardRequest(path="/s", headers={"user-agent": value})
    else:
        raw = json.dumps({"a": value}).encode()
        request = MockGuardRequest(
            method="POST",
            path="/s",
            headers={
                "content-type": "application/json",
                "content-length": str(len(raw)),
            },
            body_content=raw,
        )
    result = await detect_penetration_attempt(
        request, SecurityConfig(enable_redis=False)
    )
    return result.is_threat


@pytest.mark.parametrize("surface", ["header", "query", "json"])
@pytest.mark.parametrize("value", BLOCKED_FORMS)
async def test_every_log4j_lookup_form_is_flagged(value: str, surface: str) -> None:
    assert await _flagged(value, surface) is True


@pytest.mark.parametrize("surface", ["header", "query", "json"])
@pytest.mark.parametrize("value", BENIGN_FORMS)
async def test_plain_dollar_brace_values_stay_clean(value: str, surface: str) -> None:
    assert await _flagged(value, surface) is False
