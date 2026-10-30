import pytest

from guard_core.models import SecurityConfig

SECRETS = {
    "redis_url": "redis://:hunter2@cache.internal:6379/0",
    "ipinfo_token": "tok-ipinfo-1234567890",
    "agent_api_key": "key-agent-1234567890",
    "agent_project_encryption_key": "enc-key-1234567890",
    "agent_payload_signing_secret": "sign-secret-1234567890",
}


@pytest.fixture
def config() -> SecurityConfig:
    return SecurityConfig(
        enable_agent=True,
        enable_redis=True,
        agent_api_key=SECRETS["agent_api_key"],
        agent_project_encryption_key=SECRETS["agent_project_encryption_key"],
        agent_payload_signing_secret=SECRETS["agent_payload_signing_secret"],
        ipinfo_token=SECRETS["ipinfo_token"],
        redis_url=SECRETS["redis_url"],
    )


@pytest.mark.parametrize("name", sorted(SECRETS))
def test_neither_repr_nor_str_prints_a_secret(
    config: SecurityConfig, name: str
) -> None:
    secret = SECRETS[name]
    assert secret not in repr(config)
    assert secret not in str(config)
    assert "hunter2" not in repr(config)


@pytest.mark.parametrize("name", sorted(SECRETS))
def test_the_secret_is_still_held_by_the_config(
    config: SecurityConfig, name: str
) -> None:
    assert getattr(config, name) == SECRETS[name]
