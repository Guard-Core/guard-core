import ast
import inspect
import textwrap
import threading
from typing import Any, cast

import pytest

from guard_core.models import SecurityConfig, SyncSecurityConfig, _skip_revalidation

BOOL_FIELDS = [
    "enable_penetration_detection",
    "enable_ip_banning",
    "enable_rate_limiting",
    "emergency_mode",
    "enable_rate_limit_auto_ban",
]

UNBOUNDED_INT_FIELDS = ["rate_limit", "rate_limit_window"]

POSITIVE_INT_FIELDS = ["auto_ban_threshold", "auto_ban_duration"]

STR_LIST_FIELDS = ["blocked_user_agents", "emergency_whitelist"]


@pytest.mark.parametrize("field_name", BOOL_FIELDS)
def test_bool_field_reassignment_rejects_non_bool(field_name: str) -> None:
    config = SyncSecurityConfig()
    with pytest.raises(ValueError, match="must be a bool"):
        setattr(config, field_name, "true")


@pytest.mark.parametrize("field_name", BOOL_FIELDS)
@pytest.mark.parametrize("value", [True, False])
def test_bool_field_reassignment_accepts_bool(field_name: str, value: bool) -> None:
    config = SyncSecurityConfig()
    setattr(config, field_name, value)
    assert getattr(config, field_name) is value


@pytest.mark.parametrize("field_name", UNBOUNDED_INT_FIELDS)
def test_unbounded_int_field_reassignment_rejects_non_int(field_name: str) -> None:
    config = SyncSecurityConfig()
    with pytest.raises(ValueError, match="must be an int"):
        setattr(config, field_name, "10")


@pytest.mark.parametrize("field_name", UNBOUNDED_INT_FIELDS)
def test_unbounded_int_field_reassignment_rejects_bool(field_name: str) -> None:
    config = SyncSecurityConfig()
    with pytest.raises(ValueError, match="must be an int"):
        setattr(config, field_name, True)


@pytest.mark.parametrize("field_name", UNBOUNDED_INT_FIELDS)
def test_unbounded_int_field_reassignment_accepts_int(field_name: str) -> None:
    config = SyncSecurityConfig()
    setattr(config, field_name, 42)
    assert getattr(config, field_name) == 42


@pytest.mark.parametrize("field_name", POSITIVE_INT_FIELDS)
def test_positive_int_field_reassignment_rejects_zero(field_name: str) -> None:
    config = SyncSecurityConfig()
    with pytest.raises(ValueError, match="must be >= 1"):
        setattr(config, field_name, 0)


@pytest.mark.parametrize("field_name", POSITIVE_INT_FIELDS)
def test_positive_int_field_reassignment_rejects_negative(field_name: str) -> None:
    config = SyncSecurityConfig()
    with pytest.raises(ValueError, match="must be >= 1"):
        setattr(config, field_name, -5)


@pytest.mark.parametrize("field_name", POSITIVE_INT_FIELDS)
def test_positive_int_field_reassignment_rejects_non_int(field_name: str) -> None:
    config = SyncSecurityConfig()
    with pytest.raises(ValueError, match="must be an int"):
        setattr(config, field_name, "5")


@pytest.mark.parametrize("field_name", POSITIVE_INT_FIELDS)
def test_positive_int_field_reassignment_accepts_boundary_value(
    field_name: str,
) -> None:
    config = SyncSecurityConfig()
    setattr(config, field_name, 1)
    assert getattr(config, field_name) == 1


@pytest.mark.parametrize("field_name", STR_LIST_FIELDS)
def test_str_list_field_reassignment_rejects_non_list(field_name: str) -> None:
    config = SyncSecurityConfig()
    with pytest.raises(ValueError, match="must be a list of str"):
        setattr(config, field_name, "not-a-list")


@pytest.mark.parametrize("field_name", STR_LIST_FIELDS)
def test_str_list_field_reassignment_rejects_non_str_element(field_name: str) -> None:
    config = SyncSecurityConfig()
    with pytest.raises(ValueError, match="must be a list of str"):
        setattr(config, field_name, ["ok", 2])


@pytest.mark.parametrize(
    ("field_name", "value"),
    [("blocked_user_agents", ["ok"]), ("emergency_whitelist", ["192.0.2.1"])],
)
def test_str_list_field_reassignment_accepts_str_list(
    field_name: str, value: list[str]
) -> None:
    config = SyncSecurityConfig()
    setattr(config, field_name, value)
    assert getattr(config, field_name) == value


_CATASTROPHIC_USER_AGENT_PATTERN = r"(?:a+)+$"


def test_blocked_user_agents_construction_rejects_catastrophic_pattern() -> None:
    with pytest.raises(ValueError, match="rejected by ReDoS validator"):
        SyncSecurityConfig(blocked_user_agents=[_CATASTROPHIC_USER_AGENT_PATTERN])


def test_blocked_user_agents_reassignment_rejects_catastrophic_pattern() -> None:
    config = SyncSecurityConfig()
    with pytest.raises(ValueError, match="rejected by ReDoS validator"):
        config.blocked_user_agents = [_CATASTROPHIC_USER_AGENT_PATTERN]


def test_blocked_user_agents_construction_accepts_safe_pattern() -> None:
    config = SyncSecurityConfig(blocked_user_agents=["badbot"])
    assert config.blocked_user_agents == ["badbot"]


_P0_FIBONACCI_REDOS_USER_AGENT_PATTERN = r"(\d\d?)+$"


@pytest.mark.redos_timing
def test_blocked_user_agents_construction_rejects_fibonacci_redos_pattern() -> None:
    with pytest.raises(ValueError, match="rejected by ReDoS validator"):
        SyncSecurityConfig(blocked_user_agents=[_P0_FIBONACCI_REDOS_USER_AGENT_PATTERN])


_CATASTROPHIC_DANGEROUS_CONSTRUCT_PATTERN = r"(a+)+"


def test_set_prevalidated_skip_flag_is_not_shared_across_threads() -> None:
    config = SyncSecurityConfig()
    bypassed = threading.Event()
    stop = threading.Event()

    def safe_toggler() -> None:
        while not stop.is_set():
            config._set_prevalidated("blocked_user_agents", ["safe-bot"])

    def attacker() -> None:
        for _ in range(2000):
            try:
                config.blocked_user_agents = [_CATASTROPHIC_DANGEROUS_CONSTRUCT_PATTERN]
            except ValueError:
                config.blocked_user_agents = []
                continue
            bypassed.set()
            return

    toggler_thread = threading.Thread(target=safe_toggler, daemon=True)
    attacker_thread = threading.Thread(target=attacker)
    toggler_thread.start()
    attacker_thread.start()
    attacker_thread.join()
    stop.set()

    assert not bypassed.is_set()


def test_set_prevalidated_stays_synchronous_with_no_await_between_set_and_reset() -> (
    None
):
    source = textwrap.dedent(inspect.getsource(SecurityConfig._set_prevalidated))
    func_node = ast.parse(source).body[0]
    assert isinstance(func_node, ast.FunctionDef), (
        "SecurityConfig._set_prevalidated must stay a synchronous def; making it "
        "async and awaiting between the ContextVar set() and reset() (for "
        "example via asyncio.to_thread) copies the context into a worker and "
        "can leak the _skip_revalidation bypass flag past the setattr it "
        "was meant to guard"
    )
    assert not any(isinstance(node, ast.Await) for node in ast.walk(func_node)), (
        "an was introduced inside SecurityConfig._set_prevalidated; this "
        "reopens the asyncio.to_thread context-leak bug the synchronous "
        "set()/setattr()/reset() sequence was written to avoid"
    )


def test_set_prevalidated_skip_flag_does_not_survive_model_copy() -> None:
    config = SyncSecurityConfig()
    token = _skip_revalidation.set(True)
    try:
        copy = config.model_copy()
    finally:
        _skip_revalidation.reset(token)

    assert _skip_revalidation.get() is False
    with pytest.raises(ValueError, match="rejected by ReDoS validator"):
        copy.blocked_user_agents = [_CATASTROPHIC_DANGEROUS_CONSTRUCT_PATTERN]


def test_endpoint_rate_limits_reassignment_rejects_non_dict() -> None:
    config = SyncSecurityConfig()
    bad_value: dict[str, tuple[int, int]] = cast(Any, "nope")
    with pytest.raises(ValueError, match="must be a dict"):
        config.endpoint_rate_limits = bad_value


def test_endpoint_rate_limits_reassignment_rejects_non_str_key() -> None:
    config = SyncSecurityConfig()
    bad_value: dict[str, tuple[int, int]] = cast(Any, {1: (5, 60)})
    with pytest.raises(ValueError, match="keys must be str"):
        config.endpoint_rate_limits = bad_value


def test_endpoint_rate_limits_reassignment_rejects_wrong_tuple_length() -> None:
    config = SyncSecurityConfig()
    bad_value: dict[str, tuple[int, int]] = cast(Any, {"/api": (5, 60, 1)})
    with pytest.raises(ValueError, match=r"\(int, int\) tuple"):
        config.endpoint_rate_limits = bad_value


def test_endpoint_rate_limits_reassignment_rejects_non_int_entry() -> None:
    config = SyncSecurityConfig()
    bad_value: dict[str, tuple[int, int]] = cast(Any, {"/api": (5.5, 60)})
    with pytest.raises(ValueError, match=r"\(int, int\) tuple"):
        config.endpoint_rate_limits = bad_value


def test_endpoint_rate_limits_reassignment_accepts_valid_mapping() -> None:
    config = SyncSecurityConfig()
    config.endpoint_rate_limits = {"/api": (5, 60)}
    assert config.endpoint_rate_limits == {"/api": (5, 60)}
