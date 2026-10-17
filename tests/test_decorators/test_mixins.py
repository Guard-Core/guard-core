import pytest

from guard_core.decorators.access_control import AccessControlMixin
from guard_core.decorators.advanced import AdvancedMixin, _SimpleResponse
from guard_core.decorators.authentication import AuthenticationMixin
from guard_core.decorators.base import BaseSecurityDecorator
from guard_core.decorators.behavioral import BehavioralMixin
from guard_core.decorators.content_filtering import ContentFilteringMixin
from guard_core.decorators.rate_limiting import RateLimitingMixin
from guard_core.models import VALID_CLOUD_PROVIDERS, SecurityConfig
from tests.conftest import MockGuardRequest


class ComposedDecorator(
    BaseSecurityDecorator,
    AccessControlMixin,
    AdvancedMixin,
    AuthenticationMixin,
    BehavioralMixin,
    ContentFilteringMixin,
    RateLimitingMixin,
):
    pass


def _decorator() -> ComposedDecorator:
    config = SecurityConfig(enable_redis=False)
    return ComposedDecorator(config)


def _sample_func() -> None:
    pass


async def test_require_ip_whitelist() -> None:
    d = _decorator()
    decorated = d.require_ip(whitelist=["10.0.0.1"])(_sample_func)
    route_id = decorated._guard_route_id
    rc = d.get_route_config(route_id)
    assert rc is not None
    assert rc.ip_whitelist == ["10.0.0.1"]


async def test_require_ip_blacklist() -> None:
    d = _decorator()
    decorated = d.require_ip(blacklist=["10.0.0.2"])(_sample_func)
    route_id = decorated._guard_route_id
    rc = d.get_route_config(route_id)
    assert rc is not None
    assert rc.ip_blacklist == ["10.0.0.2"]


async def test_block_countries() -> None:
    d = _decorator()
    decorated = d.block_countries(["CN", "RU"])(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.blocked_countries == ["CN", "RU"]


async def test_allow_countries() -> None:
    d = _decorator()
    decorated = d.allow_countries(["US", "UK"])(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.whitelist_countries == ["US", "UK"]


async def test_block_clouds_default() -> None:
    d = _decorator()
    decorated = d.block_clouds()(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.block_cloud_providers == set(VALID_CLOUD_PROVIDERS)


async def test_block_clouds_specific() -> None:
    d = _decorator()
    decorated = d.block_clouds(providers=["AWS"])(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.block_cloud_providers == {"AWS"}


async def test_bypass() -> None:
    d = _decorator()
    decorated = d.bypass(["ip", "rate_limit"])(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert "ip" in rc.bypassed_checks
    assert "rate_limit" in rc.bypassed_checks


async def test_require_https() -> None:
    d = _decorator()
    decorated = d.require_https()(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.require_https is True


async def test_require_auth_bearer() -> None:
    d = _decorator()
    decorated = d.require_auth(type="bearer")(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.auth_required == "bearer"
    assert rc.auth_verifier is None


async def test_require_auth_bearer_with_verifier() -> None:
    def verifier(_request: object, credential: str) -> object:
        return credential

    d = _decorator()
    decorated = d.require_auth(type="bearer", verifier=verifier)(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.auth_required == "bearer"
    assert rc.auth_verifier is verifier


async def test_require_auth_basic() -> None:
    d = _decorator()
    decorated = d.require_auth(type="basic")(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.auth_required == "basic"


async def test_api_key_auth() -> None:
    d = _decorator()
    decorated = d.api_key_auth(header_name="X-API-Key")(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.api_key_required is True
    assert rc.required_headers["X-API-Key"] == "required"
    assert rc.api_key_header == "X-API-Key"
    assert rc.api_key_verifier is None


async def test_api_key_auth_with_verifier() -> None:
    def verifier(_request: object, credential: str) -> object:
        return credential

    d = _decorator()
    decorated = d.api_key_auth(header_name="X-Key", verifier=verifier)(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.api_key_header == "X-Key"
    assert rc.api_key_verifier is verifier


async def test_require_authorization_header() -> None:
    d = _decorator()
    decorated = d.require_authorization_header(scheme="bearer")(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.authorization_header_required == "bearer"
    assert rc.auth_required is None
    assert rc.auth_verifier is None


async def test_require_auth_conflicts_with_authorization_header() -> None:
    d = _decorator()
    d.require_authorization_header(scheme="bearer")(_sample_func)
    with pytest.raises(ValueError, match="require_authorization_header"):
        d.require_auth(type="bearer")(_sample_func)


async def test_api_key_auth_conflicts_with_authorization_header() -> None:
    d = _decorator()
    d.require_authorization_header(scheme="bearer")(_sample_func)
    with pytest.raises(ValueError, match="require_authorization_header"):
        d.api_key_auth(header_name="X-Key")(_sample_func)


async def test_require_authorization_header_conflicts_with_auth_required() -> None:
    d = _decorator()
    d.require_auth(type="bearer")(_sample_func)
    with pytest.raises(ValueError, match="require_authorization_header"):
        d.require_authorization_header(scheme="bearer")(_sample_func)


async def test_require_authorization_header_conflicts_with_api_key() -> None:
    d = _decorator()
    d.api_key_auth(header_name="X-Key")(_sample_func)
    with pytest.raises(ValueError, match="require_authorization_header"):
        d.require_authorization_header(scheme="bearer")(_sample_func)


async def test_require_headers() -> None:
    d = _decorator()
    decorated = d.require_headers({"X-Custom": "required"})(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.required_headers.get("X-Custom") == "required"


async def test_time_window() -> None:
    d = _decorator()
    decorated = d.time_window("09:00", "17:00", timezone="US/Eastern")(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.time_restrictions is not None
    assert rc.time_restrictions["start"] == "09:00"
    assert rc.time_restrictions["end"] == "17:00"


async def test_suspicious_detection() -> None:
    d = _decorator()
    decorated = d.suspicious_detection(enabled=False)(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.enable_suspicious_detection is False


async def test_honeypot_detection_json_trigger() -> None:
    d = _decorator()
    decorated = d.honeypot_detection(trap_fields=["honeypot"])(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert len(rc.custom_validators) == 1
    validator = rc.custom_validators[0]
    req = MockGuardRequest(
        method="POST",
        headers={"content-type": "application/json", "content-length": "22"},
        body_content=b'{"honeypot": "filled"}',
    )
    result = await validator(req)
    assert result is not None
    assert result.status_code == 403


async def test_honeypot_detection_json_no_trigger() -> None:
    d = _decorator()
    decorated = d.honeypot_detection(trap_fields=["honeypot"])(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    validator = rc.custom_validators[0]
    req = MockGuardRequest(
        method="POST",
        headers={"content-type": "application/json", "content-length": "15"},
        body_content=b'{"name": "test"}',
    )
    result = await validator(req)
    assert result is None


async def test_honeypot_detection_form_trigger() -> None:
    d = _decorator()
    decorated = d.honeypot_detection(trap_fields=["honeypot"])(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    validator = rc.custom_validators[0]
    req = MockGuardRequest(
        method="POST",
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "content-length": "16",
        },
        body_content=b"honeypot=filled",
    )
    result = await validator(req)
    assert result is not None
    assert result.status_code == 403


async def test_honeypot_detection_get_request() -> None:
    d = _decorator()
    decorated = d.honeypot_detection(trap_fields=["honeypot"])(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    validator = rc.custom_validators[0]
    req = MockGuardRequest(method="GET")
    result = await validator(req)
    assert result is None


async def test_honeypot_detection_unknown_content_type() -> None:
    d = _decorator()
    decorated = d.honeypot_detection(trap_fields=["honeypot"])(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    validator = rc.custom_validators[0]
    req = MockGuardRequest(
        method="POST",
        headers={"content-type": "text/plain", "content-length": "16"},
        body_content=b"honeypot=filled",
    )
    result = await validator(req)
    assert result is None


async def test_honeypot_detection_form_no_trigger() -> None:
    d = _decorator()
    decorated = d.honeypot_detection(trap_fields=["honeypot"])(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    validator = rc.custom_validators[0]
    req = MockGuardRequest(
        method="POST",
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "content-length": "9",
        },
        body_content=b"name=test",
    )
    result = await validator(req)
    assert result is None


async def test_honeypot_detection_invalid_json() -> None:
    d = _decorator()
    decorated = d.honeypot_detection(trap_fields=["honeypot"])(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    validator = rc.custom_validators[0]
    req = MockGuardRequest(
        method="POST",
        headers={"content-type": "application/json", "content-length": "15"},
        body_content=b"not json at all",
    )
    result = await validator(req)
    assert result is None


async def test_block_user_agents() -> None:
    d = _decorator()
    decorated = d.block_user_agents(["badbot", "scanner"])(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert "badbot" in rc.blocked_user_agents


def test_block_user_agents_rejects_catastrophic_pattern() -> None:
    d = _decorator()
    with pytest.raises(ValueError, match="rejected by ReDoS validator"):
        d.block_user_agents([r"(?:a+)+$"])


async def test_content_type_filter() -> None:
    d = _decorator()
    decorated = d.content_type_filter(["application/json"])(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.allowed_content_types == ["application/json"]


async def test_max_request_size() -> None:
    d = _decorator()
    decorated = d.max_request_size(1024)(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.max_request_size == 1024


async def test_require_referrer() -> None:
    d = _decorator()
    decorated = d.require_referrer(["example.com"])(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.require_referrer == ["example.com"]


async def test_custom_validation() -> None:
    async def my_validator(_request: object) -> None:
        return None

    d = _decorator()
    decorated = d.custom_validation(my_validator)(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert my_validator in rc.custom_validators


async def test_rate_limit() -> None:
    d = _decorator()
    decorated = d.rate_limit(100, window=30)(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.rate_limit == 100
    assert rc.rate_limit_window == 30


async def test_geo_rate_limit() -> None:
    d = _decorator()
    decorated = d.geo_rate_limit({"US": (100, 60), "*": (50, 60)})(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.geo_rate_limits is not None
    assert "US" in rc.geo_rate_limits


async def test_usage_monitor() -> None:
    d = _decorator()
    decorated = d.usage_monitor(max_calls=100, window=3600, action="ban")(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert len(rc.behavior_rules) == 1
    assert rc.behavior_rules[0].rule_type == "usage"


async def test_return_monitor() -> None:
    d = ComposedDecorator(
        SecurityConfig(enable_redis=False, behavior_scan_response_body=True)
    )
    decorated = d.return_monitor(
        pattern="error", max_occurrences=5, window=86400, action="log"
    )(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert len(rc.behavior_rules) == 1
    assert rc.behavior_rules[0].rule_type == "return_pattern"


async def test_return_monitor_status_pattern_does_not_require_body_scan() -> None:
    d = _decorator()
    decorated = d.return_monitor(
        pattern="status:500", max_occurrences=5, window=86400, action="log"
    )(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.behavior_rules[0].pattern == "status:500"


async def test_return_monitor_body_pattern_rejected_when_body_scan_disabled() -> None:
    d = _decorator()
    with pytest.raises(ValueError, match="behavior_scan_response_body"):
        d.return_monitor(pattern="error", max_occurrences=5, window=86400, action="log")


async def test_behavior_analysis_body_pattern_rejected_when_body_scan_disabled() -> (
    None
):
    from guard_core.handlers.behavior_handler import BehaviorRule

    d = _decorator()
    rules = [
        BehaviorRule(
            rule_type="return_pattern", threshold=5, pattern="json:status==ok"
        ),
    ]
    with pytest.raises(ValueError, match="behavior_scan_response_body"):
        d.behavior_analysis(rules)


async def test_behavior_analysis() -> None:
    from guard_core.handlers.behavior_handler import BehaviorRule

    rules = [
        BehaviorRule(rule_type="usage", threshold=10, window=60, action="log"),
    ]
    d = _decorator()
    decorated = d.behavior_analysis(rules)(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert len(rc.behavior_rules) == 1


async def test_suspicious_frequency() -> None:
    d = _decorator()
    decorated = d.suspicious_frequency(max_frequency=2.0, window=300, action="alert")(
        _sample_func
    )
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert len(rc.behavior_rules) == 1
    assert rc.behavior_rules[0].rule_type == "frequency"


async def test_simple_response_properties() -> None:
    resp = _SimpleResponse("Forbidden", 403)
    assert resp.status_code == 403
    assert resp.body == b"Forbidden"
    assert isinstance(resp.headers, dict)
