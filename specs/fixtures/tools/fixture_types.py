"""The shapes of the JSON the conformance fixture tools build and read.

``specs/fixtures/cases/*.json`` is the ground truth for every key below. A key
that only some cases carry is ``NotRequired``.
"""

from __future__ import annotations

from typing import Literal, TypeAlias, TypedDict

from typing_extensions import NotRequired

JsonValue: TypeAlias = (
    None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
)
JsonObject: TypeAlias = dict[str, JsonValue]


class DetectInput(TypedDict):
    content: str
    context: str


class DetectCase(TypedDict):
    id: str
    input: DetectInput
    expected: JsonObject
    note: NotRequired[str]


class SafetyInput(TypedDict):
    pattern: str
    mode: str
    test_strings: NotRequired[list[str]]
    max_content_length: NotRequired[int]


class SafetyExpected(TypedDict):
    safe: bool
    reason_class: str


class SafetyReference(TypedDict, total=False):
    extrapolated_seconds: float
    budget_seconds: float
    margin: float
    load_average_at_generation: float
    decided_before_timing: bool
    observed_cpu_seconds: float
    threshold_seconds: float
    kill_seconds: float
    margin_over_threshold: float
    margin_under_kill: float


class SafetyCase(TypedDict):
    id: str
    input: SafetyInput
    expected: SafetyExpected
    reference: NotRequired[SafetyReference]


class RequestStep(TypedDict, total=False):
    client_ip: str
    url_path: str
    body: str
    query_params: dict[str, str]
    method: str
    headers: dict[str, str]
    drop_cached_client_ip: bool
    guard_route_unresolved: bool
    omit_content_length: bool


class PipelineStep(RequestStep, total=False):
    stage: str
    saturate_regex_pool: bool
    modifier: str
    response_body: str
    response_status: int
    response_declared_length: int
    response_headers: dict[str, str]


class RulePayload(TypedDict):
    rule_type: Literal["usage", "return_pattern", "frequency"]
    threshold: int
    window: NotRequired[int]
    pattern: NotRequired[str | None]
    action: NotRequired[Literal["ban", "log", "throttle", "alert"]]


class AnomalySample(TypedDict):
    pattern: str
    execution_time: float
    content_length: NotRequired[int]
    matched: NotRequired[bool]
    timeout: NotRequired[bool]


class EventsStep(RequestStep, total=False):
    guard_route_template: str
    call: str
    ip: str
    duration: int
    reason: str
    provider: str
    network: str
    rule: RulePayload
    rules: JsonObject
    keep_applied: bool
    endpoint_id: str
    details: str
    content: str
    context: str
    send: str
    kwargs: JsonObject
    country: str
    blocked_countries: list[str]
    report: JsonObject
    pattern: str
    path: str
    execution_time: float
    samples: list[AnomalySample]
    slow_pattern_threshold: float
    anomaly_threshold: float
    min_samples_for_anomaly: int


class ConfigCarrier(TypedDict):
    config: NotRequired[JsonObject]


class RouterEntry(TypedDict):
    template: str
    handler: str


class PipelineCaseInput(TypedDict):
    id: str
    config: NotRequired[JsonObject]
    geo_countries: NotRequired[dict[str, str]]
    routes: NotRequired[dict[str, JsonObject]]
    custom_patterns: NotRequired[list[str]]
    router: NotRequired[list[RouterEntry]]
    drives: list[PipelineStep]


class PipelineCase(PipelineCaseInput):
    expected: list[JsonObject]


class EventsCaseInput(TypedDict):
    id: str
    config: NotRequired[JsonObject]
    geo_countries: NotRequired[dict[str, str]]
    routes: NotRequired[dict[str, JsonObject]]
    drives: list[EventsStep]
    xfail: NotRequired[bool]
    xfail_reason: NotRequired[str]


class EventsCase(EventsCaseInput):
    expected: list[JsonObject]


class RedisArgs(TypedDict, total=False):
    client_ip: str
    rate_limit: int
    rate_limit_window: int
    endpoint_path: str
    ip: str
    duration: int
    reason: str
    grouped: bool
    escalating: bool
    config: JsonObject
    endpoint_id: str
    rule: RulePayload
    response_status: int
    csp_config: dict[str, list[str]]
    hsts_config: JsonObject
    custom_headers: dict[str, str]
    pattern: str
    max_age: int
    fixture: str
    provider: str
    ranges: list[str]
    regions: dict[str, str]
    ttl: int | None
    seed: list[JsonValue]
    seed_ttl: int
    rules: JsonObject


class RedisOperation(TypedDict):
    op: str
    handler: str
    call: str
    args: RedisArgs


class RedisCaseInput(TypedDict):
    id: str
    operation: RedisOperation


class TtlRecord(TypedDict):
    set: bool
    seconds: NotRequired[int]


class ZsetMember(TypedDict):
    member: str
    score: float


class KeyProbe(TypedDict):
    key: str
    type: str
    ttl: TtlRecord
    json: NotRequired[bool]
    value: NotRequired[str]
    members: NotRequired[list[ZsetMember]]


class PinnedKey(TypedDict):
    key: str
    type: str
    ttl: TtlRecord
    value: NotRequired[str]
    value_shape: NotRequired[str]
    card: NotRequired[int]
    member_shape: NotRequired[str]
    score_shape: NotRequired[str]
    score_equals_member: NotRequired[bool]
    members: NotRequired[list[ZsetMember]]


class RedisCase(RedisCaseInput):
    prefix: str
    expected: list[PinnedKey]


class MisconfigurationCase(TypedDict):
    id: str
    input: JsonObject
    expected: JsonObject


class SuiteMeta(TypedDict):
    case_count: int
    kind: str
    consumers: list[str]
    unpinned_classes: NotRequired[dict[str, JsonObject]]
    retired_case_ids: NotRequired[list[JsonObject]]


class PrefixRule(TypedDict):
    event_type: str
    field: str
    prefix: str
    rest: str


class Comparison(TypedDict):
    threat_order: str
    excluded_fields: list[str]
    float_precision: int
    pipeline_records: str
    events_envelopes: str
    events_volatile_fields: list[str]
    events_prefix_rules: list[PrefixRule]
    events_volatile_metadata: dict[str, list[str]]
    redis_interop: str
    misconfiguration: str
    pattern_safety_records: str


SuiteCase: TypeAlias = (
    DetectCase
    | PipelineCase
    | EventsCase
    | RedisCase
    | SafetyCase
    | MisconfigurationCase
)


class CorpusIndex(TypedDict):
    spec_version: str
    engine_version: str
    engine_commit: str
    generated_at: str
    fixed_ip: str
    config_knobs: JsonObject
    pipeline_defaults: JsonObject
    suites: dict[str, SuiteMeta]
    comparison: Comparison
    cost_budgets: JsonObject
