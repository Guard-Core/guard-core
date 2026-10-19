---

title: Behavior Rules
description: API reference for BehaviorRuleConfig and SecurityConfig.global_behavior_rules
keywords: behavior rules, global behavior, 404 noise, return pattern, detection correlation, guard-core
---

Behavior Rules
==============

`BehaviorRuleConfig` is the serializable model for behavior rules. `SecurityConfig.global_behavior_rules: tuple[BehaviorRuleConfig, ...]` applies those rules to every route, in addition to any decorator-specified rules. Useful for service-wide 404 tracking, frequency caps, and detection-correlated bans.

___

BehaviorRuleConfig
------------------

```python
class BehaviorRuleConfig(BaseModel):
    rule_type: Literal["usage", "return_pattern", "frequency"]
    threshold: int = Field(ge=1)
    window: int = Field(default=3600, ge=1)
    pattern: str | None = None
    action: Literal["ban", "log", "throttle", "alert"] = "log"
    ban_duration: int | None = Field(default=None, ge=1)
    correlate_with_detection: bool = False
```

| Field                       | Type                                          | Default  | Description                                                                                  |
|-----------------------------|-----------------------------------------------|----------|----------------------------------------------------------------------------------------------|
| `rule_type`                 | `"usage" \| "return_pattern" \| "frequency"`  | required | Rule kind. `usage` and `frequency` track inbound calls; `return_pattern` matches outbound responses. |
| `threshold`                 | `int`                                         | required | Trigger count within `window` (>= 1).                                                        |
| `window`                    | `int`                                         | `3600`   | Window in seconds.                                                                           |
| `pattern`                   | `str \| None`                                 | `None`   | Match expression for `return_pattern` rules. See Return Pattern Formats below. A non-`status:` pattern requires `SecurityConfig.behavior_scan_response_body=True`; construction raises `ValueError` otherwise. |
| `action`                    | `"ban" \| "log" \| "throttle" \| "alert"`     | `"log"`  | Action when threshold is exceeded.                                                           |
| `ban_duration`              | `int \| None`                                 | `None`   | Ban duration in seconds when `action="ban"`. When `None`, falls back to a hardcoded 3600 seconds -- independent of `auto_ban_duration`, which only governs the unrelated flat penetration-detection ban path. |
| `correlate_with_detection`  | `bool`                                        | `False`  | Halve the threshold (floor 1) when the IP has any positive `suspicious_request_counts` entry. |

### Return Pattern Formats

| Format            | Example                        | Matches                                               |
|-------------------|---------------------------------|--------------------------------------------------------|
| `status:{code}`   | `status:404`                   | `response.status_code`. Always available, regardless of `behavior_scan_response_body`. |
| `json:{path}`     | `json:error.code=="AUTH_FAIL"` | JSON field value via dot-path traversal, read from the response body. |
| `regex:{pattern}` | `regex:error.*failed`          | Regex match (case-insensitive) against the response body. |
| Plain string      | `unauthorized`                 | Substring match (case-insensitive) against the response body. |

The three body-reading formats require both `SecurityConfig.behavior_scan_response_body=True` and an adapter that implements `BoundedResponseBodyReader` (see [Protocols](protocols.md#boundedresponsebodyreader)); a rule using one of them is rejected at construction if the flag is off, since it could never match. When the flag is on but the concrete response does not implement the capability (for example an adapter that has not added support yet), or, in the async `guard_core` tree, the adapter's `read_body_prefix` call exceeds `SecurityConfig.body_read_timeout` (default `3.0` seconds, bounded via `asyncio.wait_for`; `guard_core.sync` calls it directly on the request thread with no deadline), the rule evaluates to "could not evaluate" rather than a false "no match", and is logged once per pattern (throttled). Each `return_pattern` rule checked against a response performs its own independent `read_body_prefix` call; guard-core does not cache the response body prefix across rules, so a response with several such rules configured pays one bounded read per rule. Upgrading guard-core alone does not restore a previously-working body-reading rule for an adapter that has not yet shipped `BoundedResponseBodyReader` support -- see the CHANGELOG's lockstep-upgrade note.

___

SecurityConfig.global_behavior_rules
------------------------------------

```python
class SecurityConfig(BaseModel):
    global_behavior_rules: tuple[BehaviorRuleConfig, ...] = Field(default_factory=tuple)
    behavior_scan_response_body: bool = False
    behavior_max_response_body_inspect_bytes: int = 262144
```

Every entry runs against every route alongside any decorator-defined rules on that route. Global rules are evaluated by `BehavioralProcessor.process_global_return_rules()` (for `return_pattern`) and the same usage/frequency tracker the decorator rules use.

`global_behavior_rules` is a tuple, so `.append()`/`.extend()`/`.insert()` raise `AttributeError` instead of silently mutating an unvalidated list. Add a rule with a whole-field reassignment instead: `config.global_behavior_rules = (*config.global_behavior_rules, new_rule)`. Both reassignment and `model_copy(update={"global_behavior_rules": ...})` re-run the same `return_pattern`/`behavior_scan_response_body` check construction does.

`behavior_scan_response_body` and `behavior_max_response_body_inspect_bytes` gate and bound response-body reading for every `return_pattern` rule, global or decorator-attached; see [SecurityConfig - Global Behavior Rules](../configuration/security-config.md#global-behavior-rules) for the full description of both.

___

Detection-correlation semantics
-------------------------------

When `correlate_with_detection=True`, the rule's effective threshold is halved (with a floor of 1) for any IP that has any positive entry in `suspicious_request_counts`. The original threshold applies to clean IPs.

Concretely, an IP that has triggered any regex hit at least once will hit the threshold twice as fast. The audit log marks the event with `correlation=True` and the contributing categories (`correlated_categories=[...]`).

___

404-noise correlation example
-----------------------------

A canonical use is global 404 tracking that bans probes faster when they have already tripped a regex:

```python
from guard_core.models import BehaviorRuleConfig, SecurityConfig

config = SecurityConfig(
    global_behavior_rules=[
        BehaviorRuleConfig(
            rule_type="return_pattern",
            threshold=20,
            window=300,
            pattern="status:404",
            action="ban",
            ban_duration=3600,
            correlate_with_detection=True,
        ),
    ],
)
```

A clean IP that hits 20 unique 404s in 5 minutes is banned for 1 hour. An IP that already triggered (e.g.) one `recon` regex match is banned after 10 404s in the same window.

___

See also
--------

- [SecurityConfig - Global Behavior Rules](../configuration/security-config.md#global-behavior-rules)
- [Models - BehaviorRuleConfig](models.md#behaviorruleconfig)
- [Architecture - Behavioral Analysis](../internals/behavioral.md)
