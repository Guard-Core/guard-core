---

title: Behavioral Analysis
description: BehaviorTracker and BehavioralProcessor internals for usage monitoring, return pattern detection, and action enforcement in guard-core
keywords: behavioral analysis, behavior tracking, usage rules, return patterns, guard-core
---

Behavioral Analysis
===================

Guard-core provides behavioral analysis through two components: the `BehaviorTracker` handler that stores and evaluates behavioral data, and the `BehavioralProcessor` core module that integrates tracking into the middleware pipeline.

BehaviorRule
------------

```python
class BehaviorRule:
    def __init__(
        self,
        rule_type: Literal["usage", "return_pattern", "frequency"],
        threshold: int,
        window: int = 3600,
        pattern: str | None = None,
        action: Literal["ban", "log", "throttle", "alert"] = "log",
        custom_action: Callable | None = None,
        ban_duration: int | None = None,
        correlate_with_detection: bool = False,
    ): ...
```

| Field           | Type                                     | Description                                     |
|-----------------|------------------------------------------|-------------------------------------------------|
| `rule_type`     | `"usage" \| "return_pattern" \| "frequency"` | When the rule is evaluated                     |
| `threshold`     | `int`                                    | Number of occurrences before triggering         |
| `window`        | `int`                                    | Time window in seconds                          |
| `pattern`       | `str \| None`                            | Pattern for `return_pattern` rules              |
| `action`        | `"ban" \| "log" \| "throttle" \| "alert"` | Action to take when threshold is exceeded       |
| `custom_action` | `Callable \| None`                       | Override function `(client_ip, endpoint_id, details)` |
| `ban_duration`  | `int \| None`                            | Ban duration in seconds when `action="ban"`. Falls back to a hardcoded 3600 seconds when `None`, independent of `SecurityConfig.auto_ban_duration`. |
| `correlate_with_detection` | `bool`                        | Halve the effective threshold (floor 1) when the IP already has a positive `suspicious_request_counts` entry. |

### Rule Types

**`usage`** and **`frequency`**: Track how many times a client IP calls a specific endpoint within the window.

**`return_pattern`**: Track how many times a response matches a pattern for a specific client IP and endpoint.

Evaluation phase: `usage` and `frequency` rules run in the request phase, after the security pipeline allowed the request and before the application handles it. `return_pattern` rules run in the response phase, after the response exists. A rule that crosses its threshold acts on the request that crossed it (the request is still served) and the action, such as a ban, applies from the next request. This is intended.

### Return Pattern Formats

| Format           | Example                       | Matches                                      |
|------------------|-------------------------------|----------------------------------------------|
| `status:{code}`  | `status:404`                  | Response status code. Always evaluable, regardless of `behavior_scan_response_body`. |
| `json:{path}`    | `json:error.code=="AUTH_FAIL"`| JSON field value via dot-path traversal, read from the response body |
| `regex:{pattern}`| `regex:error.*failed`         | Regex match against response body (case-insensitive) |
| Plain string     | `unauthorized`                | Substring match in response body (case-insensitive) |

The three body-reading formats require `SecurityConfig.behavior_scan_response_body=True`; a rule using one of them is rejected at construction (`ValueError`) if the flag is off, both for `global_behavior_rules` (a `SecurityConfig` model validator) and for `@security.return_monitor()` / `@security.behavior_analysis()` (checked at decoration time in `BehavioralMixin`). See [Response Body Access](#response-body-access) below.

___

BehaviorTracker
---------------

### Storage

**In-memory**: `defaultdict(lambda: defaultdict(list))` mapping `endpoint_id -> client_ip -> list[timestamp]`.

**Redis**: One sorted set per `(endpoint_id, client_ip)` pair (`usage`/`frequency` rules) or per `(endpoint_id, client_ip, rule.pattern)` triple (`return_pattern` rules), keyed as `behavior:usage:{sha256(endpoint_id)}:{sha256(client_ip)}` or `behavior:return:{sha256(endpoint_id)}:{sha256(client_ip)}:{sha256(rule.pattern)}`. Each hit is `ZADD`-ed as a member scored by the event timestamp; the member itself is `uuid.uuid4().hex`, not the timestamp, since a sorted set stores one entry per unique member and two hits sharing a timestamp -- routine under a coarse clock or a concurrent burst -- would otherwise collapse into one counted entry. Entries scored below the window start are pruned with `ZREMRANGEBYSCORE`, and the remaining `ZCARD` is the count compared against the threshold, all in one pipelined round trip (`RedisManager.record_sliding_window_hit`). The key's TTL is refreshed to the rule window on every hit. Hashing each segment keeps `endpoint_id`, `client_ip`, and `rule.pattern` -- all three attacker- or operator-influenced and none validated by this layer -- from ever reaching a Redis key or pattern verbatim, and the design needs no `KEYS`/glob scan at all: counting reads and writes a single addressed key.

**Thread safety**: `BehaviorTracker.__init__` builds a `threading.Lock` (`self._lock`) that guards every read and write of `usage_counts`/`return_patterns` -- `get_recent_event_count`, and the in-memory branch of `track_endpoint_usage`/`track_return_pattern`. In the async `guard_core` tree this lock is never contended (asyncio is single-threaded and no `await` happens while it is held), so it costs one uncontended acquire per call. In the sync `guard_core.sync` tree, where a WSGI deployment runs real OS threads, it is load-bearing: without it, a reader iterating `usage_counts.values()` while a writer evicts or inserts an endpoint concurrently raises `RuntimeError: dictionary changed size during iteration`.

### Key Methods

**`track_endpoint_usage(endpoint_id, client_ip, rule) -> bool`**

Records a usage event and returns `True` if the count exceeds `rule.threshold` within `rule.window`.

**`track_return_pattern(endpoint_id, client_ip, response, rule, effective_threshold=None) -> bool`**

Checks if the response matches `rule.pattern`, records the event if it does, and returns `True` if the count exceeds the threshold. `effective_threshold`, when given, is compared instead of `rule.threshold` -- this is how the caller applies `correlate_with_detection`'s halved threshold. A pattern that could not be evaluated (see below) is treated the same as "did not match": no occurrence is recorded and the threshold cannot be exceeded from it.

### Response Body Access

`_check_response_pattern(response, pattern) -> bool | None` is the private method `track_return_pattern` calls to evaluate a single pattern against a single response. Its `status:` branch is unconditional: it reads `response.status_code` and returns a plain `bool`, unaffected by anything below.

For the three body-reading formats, it never reads `GuardResponse.body` and never probes for readability with `hasattr` -- both would make a body that *cannot* be read indistinguishable from a body that is *absent*, which is exactly the bug this design closes (a streaming response's `.body` property raising `AttributeError` used to be swallowed by `hasattr`, silently returning "no match" for every response with a real, unread payload). Instead it does, in order:

1. If `SecurityConfig.behavior_scan_response_body` is `False`, no body is read; the pattern **cannot be evaluated**.
2. Otherwise it checks, via `isinstance`, whether `response` implements the optional `BoundedResponseBodyReader` capability (`async def read_body_prefix(self, max_bytes: int) -> bytes`). An `isinstance` check against a `runtime_checkable` `Protocol` never invokes a method member, so this is safe even against a response whose (unrelated) `.body` property would raise. If the response does not implement it, the pattern **cannot be evaluated**.
3. Otherwise it calls `read_body_prefix(behavior_max_response_body_inspect_bytes)` and defensively re-slices the result to the same cap. In the async `guard_core` tree, this call is bounded by `SecurityConfig.body_read_timeout` (default `3.0` seconds) so a stalled adapter cannot hang the request; the sync `guard_core.sync` tree calls it directly and is not bounded by this field at all -- a stalled sync adapter blocks the request for as long as it takes, and the WSGI server's own request timeout is the layer meant to bound that. If the call raises, times out (async only), or returns something other than `bytes`, the pattern **cannot be evaluated**. Inside `ErrorResponseFactory.process_response` the read is shared: one `ResponseBodyPrefetch` per call (created for that response, never keyed on the response object, so a `__slots__` response or an adapter-pooled one cannot serve a stale prefix) serves every `return_pattern` rule and a `custom_response_modifier` that reads `.body`, so a response with several such rules pays one bounded read. A rule evaluated outside `process_response` (a direct `_check_response_pattern` call) still calls `read_body_prefix` itself.
4. Only once bytes are actually in hand does it decode and match against `json:` / `regex:` / substring.

"Cannot be evaluated" is a `None` return, distinct from `False` ("evaluated, did not match"). It is logged once per distinct pattern through the same `TTLCache(maxsize=1000, ttl=300)` throttle used elsewhere in this file (`_body_unavailable_log_cache`), so a hot endpoint with an unsupported response type logs at most once per five minutes per pattern rather than once per request. `track_return_pattern` folds `None` into "no occurrence recorded" (see above) -- it never reports a match it did not observe, and it never silently drops a rule without at least one log line explaining why.

Because the response body is application-produced rather than attacker-supplied, `behavior_max_response_body_inspect_bytes` bounds what guard-core *retains*, not what the endpoint produces: an adapter's `read_body_prefix` implementation must buffer at most that many bytes and must still deliver the full, unbounded body to the client afterward, so a large download or an SSE stream stays streaming. See [Protocols - BoundedResponseBodyReader](../api/protocols.md#boundedresponsebodyreader) for the adapter-side contract.

### Action Execution

```python
await tracker.apply_action(rule, client_ip, endpoint_id, details)
```

**Active mode** actions:

| Action     | Behavior                                                   |
|------------|-----------------------------------------------------------|
| `ban`      | Calls `ip_ban_manager.ban_ip(client_ip, rule.ban_duration or 3600, "behavioral_violation")` |
| `log`      | Logs a warning                                             |
| `throttle` | Logs a warning (throttling is informational; rate limiting handles enforcement) |
| `alert`    | Logs at CRITICAL level                                     |
| Custom     | Calls `rule.custom_action(client_ip, endpoint_id, details)`. An exception raised by it is logged at ERROR level and the action is reported as `tracked` |

**Passive mode**: All actions are logged with a `[PASSIVE MODE]` prefix instead of being executed.

___

BehavioralProcessor
-------------------

The processor integrates behavioral tracking into the middleware pipeline. It is called at two points in the request lifecycle:

### Usage Rules (Pre-Handler)

```python
await processor.process_usage_rules(request, client_ip, route_config)
```

Iterates over `route_config.behavior_rules` where `rule_type` is `"usage"` or `"frequency"`. For each rule that exceeds its threshold, emits a `decorator_violation` event and applies the rule's action.

### Return Rules (Post-Handler)

```python
await processor.process_return_rules(request, response, client_ip, route_config)
```

Iterates over rules where `rule_type` is `"return_pattern"`. Checks if the response matches the rule's pattern, and if the threshold is exceeded, emits an event and applies the action.

### Endpoint ID Resolution

```python
def get_endpoint_id(self, request: GuardRequest) -> str
```

Resolves the endpoint identifier from the request:

1. If `request.state.guard_endpoint_id` exists, returns that value directly.
2. Otherwise, falls back to `"{method}:{url_path}"`.

___

Configuration via Decorators
-----------------------------

Behavioral rules are attached to routes through the `SecurityDecorator`:

```python
from guard_core.decorators import SecurityDecorator
from guard_core.handlers.behavior_handler import BehaviorRule

security = SecurityDecorator(config)


@security.behavior_analysis(
    rules=[
        BehaviorRule(
            rule_type="usage",
            threshold=100,
            window=300,
            action="throttle",
        ),
        BehaviorRule(
            rule_type="return_pattern",
            threshold=10,
            window=60,
            pattern="status:429",
            action="ban",
        ),
    ]
)
async def my_endpoint(): ...
```
