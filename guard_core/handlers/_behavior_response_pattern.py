import json
import logging
import re
from typing import Protocol, runtime_checkable

from cachetools import TTLCache

from guard_core._utils.capability import has_callable
from guard_core._utils.response_prefetch import read_shared_prefix
from guard_core.handlers._behavior_json_pattern import BehaviorJsonPatternMixin
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse


@runtime_checkable
class _BoundedResponseBodyReader(Protocol):
    async def read_body_prefix(self, max_bytes: int) -> bytes: ...


class BehaviorResponsePatternMixin(BehaviorJsonPatternMixin):
    config: SecurityConfig
    logger: logging.Logger
    _body_unavailable_log_cache: TTLCache[str, bool]

    def _log_body_unavailable(self, pattern: str) -> None:
        if self._body_unavailable_log_cache.get(pattern) is not None:
            return
        self._body_unavailable_log_cache[pattern] = True
        from guard_core._utils.detection_scan import _redact_pattern_source

        self.logger.warning(
            "return_pattern rule with pattern %r could not be evaluated: "
            "the response does not support bounded body reading "
            "(BoundedResponseBodyReader), so its body cannot be inspected",
            _redact_pattern_source(pattern),
        )

    async def _read_response_body_prefix(
        self, response: GuardResponse, pattern: str
    ) -> bytes | None:
        if not self.config.behavior_scan_response_body:
            return None

        if not has_callable(response, "read_body_prefix"):
            self._log_body_unavailable(pattern)
            return None

        max_bytes = self.config.behavior_max_response_body_inspect_bytes
        prefix = await read_shared_prefix(
            response, max_bytes, self.config.body_read_timeout
        )

        if prefix is None:
            self._log_body_unavailable(pattern)
            return None

        return prefix

    async def _check_response_pattern(
        self, response: GuardResponse, pattern: str
    ) -> bool | None:
        try:
            if pattern.startswith("status:"):
                expected_status = int(pattern.split(":", 1)[1])
                return response.status_code == expected_status

            raw_body = await self._read_response_body_prefix(response, pattern)
            if raw_body is None:
                return None

            if not raw_body:
                return False

            body_str = raw_body.decode("utf-8", errors="surrogateescape")

            if pattern.startswith("json:"):
                json_pattern = pattern.split(":", 1)[1]
                try:
                    response_json = json.loads(body_str)
                    return self._match_json_pattern(response_json, json_pattern)
                except json.JSONDecodeError:
                    return False

            if pattern.startswith("regex:"):
                regex_pattern = pattern.split(":", 1)[1]
                return bool(re.search(regex_pattern, body_str, re.IGNORECASE))

            return pattern.lower() in body_str.lower()
        except Exception as e:
            self.logger.error(f"Error checking response pattern: {str(e)}")
            return False
