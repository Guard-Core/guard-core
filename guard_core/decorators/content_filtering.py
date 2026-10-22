import logging
from collections.abc import Awaitable, Callable

from guard_core.decorators.base import BaseSecurityMixin, GuardedCallable
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse


class ContentFilteringMixin(BaseSecurityMixin):
    config: SecurityConfig

    def block_user_agents(
        self, patterns: list[str]
    ) -> Callable[[GuardedCallable], GuardedCallable]:
        from guard_core.detection_engine.compiler import PatternCompiler

        compiler = PatternCompiler()
        for pattern in patterns:
            is_safe, reason = compiler.validate_pattern_safety(
                pattern,
                max_content_length=self.config.detection_max_body_inspect_bytes,
            )
            if not is_safe:
                from guard_core._utils.detection_scan import _redact_pattern_source

                raise ValueError(
                    f"block_user_agents pattern rejected by ReDoS validator: "
                    f"{_redact_pattern_source(pattern)!r} ({reason})"
                )

        def decorator(func: GuardedCallable) -> GuardedCallable:
            route_config = self._ensure_route_config(func)
            route_config.blocked_user_agents.extend(patterns)
            return self._apply_route_config(func)

        return decorator

    def content_type_filter(
        self, allowed_types: list[str]
    ) -> Callable[[GuardedCallable], GuardedCallable]:
        def decorator(func: GuardedCallable) -> GuardedCallable:
            route_config = self._ensure_route_config(func)
            route_config.allowed_content_types = allowed_types
            return self._apply_route_config(func)

        return decorator

    def max_request_size(
        self, size_bytes: int
    ) -> Callable[[GuardedCallable], GuardedCallable]:
        if size_bytes < 0:
            raise ValueError(
                f"max_request_size must not be negative (got {size_bytes}); "
                "use None for no limit"
            )

        def decorator(func: GuardedCallable) -> GuardedCallable:
            if size_bytes == 0:
                logging.getLogger("guard_core.decorators").warning(
                    "max_request_size(0) on %s: 0 now refuses any request body; "
                    "use None for no limit",
                    getattr(func, "__qualname__", repr(func)),
                )
            route_config = self._ensure_route_config(func)
            route_config.max_request_size = size_bytes
            return self._apply_route_config(func)

        return decorator

    def require_referrer(
        self, allowed_domains: list[str]
    ) -> Callable[[GuardedCallable], GuardedCallable]:
        def decorator(func: GuardedCallable) -> GuardedCallable:
            route_config = self._ensure_route_config(func)
            route_config.require_referrer = allowed_domains
            return self._apply_route_config(func)

        return decorator

    def custom_validation(
        self,
        validator: Callable[[GuardRequest], Awaitable[GuardResponse | None]],
    ) -> Callable[[GuardedCallable], GuardedCallable]:
        def decorator(func: GuardedCallable) -> GuardedCallable:
            route_config = self._ensure_route_config(func)
            route_config.custom_validators.append(validator)
            return self._apply_route_config(func)

        return decorator

    def detection_exclusion(
        self,
        headers: set[str] | None = None,
        params: set[str] | dict[str, set[str]] | None = None,
        body_fields: set[str] | dict[str, set[str]] | None = None,
        categories: set[str] | None = None,
        scan_body: bool | None = None,
        semantic_headers: set[str] | None = None,
        path_params: set[str] | dict[str, set[str]] | None = None,
    ) -> Callable[[GuardedCallable], GuardedCallable]:
        def decorator(func: GuardedCallable) -> GuardedCallable:
            from guard_core._security_config_validators import (
                _validate_excluded_detection_params_value,
            )

            route_config = self._ensure_route_config(func)
            if headers is not None:
                route_config.excluded_detection_headers = set(headers)
            if semantic_headers is not None:
                route_config.excluded_semantic_detection_headers = set(semantic_headers)
            if params is not None:
                route_config.excluded_detection_params = (
                    _validate_excluded_detection_params_value(params)
                )
            if path_params is not None:
                from guard_core._security_config_validators import (
                    _validate_excluded_detection_params_value,
                )

                route_config.excluded_detection_path_params = (
                    _validate_excluded_detection_params_value(path_params)
                )
            if body_fields is not None:
                route_config.excluded_detection_body_fields = (
                    _validate_excluded_detection_params_value(
                        body_fields, field_name="excluded_detection_body_fields"
                    )
                )
            if categories is not None:
                route_config.enabled_detection_categories = set(categories)
            if scan_body is not None:
                route_config.detection_scan_body = scan_body
            return self._apply_route_config(func)

        return decorator
