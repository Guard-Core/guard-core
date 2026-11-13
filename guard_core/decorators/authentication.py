import logging
from collections.abc import Callable

from guard_core._misconfiguration_kinds import (
    K_REQUIRE_AUTH_CAPITALIZED_SCHEME,
    kinds_log_extra,
)
from guard_core.decorators.base import (
    AuthVerifier,
    BaseSecurityMixin,
    GuardedParams,
    GuardedReturn,
)

logger = logging.getLogger("guard_core.decorators")


class AuthenticationMixin(BaseSecurityMixin):
    def require_https(
        self,
    ) -> Callable[
        [Callable[GuardedParams, GuardedReturn]], Callable[GuardedParams, GuardedReturn]
    ]:
        def decorator(
            func: Callable[GuardedParams, GuardedReturn],
        ) -> Callable[GuardedParams, GuardedReturn]:
            route_config = self._ensure_route_config(func)
            route_config.require_https = True
            return self._apply_route_config(func)

        return decorator

    def require_auth(
        self,
        type: str = "bearer",
        verifier: AuthVerifier | None = None,
    ) -> Callable[
        [Callable[GuardedParams, GuardedReturn]], Callable[GuardedParams, GuardedReturn]
    ]:
        def decorator(
            func: Callable[GuardedParams, GuardedReturn],
        ) -> Callable[GuardedParams, GuardedReturn]:
            from guard_core.decorators._route_arguments import (
                canonical_auth_scheme,
                capitalized_scheme_note,
            )

            route_config = self._ensure_route_config(func)
            if route_config.authorization_header_required is not None:
                raise ValueError(
                    "require_auth cannot be combined with require_authorization_header;"
                    " the latter is presence-only and mutually exclusive with"
                    " authenticated routes"
                )
            scheme = canonical_auth_scheme(type)
            if scheme != type:
                logger.warning(
                    capitalized_scheme_note(
                        getattr(func, "__qualname__", repr(func)), type, scheme
                    ),
                    extra=kinds_log_extra(K_REQUIRE_AUTH_CAPITALIZED_SCHEME, None),
                )
            route_config.auth_required = scheme
            route_config.auth_verifier = verifier
            return self._apply_route_config(func)

        return decorator

    def api_key_auth(
        self,
        header_name: str = "X-API-Key",
        verifier: AuthVerifier | None = None,
    ) -> Callable[
        [Callable[GuardedParams, GuardedReturn]], Callable[GuardedParams, GuardedReturn]
    ]:
        def decorator(
            func: Callable[GuardedParams, GuardedReturn],
        ) -> Callable[GuardedParams, GuardedReturn]:
            route_config = self._ensure_route_config(func)
            if route_config.authorization_header_required is not None:
                raise ValueError(
                    "api_key_auth cannot be combined with require_authorization_header;"
                    " the latter is presence-only and mutually exclusive with"
                    " authenticated routes"
                )
            route_config.api_key_required = True
            route_config.required_headers.setdefault(header_name, "required")
            route_config.api_key_header = header_name
            route_config.api_key_verifier = verifier
            return self._apply_route_config(func)

        return decorator

    def require_authorization_header(
        self,
        scheme: str = "bearer",
    ) -> Callable[
        [Callable[GuardedParams, GuardedReturn]], Callable[GuardedParams, GuardedReturn]
    ]:
        def decorator(
            func: Callable[GuardedParams, GuardedReturn],
        ) -> Callable[GuardedParams, GuardedReturn]:
            from guard_core.decorators._route_arguments import canonical_auth_scheme

            route_config = self._ensure_route_config(func)
            if route_config.auth_required is not None or route_config.api_key_required:
                raise ValueError(
                    "require_authorization_header cannot be combined with"
                    " require_auth or api_key_auth; it is presence-only and"
                    " mutually exclusive with authenticated routes"
                )
            route_config.authorization_header_required = canonical_auth_scheme(scheme)
            return self._apply_route_config(func)

        return decorator

    def require_headers(
        self, headers: dict[str, str]
    ) -> Callable[
        [Callable[GuardedParams, GuardedReturn]], Callable[GuardedParams, GuardedReturn]
    ]:
        def decorator(
            func: Callable[GuardedParams, GuardedReturn],
        ) -> Callable[GuardedParams, GuardedReturn]:
            route_config = self._ensure_route_config(func)
            route_config.required_headers.update(headers)
            return self._apply_route_config(func)

        return decorator
