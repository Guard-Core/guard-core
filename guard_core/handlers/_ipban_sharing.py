import logging
from typing import TYPE_CHECKING

from guard_core._misconfiguration_kinds import (
    K_BAN_UNENFORCED_FOR_APP,
    kinds_log_extra,
)
from guard_core._utils.app_scope import (
    SHARED_BY_APPS,
    AppScope,
    existing_app_scope_of,
    in_app_scope,
)
from guard_core._utils.nat64 import nat64_table_of
from guard_core._utils.sampling import PerApp, WarnedKeys
from guard_core.handlers._ipban_bans import IpBanOperationsMixin
from guard_core.handlers._ipban_carve import IpBanCarveMixin
from guard_core.handlers._ipban_migration import IpBanMigrationMixin
from guard_core.handlers._ipban_queries import IpBanQueryMixin
from guard_core.utils import _canonicalize_ip

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig
    from guard_core.protocols.redis_protocol import RedisHandlerProtocol

_UNSCOPED_WARNING = (
    "A ban, unban or ban lookup ran on a ban manager shared by the apps %s with "
    "no app in scope and no config= argument: it was resolved across every "
    "sharing app and no agent event was sent (first seen on %s). Pass "
    "config=<the app's config> to run it as one app."
)
_warned_about_unscoped_calls = False
_UNENFORCED_BAN_WARNING = (
    "A stored ban on %s is not enforced for the app with the Redis prefix %r (%s): "
    "the address is one of its trusted proxies or a loopback address, and a ban "
    "there would block every user behind it. The ban stays in force for apps "
    "that do not trust it."
)
_MAX_WARNED_UNENFORCED_BANS = 256
_warned_unenforced_bans = PerApp("unenforced_bans", WarnedKeys)


def _redacted_apps_of(apps: list[tuple["SecurityConfig", AppScope]]) -> str:
    from guard_core.handlers.redis_handler import _redact_redis_url

    return ", ".join(
        f"{config.redis_prefix!r} ({_redact_redis_url(config.redis_url)})"
        for config, _ in apps
    )


def _redis_still_open(handler: "RedisHandlerProtocol | None") -> bool:
    return handler is not None and getattr(handler, "_closed", False) is not True


def _scope_through(
    config: "SecurityConfig",
    scope: AppScope,
    live_redis: "RedisHandlerProtocol | None",
) -> AppScope:
    """A copy of the app's scope that writes through a live sharing app's Redis
    handler and sends no agent event."""
    through = AppScope(config)
    through.redis_handler = live_redis
    through.rule_exempt_networks = scope.rule_exempt_networks
    return through


class IpBanSharedAppsMixin(
    IpBanMigrationMixin, IpBanOperationsMixin, IpBanQueryMixin, IpBanCarveMixin
):
    """Bans, unbans and lookups made on a manager several apps share, with no app
    in scope and no ``config=``: resolved across the sharing apps, never as the
    app that happened to bind last."""

    logger: logging.Logger

    def _ban_stands_for(self, ip: str, config: "SecurityConfig | None") -> bool:
        """Whether a ban a lookup found is enforced for the app running under
        ``config``: not when ``config`` would refuse to record it (its trusted
        proxies and loopback), so this app's reads match its writes."""
        if self._self_dos_refusal_reason(ip, config) is None:
            return True
        if config is not None:
            warned = _warned_unenforced_bans.for_app(config)
            if ip not in warned and len(warned) < _MAX_WARNED_UNENFORCED_BANS:
                from guard_core.handlers.redis_handler import _redact_redis_url

                warned.add(ip)
                self.logger.warning(
                    _UNENFORCED_BAN_WARNING,
                    ip,
                    config.redis_prefix,
                    _redact_redis_url(config.redis_url),
                    extra=kinds_log_extra(K_BAN_UNENFORCED_FOR_APP, None),
                )
        return False

    def _across_apps_scopes(
        self, method: str
    ) -> list[tuple["SecurityConfig", AppScope]]:
        """Each live sharing app's config with its scope; the config is returned so
        the caller holds it while it uses the scope, which holds it weakly."""
        global _warned_about_unscoped_calls
        sharing = self.__dict__.get(SHARED_BY_APPS) or {}
        found = [(config, existing_app_scope_of(config)) for config in sharing.values()]
        apps = [(config, scope) for config, scope in found if scope is not None]
        if apps and not _warned_about_unscoped_calls:
            _warned_about_unscoped_calls = True
            self.logger.warning(_UNSCOPED_WARNING, _redacted_apps_of(apps), method)
        live_redis = next(
            (s.redis_handler for _, s in apps if _redis_still_open(s.redis_handler)),
            None,
        )
        return [
            (config, _scope_through(config, scope, live_redis))
            for config, scope in apps
        ]

    async def _ban_ip_across_sharing_apps(
        self, ip: str, duration: int, reason: str, grouped: bool
    ) -> bool:
        apps = self._across_apps_scopes("ban_ip")
        ip = _canonicalize_ip(ip, nat64_table_of(self.config))
        for _, scope in apps:
            with in_app_scope(scope):
                if (
                    self._refuse_rule_exempt_target(ip)
                    or self._self_dos_refusal_reason(ip) is not None
                ):
                    return False
        targets: dict[str, AppScope] = {}
        for config, scope in apps:
            identity = self._grouped_identity_of(ip, config) if grouped else None
            targets.setdefault(identity or ip, scope)
        applied = True
        for target, scope in targets.items():
            with in_app_scope(scope):
                result = await self._apply_ban(
                    target, duration, reason, grouped, escalate=False
                )
            applied = applied and result is not None
        return applied

    async def _is_ip_banned_across_sharing_apps(self, ip: str) -> bool:
        banned = False
        for _, scope in self._across_apps_scopes("is_ip_banned"):
            with in_app_scope(scope):
                banned = await self.is_ip_banned(ip) or banned
        return banned

    async def _unban_ip_across_sharing_apps(self, ip: str, reason: str) -> None:
        seen: set[str | None] = set()
        for config, scope in self._across_apps_scopes("unban_ip"):
            identity = self._grouped_identity_of(
                _canonicalize_ip(ip, nat64_table_of(config)), config
            )
            if identity in seen:
                continue
            seen.add(identity)
            with in_app_scope(scope):
                await self.unban_ip(ip, reason=reason)
