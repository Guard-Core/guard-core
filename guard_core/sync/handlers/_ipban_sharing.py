import logging
from typing import TYPE_CHECKING

from guard_core.sync._utils.app_scope import (
    SHARED_BY_APPS,
    AppScope,
    existing_app_scope_of,
    in_app_scope,
)
from guard_core.sync.handlers._ipban_bans import IpBanOperationsMixin
from guard_core.sync.handlers._ipban_carve import IpBanCarveMixin
from guard_core.sync.handlers._ipban_migration import IpBanMigrationMixin
from guard_core.sync.handlers._ipban_queries import IpBanQueryMixin
from guard_core.sync.utils import _canonicalize_ip

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol

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
_warned_unenforced_bans: set[str] = set()


def _redacted_apps_of(scopes: list[AppScope]) -> str:
    from guard_core.sync.handlers.redis_handler import _redact_redis_url

    return ", ".join(
        f"{scope.config.redis_prefix!r} ({_redact_redis_url(scope.config.redis_url)})"
        for scope in scopes
    )


def _redis_still_open(handler: "SyncRedisHandlerProtocol | None") -> bool:
    return handler is not None and getattr(handler, "_closed", False) is not True


def _scope_through(
    scope: AppScope, live_redis: "SyncRedisHandlerProtocol | None"
) -> AppScope:
    """A copy of the app's scope that writes through a live sharing app's Redis
    handler and sends no agent event."""
    through = AppScope(scope.config)
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

    def _ban_stands_for(self, ip: str, config: "SyncSecurityConfig") -> bool:
        """Whether a ban a lookup found is enforced for the app running under
        ``config``: not when ``config`` would refuse to record it (its trusted
        proxies and loopback), so this app's reads match its writes."""
        if self._self_dos_refusal_reason(ip, config) is None:
            return True
        if (
            ip not in _warned_unenforced_bans
            and len(_warned_unenforced_bans) < _MAX_WARNED_UNENFORCED_BANS
        ):
            from guard_core.sync.handlers.redis_handler import _redact_redis_url

            _warned_unenforced_bans.add(ip)
            self.logger.warning(
                _UNENFORCED_BAN_WARNING,
                ip,
                config.redis_prefix,
                _redact_redis_url(config.redis_url),
            )
        return False

    def _across_apps_scopes(self, method: str) -> list[AppScope]:
        global _warned_about_unscoped_calls
        sharing = self.__dict__.get(SHARED_BY_APPS) or {}
        found = (existing_app_scope_of(config) for config in list(sharing.values()))
        scopes = [scope for scope in found if scope is not None]
        if scopes and not _warned_about_unscoped_calls:
            _warned_about_unscoped_calls = True
            self.logger.warning(_UNSCOPED_WARNING, _redacted_apps_of(scopes), method)
        live_redis = next(
            (s.redis_handler for s in scopes if _redis_still_open(s.redis_handler)),
            None,
        )
        return [_scope_through(scope, live_redis) for scope in scopes]

    def _ban_ip_across_sharing_apps(
        self, ip: str, duration: int, reason: str, grouped: bool
    ) -> bool:
        scopes = self._across_apps_scopes("ban_ip")
        ip = _canonicalize_ip(ip)
        for scope in scopes:
            with in_app_scope(scope):
                if (
                    self._refuse_rule_exempt_target(ip)
                    or self._self_dos_refusal_reason(ip) is not None
                ):
                    return False
        targets: dict[str, AppScope] = {}
        for scope in scopes:
            identity = self._grouped_identity_of(ip, scope.config) if grouped else None
            targets.setdefault(identity or ip, scope)
        applied = True
        for target, scope in targets.items():
            with in_app_scope(scope):
                result = self._apply_ban(
                    target, duration, reason, grouped, escalate=False
                )
            applied = applied and result is not None
        return applied

    def _is_ip_banned_across_sharing_apps(self, ip: str) -> bool:
        banned = False
        for scope in self._across_apps_scopes("is_ip_banned"):
            with in_app_scope(scope):
                banned = self.is_ip_banned(ip) or banned
        return banned

    def _unban_ip_across_sharing_apps(self, ip: str, reason: str) -> None:
        seen: set[str | None] = set()
        for scope in self._across_apps_scopes("unban_ip"):
            identity = self._grouped_identity_of(_canonicalize_ip(ip), scope.config)
            if identity in seen:
                continue
            seen.add(identity)
            with in_app_scope(scope):
                self.unban_ip(ip, reason=reason)
