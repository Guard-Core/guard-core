import logging
import time
from collections.abc import MutableMapping
from typing import Any

_RECIDIVE_NAMESPACE = "recidive"


def escalated_duration(base: int, prior_bans: int, factor: float, cap: int) -> int:
    """The k-th repeat ban lasts ``base * factor ** k`` seconds, capped at ``cap``.

    A base already above the cap is kept as it is: escalation never shortens a ban.
    """
    try:
        grown = base * factor**prior_bans
    except OverflowError:
        grown = float(cap)
    return max(base, int(min(grown, cap)))


class IpBanRecidiveMixin:
    """Counts the bans applied to one identity so the next one can last longer.

    The count lives in Redis under ``recidive:<identity>`` when a handler is set,
    and always in memory (``recidive_history``) so a Redis outage still escalates in
    this process. Its lifetime is the window plus the ban just applied, so a count
    survives the ban it belongs to and then ages out. Every unban of the identity
    forgets it; a natural expiry keeps it.
    """

    recidive_history: dict[str, tuple[int, float]]
    banned_ips: MutableMapping[str, float]
    config: Any = None
    redis_handler: Any = None
    logger: logging.Logger

    def _recidive_applies(self, ip: str, grouped: bool) -> bool:
        return bool(getattr(self.config, "enable_recidive", False)) and (
            grouped or "/" not in ip
        )

    def _recidive_memory_count(self, identity: str, now: float) -> int:
        count, until = self.recidive_history.get(identity, (0, 0.0))
        return count if until > now else 0

    def _recidive_prior_bans(self, identity: str) -> int:
        now = time.time()
        if self.redis_handler:
            try:
                raw = self.redis_handler.get_key(_RECIDIVE_NAMESPACE, identity)
                return int(raw) if raw is not None else 0
            except Exception as error:
                self.logger.warning(
                    "Redis recidive count of %s unreadable, using this process's: %s",
                    identity,
                    error,
                )
        return self._recidive_memory_count(identity, now)

    def _escalated_ban_terms(
        self, namespace: str, key: str, base: int
    ) -> tuple[int, int | None]:
        """The duration to apply and the ban's number in the window.

        The number is None when a ban is already active: that write only replaces
        it, so it is not counted. The claim is a SET NX, so of several workers
        banning the same client at once exactly one counts.
        """
        prior = self._recidive_prior_bans(key)
        applied = escalated_duration(
            base,
            prior,
            self.config.recidive_factor,
            self.config.recidive_max_duration,
        )
        if not self._claim_ban_key(namespace, key, applied):
            return applied, None
        return applied, self._record_recidive_ban(key, applied)

    def _claim_ban_key(self, namespace: str, key: str, duration: int) -> bool:
        now = time.time()
        if self.redis_handler:
            try:
                return bool(
                    self.redis_handler.set_key_if_absent(
                        namespace, key, str(now + duration), ttl=duration
                    )
                )
            except Exception as error:
                self.logger.warning(
                    "Redis ban claim of %s failed, using this process's view: %s",
                    key,
                    error,
                )
        return self.banned_ips.get(key, 0.0) <= now

    def _record_recidive_ban(self, identity: str, applied_duration: int) -> int:
        lifetime = self.config.recidive_window + applied_duration
        now = time.time()
        count = self._recidive_memory_count(identity, now) + 1
        self._remember_recidive(identity, count, now + lifetime)
        if self.redis_handler:
            try:
                shared = self.redis_handler.incr(
                    _RECIDIVE_NAMESPACE, identity, ttl=lifetime
                )
                count = int(shared) if shared else count
            except Exception as error:
                self.logger.warning(
                    "Redis recidive count of %s not stored, kept in this process: %s",
                    identity,
                    error,
                )
        return count

    def _remember_recidive(self, identity: str, count: int, until: float) -> None:
        history = self.recidive_history
        if identity not in history and len(history) >= self._recidive_capacity():
            now = time.time()
            for stale in [key for key, (_, end) in history.items() if end <= now]:
                del history[stale]
            if len(history) >= self._recidive_capacity():
                del history[min(history, key=lambda key: history[key][1])]
        history[identity] = (count, until)

    def _recidive_capacity(self) -> int:
        return int(getattr(self.config, "banned_ips_max_entries", 100_000))

    def _forget_recidive_in_memory(self, identity: str) -> None:
        self.recidive_history.pop(identity, None)
