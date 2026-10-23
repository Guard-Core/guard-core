import importlib.util
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig

_DOWNLOADERS = ("aiohttp", "requests")
_ADAPTER_FOR_MESSAGES: str | None = None


def register_adapter(distribution: str) -> None:
    global _ADAPTER_FOR_MESSAGES
    _ADAPTER_FOR_MESSAGES = distribution


def _extra_installed(*module_names: str) -> bool:
    return any(importlib.util.find_spec(name) is not None for name in module_names)


def install_hint(extra: str, adapter: str | None = None) -> str:
    hint = f"pip install guard-core[{extra}]"
    named = adapter or _ADAPTER_FOR_MESSAGES
    if named is None:
        return hint
    return f"{hint} (or {named}[{extra}])"


def require_redis_extra() -> None:
    if not _extra_installed("redis"):
        raise ValueError(
            "enable_redis=True requires the 'redis' package. "
            f"Install it with: {install_hint('redis')}"
        )


def require_cloud_extra() -> None:
    if not _extra_installed(*_DOWNLOADERS):
        raise ValueError(
            "block_cloud_providers / enable_dynamic_rules requires 'aiohttp' or "
            f"'requests'. Install it with: {install_hint('cloud')}"
        )


def require_geo_extra() -> None:
    if not _extra_installed("maxminddb") or not _extra_installed(*_DOWNLOADERS):
        raise ValueError(
            "geo_ip_handler / country rules require the 'maxminddb' package and "
            "'aiohttp' or 'requests' to download the database. "
            f"Install them with: {install_hint('geo')}"
        )


def cloud_blocking_requested(
    block_cloud_providers: object, enable_dynamic_rules: bool
) -> bool:
    return bool(block_cloud_providers) or enable_dynamic_rules


def cloud_blocking_enabled(config: "SecurityConfig") -> bool:
    return cloud_blocking_requested(
        config.block_cloud_providers, config.enable_dynamic_rules
    )
