import importlib.util
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig

Tree = Literal["async", "sync"]

_DOWNLOADER_BY_TREE: dict[Tree, str] = {"async": "aiohttp", "sync": "requests"}
_ADAPTER: tuple[str, Tree] | None = None


def register_adapter(distribution: str, tree: Tree) -> None:
    global _ADAPTER
    _ADAPTER = (distribution, tree)


def _extra_installed(*module_names: str) -> bool:
    return any(importlib.util.find_spec(name) is not None for name in module_names)


def _downloader_modules() -> tuple[str, ...]:
    if _ADAPTER is None:
        return tuple(_DOWNLOADER_BY_TREE.values())
    return (_DOWNLOADER_BY_TREE[_ADAPTER[1]],)


def _install_hint(extra: str) -> str:
    hint = f"pip install guard-core[{extra}]"
    if _ADAPTER is None:
        return hint
    return f"{hint} (or {_ADAPTER[0]}[{extra}])"


def require_redis_extra() -> None:
    if not _extra_installed("redis"):
        raise ValueError(
            "enable_redis=True requires the 'redis' package. "
            f"Install it with: {_install_hint('redis')}"
        )


def require_cloud_extra() -> None:
    modules = _downloader_modules()
    if not _extra_installed(*modules):
        raise ValueError(
            "block_cloud_providers / enable_dynamic_rules requires "
            f"{' or '.join(repr(name) for name in modules)}. "
            f"Install it with: {_install_hint('cloud')}"
        )


def require_geo_extra() -> None:
    modules = _downloader_modules()
    if not _extra_installed("maxminddb") or not _extra_installed(*modules):
        raise ValueError(
            "geo_ip_handler / country rules require the 'maxminddb' package and "
            f"{' or '.join(repr(name) for name in modules)} to download the "
            f"database. Install them with: {_install_hint('geo')}"
        )


def cloud_blocking_requested(
    block_cloud_providers: object, enable_dynamic_rules: bool
) -> bool:
    return bool(block_cloud_providers) or enable_dynamic_rules


def cloud_blocking_enabled(config: "SecurityConfig") -> bool:
    return cloud_blocking_requested(
        config.block_cloud_providers, config.enable_dynamic_rules
    )
