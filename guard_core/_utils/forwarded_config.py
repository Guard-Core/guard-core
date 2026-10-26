from typing import Protocol


class ForwardedForConfig(Protocol):
    @property
    def agent_enable_events(self) -> bool: ...

    @property
    def muted_event_types(self) -> frozenset[str]: ...

    @property
    def trusted_proxies(self) -> tuple[str, ...]: ...

    @property
    def trusted_proxy_depth(self) -> int: ...
