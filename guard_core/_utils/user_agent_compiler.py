from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guard_core.detection_engine.compiler import PatternCompiler
    from guard_core.handlers.suspatterns_handler import SusPatternsManager

_fallback_user_agent_compiler: "PatternCompiler | None" = None
_active_sus_patterns_getter: "Callable[[], SusPatternsManager] | None" = None


def user_agent_compiler() -> "PatternCompiler":
    """The compiler whose cache holds the blocked user-agent patterns: the active
    manager's (the one its ``add_pattern`` and ``clear_cache`` keep), else one
    kept for the process, so a pattern is compiled once, not on every request."""
    global _fallback_user_agent_compiler, _active_sus_patterns_getter
    if _active_sus_patterns_getter is None:
        from guard_core.handlers.suspatterns_handler import active_sus_patterns

        _active_sus_patterns_getter = active_sus_patterns
    compiler = _active_sus_patterns_getter()._compiler
    if compiler is not None:
        return compiler
    if _fallback_user_agent_compiler is None:
        from guard_core.detection_engine.compiler import PatternCompiler

        _fallback_user_agent_compiler = PatternCompiler()
    return _fallback_user_agent_compiler
