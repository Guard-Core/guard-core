"""The records the engine parks on a SecurityConfig, and what a copy does with them.

A record parked on a config belongs to the app built from that config. A copy of
the config is another app, so it must not carry the record: it would route its
events and writes through the original app's handlers. The copy hooks of
SecurityConfig drop every name registered here. An adapter that parks a per-app
record of its own on the config registers its attribute name once.
"""

APP_SCOPE_RECORD = "_guard_app_scope"
APP_MANAGERS_RECORD = "_guard_app_managers"
PATTERN_MANAGER_RECORD = "_guard_pattern_manager"
BAN_THRESHOLD_CONTEXT_RECORD = "_guard_ban_threshold_context"

_PER_APP_RECORDS: frozenset[str] = frozenset(
    {
        APP_SCOPE_RECORD,
        APP_MANAGERS_RECORD,
        PATTERN_MANAGER_RECORD,
        BAN_THRESHOLD_CONTEXT_RECORD,
    }
)


def register_per_app_record(name: str) -> None:
    """Make a copy of a SecurityConfig drop the attribute ``name`` parked on it."""
    global _PER_APP_RECORDS
    _PER_APP_RECORDS = _PER_APP_RECORDS | {name}


def without_per_app_records(instance_dict: dict[str, object]) -> dict[str, object]:
    names = _PER_APP_RECORDS
    return {key: value for key, value in instance_dict.items() if key not in names}
