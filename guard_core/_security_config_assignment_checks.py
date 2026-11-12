"""The construction-time rules that an assignment or ``model_copy(update=...)`` must
meet as well: the ``Field`` constraints, the cross-field validators and the 5.0.0
refusal of a misconfiguration. Each runs only for the field that changed."""

from collections.abc import Mapping
from functools import cache
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, create_model

from guard_core._misconfiguration import (
    config_logger,
    config_misconfigurations,
    report_misconfiguration,
)
from guard_core._security_config_field_validators import require_agent_config

if TYPE_CHECKING:
    from guard_core._security_config_fields import RequestT
    from guard_core.models import SecurityConfig

_AGENT_RULE_FIELDS = frozenset(
    {
        "enable_agent",
        "agent_api_key",
        "agent_strict",
        "enable_dynamic_rules",
        "enable_enrichment",
    }
)
_RECIDIVE_CAP_FIELDS = frozenset(
    {"enable_recidive", "recidive_max_duration", "auto_ban_duration"}
)


@cache
def _constraint_probe(
    config_class: type[BaseModel], name: str
) -> type[BaseModel] | None:
    info = config_class.model_fields[name]
    if not info.metadata and info.annotation is not bool:
        return None
    return create_model(
        f"_{name}_constraint",
        __config__=ConfigDict(arbitrary_types_allowed=True),
        value=(info.annotation or object, info),
    )


def require_field_constraints(
    config: "SecurityConfig[RequestT]", name: str, value: object
) -> object:
    """Refuse a value the ``Field`` constraints of ``name`` (``ge``, ``le``, ``gt``,
    ``min_length`` and the like) would have refused at construction. A ``bool``
    field returns the value as construction would read it (``"no"`` is ``False``),
    every other field returns the value as given."""
    probe = _constraint_probe(type(config), name)
    if probe is None:
        return value
    validated = probe.model_validate({"value": value})
    if type(config).model_fields[name].annotation is bool:
        return validated.model_dump()["value"]
    return value


def misconfigurations_now(config: "SecurityConfig[RequestT]") -> frozenset[str]:
    return frozenset(config_misconfigurations(config))


def require_cross_field_rules(
    config: "SecurityConfig[RequestT]",
    changed: frozenset[str],
    problems_before: frozenset[str],
    *,
    stacklevel: int,
) -> None:
    if changed & _AGENT_RULE_FIELDS:
        require_agent_config(config)
    if changed & _RECIDIVE_CAP_FIELDS:
        from guard_core._security_config_validators import (
            _require_recidive_cap_covers_auto_ban,
        )

        _require_recidive_cap_covers_auto_ban(config)
    for problem in config_misconfigurations(config):
        if problem not in problems_before:
            report_misconfiguration(
                config,
                problem,
                logger=config_logger,
                stacklevel=stacklevel,
            )


def changed_copy_fields(
    config: "SecurityConfig[RequestT]", update: Mapping[str, object]
) -> None:
    for name in update:
        if name in type(config).model_fields:
            require_field_constraints(config, name, getattr(config, name))
