import re

from guard_core._utils.source_path_shapes import named_file_leaf_in_benign_shape
from guard_core.handlers._suspatterns_credential_files import (
    CREDENTIAL_FILES_WITH_DIRECTORY_ROW,
    credential_file_is_a_home_tilde_reference,
    private_key_name_is_bare,
)
from guard_core.handlers._suspatterns_named_floor import (
    is_the_request_url_path,
    last_segment_is_not_the_apps_own_route,
    named_file_in_a_push_list_is_plain,
    named_path_has_a_trick_suffix,
)
from guard_core.handlers._suspatterns_pattern_table import (
    NAMED_DIRECTORY_PATH_SOURCES,
    NAMED_FILE_PATH_SOURCES,
    RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES,
    ROUTE_GATED_PATH_SOURCES,
)
from guard_core.handlers._suspatterns_sources import _recon_path_value_is_probe


def _credential_row_match_is_cleared(
    source: str, match: re.Match, context: str
) -> bool:
    return source == CREDENTIAL_FILES_WITH_DIRECTORY_ROW and (
        credential_file_is_a_home_tilde_reference(match.group())
        or (
            not is_the_request_url_path(context)
            and private_key_name_is_bare(match.group())
        )
    )


def _directory_row_match_is_cleared(source: str, match: re.Match) -> bool:
    return (
        source in NAMED_DIRECTORY_PATH_SOURCES
        and named_file_leaf_in_benign_shape()
        and not named_path_has_a_trick_suffix(match.group())
    )


def path_row_match_is_cleared(
    pattern: re.Pattern, match: re.Match, context: str
) -> bool:
    source = pattern.pattern
    if _credential_row_match_is_cleared(source, match, context):
        return True
    if _directory_row_match_is_cleared(source, match):
        return True
    if source in NAMED_FILE_PATH_SOURCES and (
        named_file_in_a_push_list_is_plain(pattern, match)
    ):
        return True
    if source in ROUTE_GATED_PATH_SOURCES and not (
        last_segment_is_not_the_apps_own_route(match, context)
    ):
        return True
    return source in RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES and not (
        _recon_path_value_is_probe(match, context)
    )
