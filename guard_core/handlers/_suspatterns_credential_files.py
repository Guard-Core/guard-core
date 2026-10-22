from guard_core.handlers._suspatterns_shell_sources import _CTX_URL_PATH_ONLY
from guard_core.handlers._suspatterns_sources import (
    _CTX_SENSITIVE_FILE,
    _EXTENSION_TRICK_SUFFIX,
    _NAMED_PATH_SUFFIX_RE,
    _PATH_ONLY_CHAR_RE,
    _PATH_ONLY_SEP_RE,
    _path_only_pattern,
)

_PRIVATE_KEY_NAMES = r"id_(?:rsa|dsa|ecdsa|ed25519|ecdsa_sk|ed25519_sk)"
_CREDENTIAL_FILES_WITH_DIRECTORY = (
    rf"(?:\.ssh/(?:{_PRIVATE_KEY_NAMES}|authorized_keys)"
    r"|\.aws/credentials"
    r"|\.docker/config\.json"
    r"|\.kube/config"
    r"|\.azure/(?:accessTokens|msal_token_cache)\.json"
    r"|\.config/gh/hosts\.yml"
    r"|\.config/gcloud/(?:credentials\.db|application_default_credentials\.json)"
    r"|\.terraform\.d/credentials\.tfrc\.json"
    r"|\.m2/settings\.xml"
    r"|\.gradle/gradle\.properties"
    r"|\.cargo/credentials(?:\.toml)?"
    r"|\.gem/credentials"
    r"|\.(?:config/)?composer/auth\.json)"
).replace("/", _PATH_ONLY_SEP_RE)
_CREDENTIAL_FILES_BY_NAME = (
    r"(?:\.git-credentials|\.netrc|_netrc|\.pgpass|\.pypirc|\.vault-token|\.s3cfg"
    r"|\.boto|terraform\.tfstate|\.bash_history|\.zsh_history)"
)
_BARE_PRIVATE_KEY_LAST_URL_SEGMENT = (
    rf"\A{_PATH_ONLY_SEP_RE}(?:{_PATH_ONLY_CHAR_RE}+{_PATH_ONLY_SEP_RE})*"
    rf"{_PRIVATE_KEY_NAMES}{_EXTENSION_TRICK_SUFFIX}(?:\?\S*)?\s*\Z"
)

CREDENTIAL_FILES_WITH_DIRECTORY_ROW = _path_only_pattern(
    _CREDENTIAL_FILES_WITH_DIRECTORY, suffix=_NAMED_PATH_SUFFIX_RE
)

CREDENTIAL_FILE_ROWS: tuple[tuple[str, frozenset[str], str], ...] = (
    (
        CREDENTIAL_FILES_WITH_DIRECTORY_ROW,
        _CTX_SENSITIVE_FILE,
        "sensitive_file",
    ),
    (
        _path_only_pattern(_CREDENTIAL_FILES_BY_NAME, suffix=_NAMED_PATH_SUFFIX_RE),
        _CTX_SENSITIVE_FILE,
        "sensitive_file",
    ),
    (_BARE_PRIVATE_KEY_LAST_URL_SEGMENT, _CTX_URL_PATH_ONLY, "sensitive_file"),
)
