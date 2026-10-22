import re

from guard_core.handlers._suspatterns_sources import (
    _CTX_SENSITIVE_FILE,
    _NAMED_PATH_SUFFIX_RE,
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
# A bare private key name counts only behind a separator (a URL path segment); the
# match clearing below drops it outside the request URL path.
_BARE_PRIVATE_KEY_LAST_URL_SEGMENT = rf"(?<={_PATH_ONLY_SEP_RE}){_PRIVATE_KEY_NAMES}"
_BARE_PRIVATE_KEY_SEGMENT_RE = re.compile(
    rf"(?<!\.ssh){_PATH_ONLY_SEP_RE}{_PRIVATE_KEY_NAMES}", re.IGNORECASE
)

CREDENTIAL_FILES_REQUIRED = (
    rf"(?:{_CREDENTIAL_FILES_WITH_DIRECTORY}|{_CREDENTIAL_FILES_BY_NAME}"
    rf"|{_BARE_PRIVATE_KEY_LAST_URL_SEGMENT})"
)

# The .env row extended with the credential files (the ones with a directory and the
# ones by name): one row, so the credential list adds no regex call to a request.
CREDENTIAL_FILES_WITH_DIRECTORY_ROW = _path_only_pattern(
    rf"(?:\.env(?:\.\w+)?|{CREDENTIAL_FILES_REQUIRED})", suffix=_NAMED_PATH_SUFFIX_RE
)

CREDENTIAL_FILE_ROWS: tuple[tuple[str, frozenset[str], str], ...] = (
    (CREDENTIAL_FILES_WITH_DIRECTORY_ROW, _CTX_SENSITIVE_FILE, "sensitive_file"),
)


def private_key_name_is_bare(path: str) -> bool:
    return _BARE_PRIVATE_KEY_SEGMENT_RE.search(path) is not None
