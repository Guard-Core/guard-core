_DEFAULT_MAX_BODY_INSPECT_BYTES = 262144
_DEFAULT_MAX_FILE_INSPECT_BYTES = 1048576

ALL_DETECTION_CATEGORIES: frozenset[str] = frozenset(
    {
        "xss",
        "sqli",
        "dir_traversal",
        "path_traversal",
        "cmd_injection",
        "file_inclusion",
        "ldap",
        "xml",
        "ssrf",
        "nosql",
        "file_upload",
        "template",
        "http_split",
        "sensitive_file",
        "cms_probing",
        "recon",
        "proto_pollution",
        "code_injection",
        "deserialization",
    }
)
