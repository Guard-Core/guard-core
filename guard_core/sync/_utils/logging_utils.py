import contextvars
import json
import logging

from guard_core._lazy_patterns import LazyPatterns, module_attribute_lookup
from guard_core.sync._utils.pair_value_scan import _bounded_percent_decode
from guard_core.sync._utils.sensitive_names import name_is_sensitive

logger = logging.getLogger("guard_core")

_JSON_LEAF_START_CHARS = frozenset("{[")

# Set while a redaction traversal collapses a container at the JSON depth
# cap; the display path uses it to redact the whole value instead of
# emitting a huge half-redacted structure (see request_logging).
_json_depth_cap_hit: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "guard_core_redaction_json_depth_cap_hit", default=False
)


def _sanitize_for_log(value: str) -> str:
    r"""Make a string safe to emit on any console encoding.

    Control characters become ``\xNN`` escapes and every non-ASCII character
    becomes a ``\uXXXX`` (or ``\xNN`` for surrogate-escaped bytes) escape, so
    the result is pure ASCII and can never raise ``UnicodeEncodeError`` on
    legacy code pages such as Windows cp1252.
    """
    if not value:
        return value
    sanitized = value.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    out: list[str] = []
    for char in sanitized:
        code = ord(char)
        if 32 <= code <= 126:
            out.append(char)
        elif 0xDC80 <= code <= 0xDCFF:
            out.append(f"\\x{code - 0xDC00:02x}")
        else:
            out.append(f"\\u{code:04x}")
    return "".join(out)


_PATTERNS = LazyPatterns(
    {
        "_LONE_SURROGATE_OUTSIDE_ESCAPED_BYTES_RE": ("[\ud800-\udc7f\udd00-\udfff]", 0),
    }
)
__getattr__ = module_attribute_lookup(_PATTERNS)


def _sanitize_for_reporting(value: str) -> str:
    """Render ``value`` for a log line or an event, for any string.

    A surrogate-escaped byte (U+DC80..U+DCFF) shows as ``\\xNN``. Any other lone
    surrogate, which JSON ``\\ud800`` produces and ``surrogateescape`` cannot
    encode, shows as ``\\uXXXX`` instead of raising.
    """
    if value.isascii():
        return value
    value = _PATTERNS["_LONE_SURROGATE_OUTSIDE_ESCAPED_BYTES_RE"].sub(
        lambda lone: f"\\u{ord(lone.group()):04x}", value
    )
    return value.encode("utf-8", errors="surrogateescape").decode(
        "utf-8", errors="backslashreplace"
    )


def _nested_json_leaf_candidate(value: str) -> str | None:
    if value[:1] in _JSON_LEAF_START_CHARS:
        return value
    if value[:1] != "%":
        return None
    decoded = _bounded_percent_decode(value)
    return decoded if decoded[:1] in _JSON_LEAF_START_CHARS else None


def _try_redact_nested_json_leaf(
    value: str,
    leaf_sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    max_depth: int,
) -> str | None:
    candidate = _nested_json_leaf_candidate(value)
    if candidate is None:
        return None
    try:
        parsed = json.loads(candidate)
    except ValueError:
        return None
    except RecursionError:
        return "[REDACTED]"
    redacted = _redact_sensitive_json(
        parsed, leaf_sensitive, sensitive_body_fields, max_depth
    )
    if redacted == parsed:
        return None
    return json.dumps(redacted, separators=(",", ":"), ensure_ascii=False)


def _redact_json_string_leaf(
    value: str,
    leaf_sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    max_depth: int,
) -> str:
    from guard_core.sync._utils.pair_redaction import _redact_pairs_in_text
    from guard_core.sync._utils.request_logging import _redact_xml_elements

    nested_json = _try_redact_nested_json_leaf(
        value, leaf_sensitive, sensitive_body_fields, max_depth
    )
    if nested_json is not None:
        return nested_json

    xml_redacted = _redact_xml_elements(value, leaf_sensitive)
    return _redact_pairs_in_text(
        xml_redacted, leaf_sensitive, sensitive_body_fields, max_depth
    )


_JsonContainer = dict[object, object] | list[object]


def _redact_json_child(
    key: object,
    item: object,
    source_is_dict: bool,
    depth: int,
    max_depth: int,
    leaf_sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    stack: list[tuple[_JsonContainer, _JsonContainer, int]],
) -> object:
    if source_is_dict and name_is_sensitive(str(key), sensitive_body_fields):
        return "[REDACTED]"
    if isinstance(item, str):
        return _redact_json_string_leaf(
            item, leaf_sensitive, sensitive_body_fields, max_depth
        )
    if not isinstance(item, dict | list):
        return item
    child_depth = depth + 1
    if child_depth >= max_depth:
        _json_depth_cap_hit.set(True)
        return "[REDACTED]"
    child: _JsonContainer = {} if isinstance(item, dict) else []
    stack.append((item, child, child_depth))
    return child


def _redact_sensitive_json(
    value: object,
    sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    max_depth: int,
) -> object:
    if not isinstance(value, dict | list):
        return value
    if max_depth <= 1:
        return "[REDACTED]"
    leaf_sensitive = sensitive | sensitive_body_fields
    root: _JsonContainer = {} if isinstance(value, dict) else []
    stack: list[tuple[_JsonContainer, _JsonContainer, int]] = [(value, root, 1)]
    while stack:
        source, target, depth = stack.pop()
        source_is_dict = isinstance(source, dict)
        entries = source.items() if isinstance(source, dict) else enumerate(source)
        for key, item in entries:
            redacted_item = _redact_json_child(
                key,
                item,
                source_is_dict,
                depth,
                max_depth,
                leaf_sensitive,
                sensitive_body_fields,
                stack,
            )
            if isinstance(target, dict):
                target[key] = redacted_item
            else:
                target.append(redacted_item)
    return root


_LEVEL_NUMBERS: dict[str, int] = {
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


def _logs_at_level(logger: logging.Logger, level: str) -> bool:
    number = _LEVEL_NUMBERS.get(level)
    return number is not None and logger.isEnabledFor(number)


def _log_at_level(logger: logging.Logger, level: str, msg: str) -> None:
    # a CR or LF inside a client-supplied value must not start a forged log line
    msg = _sanitize_for_reporting(msg).replace("\r", "\\r").replace("\n", "\\n")
    if level == "INFO":
        logger.info(msg)
    elif level == "DEBUG":
        logger.debug(msg)
    elif level == "WARNING":
        logger.warning(msg)
    elif level == "ERROR":
        logger.error(msg)
    elif level == "CRITICAL":
        logger.critical(msg)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        import json

        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        return json.dumps(log_entry, default=str)


def _create_formatter(log_format: str) -> logging.Formatter:
    if log_format == "json":
        return JsonFormatter()
    return logging.Formatter("[%(name)s] %(asctime)s - %(levelname)s - %(message)s")


class _YieldToHostRootHandlers(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not logging.getLogger().handlers


_OWN_HANDLER_ATTR = "_guard_core_installed"


def setup_custom_logging(
    log_file: str | None = None, log_format: str = "text"
) -> logging.Logger:
    logger = logging.getLogger("guard_core")
    for handler in logger.handlers[:]:
        if not getattr(handler, _OWN_HANDLER_ATTR, False):
            continue
        handler.close()
        logger.removeHandler(handler)

    formatter = _create_formatter(log_format)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.addFilter(_YieldToHostRootHandlers())
    setattr(console_handler, _OWN_HANDLER_ATTR, True)
    logger.addHandler(console_handler)

    if log_file:
        try:
            import os

            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            setattr(file_handler, _OWN_HANDLER_ATTR, True)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Failed to create log file {log_file}: {e}")

    logger.setLevel(logging.INFO)

    return logger
