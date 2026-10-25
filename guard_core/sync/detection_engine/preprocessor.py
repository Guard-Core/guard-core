import re
import unicodedata
from typing import TYPE_CHECKING

from guard_core.sync.detection_engine import (
    base64_decode,
    encoding_decoders,
    truncation,
)
from guard_core.sync.detection_engine.base64_view import (
    build_short_base64_additive_view,
)
from guard_core.sync.detection_engine.on_handler_indicator import (
    ON_HANDLER_PATTERN,
    OnHandlerIndicator,
)
from guard_core.sync.handlers._suspatterns_sources import (
    _DEFAULT_MAX_BODY_INSPECT_BYTES,
)

if TYPE_CHECKING:
    from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol

_WHITESPACE_RUN_RE = re.compile(r"\s+")
_NON_WHITESPACE_RE = re.compile(r"\S")
_COLLAPSE_WINDOW = 32768


def collapse_whitespace_runs(content: str) -> str:
    collapsed: list[str] = []
    start = 0
    while start < len(content):
        cut = _NON_WHITESPACE_RE.search(content, start + _COLLAPSE_WINDOW)
        end = cut.start() if cut else len(content)
        collapsed.append(_WHITESPACE_RUN_RE.sub(" ", content[start:end]))
        start = end
    return "".join(collapsed)


class ContentPreprocessor:
    _DEFAULT_MAX_FULL_SCAN_BYTES = _DEFAULT_MAX_BODY_INSPECT_BYTES

    def __init__(
        self,
        max_content_length: int = 10000,
        preserve_attack_patterns: bool = True,
        agent_handler: "SyncAgentHandlerProtocol | None" = None,
        correlation_id: str | None = None,
        max_full_scan_bytes: int | None = None,
    ):
        self.max_content_length = max_content_length
        self.preserve_attack_patterns = preserve_attack_patterns
        self.agent_handler = agent_handler
        self.correlation_id = correlation_id
        self._MAX_FULL_SCAN_BYTES = (
            max_full_scan_bytes
            if max_full_scan_bytes is not None
            else self._DEFAULT_MAX_FULL_SCAN_BYTES
        )

        self.attack_indicators = [
            r"<script",
            r"javascript:",
            ON_HANDLER_PATTERN,
            r"SELECT\s+.{0,50}?\s+FROM",
            r"UNION\s+SELECT",
            r"\.\./",
            r"eval\s*\(",
            r"exec\s*\(",
            r"system\s*\(",
            r"<\?php",
            r"<%",
            r"{{",
            r"{%",
            r"<iframe",
            r"<object",
            r"<embed",
            r"onerror\s*=",
            r"onload\s*=",
            r"\$\{",
            r"\\x[0-9a-fA-F]{2}",
            r"%[0-9a-fA-F]{2}",
            r"`",
            r"\$\(",
            r"[;&|]",
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        ]

        self.compiled_indicators: list[re.Pattern[str] | OnHandlerIndicator] = [
            OnHandlerIndicator()
            if pattern == ON_HANDLER_PATTERN
            else re.compile(pattern, re.IGNORECASE)
            for pattern in self.attack_indicators
        ]

    _BASE64_RE = base64_decode.BASE64_RE
    _GZIP_MAGIC = base64_decode.GZIP_MAGIC
    _MAX_GUNZIP_ATTEMPTS_PER_PASS = base64_decode.MAX_GUNZIP_ATTEMPTS_PER_PASS
    _LDAP_HEX_ESCAPE_RE = re.compile(r"\\([0-9a-fA-F]{2})")
    _SQL_BLOCK_COMMENT_STRIP_RE = re.compile(
        r"(?<!\w)/\*(?!!)(.*?)\*/|/\*(?!!)(.*?)\*/(?!\w)", re.DOTALL
    )
    _SQL_LINE_COMMENT_MARKER_RE = re.compile(r"--|#")
    _SQL_LINE_COMMENT_DROP_RE = re.compile(r"--(?=[\s\x00-\x1f]|\Z)[^\n]*|#[^\n]*")
    _SQL_COMMENT_MARKERS = ("--", "#", "/*")

    def _send_preprocessor_event(
        self,
        event_type: str,
        action_taken: str,
        reason: str,
        **kwargs: object,
    ) -> None:
        if not self.agent_handler:
            return

        try:
            from datetime import datetime, timezone

            event = type(
                "SecurityEvent",
                (),
                {
                    "timestamp": datetime.now(timezone.utc),
                    "event_type": event_type,
                    "ip_address": "system",
                    "action_taken": action_taken,
                    "reason": reason,
                    "metadata": {
                        "component": "ContentPreprocessor",
                        "correlation_id": self.correlation_id,
                        **kwargs,
                    },
                },
            )()
            self.agent_handler.send_event(event)
        except Exception as e:
            import logging

            logging.getLogger("guard_core.sync.detection_engine").error(
                f"Failed to send preprocessor event to agent: {e}"
            )

    def normalize_unicode(self, content: str) -> str:
        normalized = unicodedata.normalize("NFKC", content)

        lookalikes = {
            "\u2044": "/",
            "\uff0f": "/",
            "\u29f8": "/",
            "\u0130": "I",
            "\u0131": "i",
            "\u200b": "",
            "\u200c": "",
            "\u200d": "",
            "\ufeff": "",
            "\u00ad": "",
            "\u034f": "",
            "\u180e": "",
            "\u2028": "\n",
            "\u2029": "\n",
            "\ue000": "",
            "\ufff0": "",
            "\u01c0": "|",
            "\u037e": ";",
            "\u2215": "/",
            "\u2216": "\\",
            "\uff1c": "<",
            "\uff1e": ">",
            "\uff1b": ";",
            "\uff5c": "|",
            "\uff06": "&",
        }

        for char, replacement in lookalikes.items():
            normalized = normalized.replace(char, replacement)

        return normalized

    def remove_excessive_whitespace(self, content: str) -> str:
        content = collapse_whitespace_runs(content)
        content = content.strip()
        return content

    def extract_attack_regions(self, content: str) -> list[tuple[int, int]]:
        return truncation.extract_attack_regions(self, content)

    def _extract_and_concatenate_attack_regions(
        self,
        content: str,
        attack_regions: list[tuple[int, int]],
        budget: int | None = None,
    ) -> str:
        if budget is None:
            budget = self.max_content_length
        return truncation.extract_and_concatenate_attack_regions(
            content, attack_regions, budget
        )

    def _build_result_with_attack_regions_and_context(
        self,
        content: str,
        attack_regions: list[tuple[int, int]],
        budget: int | None = None,
    ) -> str:
        if budget is None:
            budget = self.max_content_length
        return truncation.build_result_with_attack_regions_and_context(
            content, attack_regions, budget
        )

    def _cap_with_tail(self, content: str) -> str:
        return truncation.cap_with_tail(content, self._MAX_FULL_SCAN_BYTES)

    def truncate_safely(self, content: str) -> str:
        return truncation.truncate_safely(self, content)

    def remove_null_bytes(self, content: str) -> str:
        content = content.replace("\x00", "")

        control_chars = "".join(chr(i) for i in range(32) if i not in (9, 10, 13))
        translator = str.maketrans("", "", control_chars)
        return content.translate(translator)

    def _is_hex_literal(self, token: str) -> bool:
        return base64_decode.is_hex_literal(token)

    def _printable_ratio(self, text: str) -> float:
        return base64_decode.printable_ratio(text)

    def _replacement_char_ratio(self, text: str) -> float:
        return base64_decode.replacement_char_ratio(text)

    def _bounded_gunzip(self, raw: bytes) -> bytes | None:
        return base64_decode.bounded_gunzip(raw, self._MAX_FULL_SCAN_BYTES)

    def _decode_base64_candidates(
        self, content: str, gunzip_attempts_left: list[int] | None = None
    ) -> str:
        return base64_decode.decode_base64_candidates(
            content, gunzip_attempts_left, self._MAX_FULL_SCAN_BYTES
        )

    def _decode_hex_escapes(self, content: str) -> str:
        return encoding_decoders.decode_hex_escapes(content)

    def _decode_ldap_hex_escapes(self, content: str) -> str:
        def _replace(match: re.Match[str]) -> str:
            try:
                return chr(int(match.group(1), 16))
            except ValueError:
                return match.group(0)

        return self._LDAP_HEX_ESCAPE_RE.sub(_replace, content)

    def _decode_unicode_escapes(self, content: str) -> str:
        return encoding_decoders.decode_unicode_escapes(content)

    def _decode_percent_u_escapes(self, content: str) -> str:
        return encoding_decoders.decode_percent_u_escapes(content)

    def _lenient_overlong_utf8_decode(self, raw: bytes) -> str:
        return encoding_decoders.lenient_overlong_utf8_decode(raw)

    def _decode_overlong_utf8_percent_runs(self, content: str) -> str:
        return encoding_decoders.decode_overlong_utf8_percent_runs(content)

    def _strip_sql_comments(self, content: str) -> str:
        def _replace_block_comment(match: re.Match[str]) -> str:
            body = match.group(1) if match.group(1) is not None else match.group(2)
            return f" {body} "

        content = self._SQL_BLOCK_COMMENT_STRIP_RE.sub(_replace_block_comment, content)
        content = self._SQL_LINE_COMMENT_MARKER_RE.sub(" ", content)
        return content

    def decode_common_encodings(
        self, content: str, decode_budget_exhausted: list[bool] | None = None
    ) -> str:
        from guard_core.sync.core.events.event_types import EVENT_DECODING_ERROR

        max_decode_iterations = 16
        iterations = 0
        gunzip_attempts_left = [self._MAX_GUNZIP_ATTEMPTS_PER_PASS]

        while iterations < max_decode_iterations:
            original = content

            content = self._decode_overlong_utf8_percent_runs(content)

            try:
                decoded = encoding_decoders.percent_decode(content, errors="ignore")
                if decoded != content:
                    content = decoded
            except Exception as e:
                self._send_preprocessor_event(
                    event_type=EVENT_DECODING_ERROR,
                    action_taken="decode_failed",
                    reason="Failed to URL decode content",
                    error=str(e),
                    error_type="url_decode",
                )

            try:
                import html

                decoded = html.unescape(content)
                if decoded != content:
                    content = decoded
            except Exception as e:
                self._send_preprocessor_event(
                    event_type=EVENT_DECODING_ERROR,
                    action_taken="decode_failed",
                    reason="Failed to HTML decode content",
                    error=str(e),
                    error_type="html_decode",
                )

            content = self._decode_percent_u_escapes(content)
            content = self._decode_hex_escapes(content)
            content = self._decode_ldap_hex_escapes(content)
            content = self._decode_unicode_escapes(content)
            content = self.normalize_unicode(content)
            content = self._decode_base64_candidates(content, gunzip_attempts_left)

            if content == original:
                break

            iterations += 1
        else:
            if decode_budget_exhausted is not None:
                decode_budget_exhausted[0] = True

        return content

    def drop_sql_comments(self, content: str) -> str | None:
        if not any(marker in content for marker in self._SQL_COMMENT_MARKERS):
            return None

        def _replace_block_comment(match: re.Match[str]) -> str:
            body = match.group(1) if match.group(1) is not None else match.group(2)
            return f" {body} "

        content = self._SQL_BLOCK_COMMENT_STRIP_RE.sub(_replace_block_comment, content)
        return self._SQL_LINE_COMMENT_DROP_RE.sub("", content)

    def preprocess_comment_dropped_view(
        self, decoded: str, processed: str
    ) -> str | None:
        dropped = self.drop_sql_comments(decoded)
        if dropped is None:
            return None
        view = self.remove_excessive_whitespace(self.remove_null_bytes(dropped))
        view = self.truncate_safely(view)
        return None if view == processed else view

    def preprocess(
        self, content: str, decode_budget_exhausted: list[bool] | None = None
    ) -> str:
        processed, _decoded = self.preprocess_with_decoded(
            content, decode_budget_exhausted
        )
        return processed

    def preprocess_with_decoded(
        self, content: str, decode_budget_exhausted: list[bool] | None = None
    ) -> tuple[str, str]:
        if not content:
            return "", ""

        decoded = self.normalize_unicode(content)
        decoded = self.decode_common_encodings(decoded, decode_budget_exhausted)
        processed = self.remove_null_bytes(decoded)
        processed = self.remove_excessive_whitespace(processed)
        processed = self.truncate_safely(processed)

        return processed, decoded

    def preprocess_signal_preserving(self, content: str) -> str:
        if not content:
            return ""

        content = self.normalize_unicode(content)
        return self.truncate_safely(content)

    def preprocess_url_decoded_newline_preserving(
        self, content: str, decode_budget_exhausted: list[bool] | None = None
    ) -> str:
        if not content:
            return ""

        content = self.normalize_unicode(content)
        content = self.decode_common_encodings(content, decode_budget_exhausted)
        return self.truncate_safely(content)

    def preprocess_short_base64_additive_view(self, content: str) -> str:
        return build_short_base64_additive_view(self, content)

    def preprocess_batch(self, contents: list[str]) -> list[str]:
        return [self.preprocess(content) for content in contents]
