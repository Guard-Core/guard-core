import ast
import logging
import re
from collections import Counter
from typing import Any

logger = logging.getLogger(__name__)

_BINARY_CONTENT_RATIO_THRESHOLD = 0.2


def looks_like_binary_content(content: str) -> bool:
    if not content:
        return False
    non_printable = (
        0
        if content.isprintable()
        else len(content) - sum(map(str.isprintable, content))
    )
    non_text_count = (
        non_printable
        - content.count("\t")
        - content.count("\r")
        - content.count("\n")
        + content.count("�")
    )
    return non_text_count / len(content) >= _BINARY_CONTENT_RATIO_THRESHOLD


class SemanticAnalyzer:
    def __init__(self) -> None:
        self.attack_keywords = {
            "xss": {
                "script",
                "javascript",
                "onerror",
                "onload",
                "onclick",
                "onmouseover",
                "alert",
                "eval",
                "document",
                "cookie",
                "window",
                "location",
            },
            "sql": {
                "select",
                "union",
                "insert",
                "update",
                "delete",
                "drop",
                "from",
                "where",
                "order",
                "group",
                "having",
                "concat",
                "substring",
                "database",
                "table",
                "column",
            },
            "command": {
                "exec",
                "system",
                "shell",
                "cmd",
                "bash",
                "powershell",
                "wget",
                "curl",
                "nc",
                "netcat",
                "chmod",
                "chown",
                "sudo",
                "passwd",
            },
            "path": {"etc", "passwd", "shadow", "hosts", "proc", "boot", "win", "ini"},
            "template": {
                "render",
                "template",
                "jinja",
                "mustache",
                "handlebars",
                "ejs",
                "pug",
                "twig",
            },
        }

        self.suspicious_chars = {
            "brackets": r"[<>{}()\[\]]",
            "quotes": r"['\"`]",
            "slashes": r"[/\\]",
            "special": r"[;&|$]",
            "wildcards": r"[*?]",
        }

        self.attack_structures = {
            "tag_like": r"<[^>]+>",
            "function_call": r"\w{1,64}\s*\([^)]{0,256}\)",
            "command_chain": r"[;&|]{1,2}",
            "path_traversal": r"\.{2,20}[/\\]",
            "url_pattern": r"[a-z]{1,32}://",
        }

    def _tag_scan_window(self, content: str) -> str:
        return content[: content.rfind(">") + 1]

    def extract_tokens(self, content: str) -> list[str]:
        MAX_CONTENT_LENGTH = 50000
        if len(content) > MAX_CONTENT_LENGTH:
            content = content[:MAX_CONTENT_LENGTH]

        content = re.sub(r"\s+", " ", content)

        MAX_TOKENS = 1000
        tokens = re.findall(r"\b\w+\b", content.lower())[:MAX_TOKENS]

        special_patterns = []
        for name, pattern in self.attack_structures.items():
            scan_content = (
                self._tag_scan_window(content) if name == "tag_like" else content
            )
            special_patterns.extend(
                re.findall(pattern, scan_content, re.IGNORECASE)[:10]
            )

            if len(special_patterns) >= 50:
                break

        return (tokens + special_patterns)[:MAX_TOKENS]

    def calculate_entropy(self, content: str) -> float:
        if not content:
            return 0.0

        MAX_ENTROPY_LENGTH = 10000
        if len(content) > MAX_ENTROPY_LENGTH:
            content = content[:MAX_ENTROPY_LENGTH]

        char_counts = Counter(content)
        length = len(content)

        import math

        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def detect_encoding_layers(self, content: str) -> int:
        MAX_SCAN_LENGTH = 10000
        if len(content) > MAX_SCAN_LENGTH:
            content = content[:MAX_SCAN_LENGTH]

        layers = 0

        if re.search(r"%[0-9a-fA-F]{2}", content):
            layers += 1

        if re.search(r"[A-Za-z0-9+/]{4,}={0,2}", content):
            layers += 1

        if re.search(r"(?:0x)?[0-9a-fA-F]{4,}", content):
            layers += 1

        if re.search(r"\\u[0-9a-fA-F]{4}", content):
            layers += 1

        if re.search(r"&[#\w]+;", content):
            layers += 1

        return layers

    def _calculate_base_score(self, token_set: set[str], keywords: set[str]) -> float:
        if not keywords:
            return 0.0

        matches = len(token_set.intersection(keywords))
        return matches / len(keywords)

    def _get_structural_pattern_boost(self, attack_type: str, content: str) -> float:
        pattern_checks = {
            "xss": (self.attack_structures["tag_like"], 0),
            "sql": (r"\b(?:union|select|from|where)\b", re.IGNORECASE),
            "command": (r"[;&|]", 0),
            "path": (self.attack_structures["path_traversal"], 0),
        }

        if attack_type not in pattern_checks:
            return 0.0

        pattern, flags = pattern_checks[attack_type]
        scan_content = (
            self._tag_scan_window(content) if attack_type == "xss" else content
        )
        if re.search(pattern, scan_content, flags):
            return 0.3

        return 0.0

    def _attack_probabilities_for_tokens(
        self, token_set: set[str], content: str
    ) -> dict[str, float]:
        probabilities = {}

        for attack_type, keywords in self.attack_keywords.items():
            base_score = self._calculate_base_score(token_set, keywords)
            pattern_boost = self._get_structural_pattern_boost(attack_type, content)
            score = base_score + pattern_boost
            probabilities[attack_type] = min(score, 1.0)

        return probabilities

    def analyze_attack_probability(self, content: str) -> dict[str, float]:
        tokens = self.extract_tokens(content)
        return self._attack_probabilities_for_tokens(set(tokens), content)

    def detect_obfuscation(self, content: str) -> bool:
        if looks_like_binary_content(content):
            return False

        if self.calculate_entropy(content) > 4.5:
            return True

        if self.detect_encoding_layers(content) > 2:
            return True

        special_char_ratio = len(re.findall(r"[^a-zA-Z0-9\s]", content)) / max(
            len(content), 1
        )
        if special_char_ratio > 0.4:
            return True

        if re.search(r"\S{100,}", content):
            return True

        return False

    def extract_suspicious_patterns(self, content: str) -> list[dict[str, Any]]:
        patterns = []

        for name, pattern in self.attack_structures.items():
            scan_content = (
                self._tag_scan_window(content) if name == "tag_like" else content
            )
            for match in re.finditer(pattern, scan_content, re.IGNORECASE):
                context_start = max(0, match.start() - 20)
                context_end = min(len(content), match.end() + 20)
                patterns.append(
                    {
                        "type": name,
                        "pattern": match.group(),
                        "position": match.start(),
                        "context": content[context_start:context_end],
                    }
                )

        return patterns

    def _check_code_pattern_risks(self, content: str) -> float:
        risk = 0.0

        if re.search(r"[\{\}].*[\{\}]", content):
            risk += 0.2

        if re.search(self.attack_structures["function_call"], content):
            risk += 0.2

        if re.search(r"[$@]\w+", content):
            risk += 0.1

        if re.search(r"[=+\-*/]{2,}", content):
            risk += 0.1

        return risk

    def _check_ast_parsing_risk(self, content: str) -> float:
        MAX_AST_LENGTH = 1000

        if len(content) > MAX_AST_LENGTH:
            return 0.0

        try:
            import concurrent.futures

            def _parse_ast() -> bool:
                try:
                    ast.parse(content, mode="eval")
                    return True
                except SyntaxError:
                    return False
                except Exception:
                    return False

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_parse_ast)
                try:
                    if future.result(timeout=0.1):
                        return 0.3
                except concurrent.futures.TimeoutError:
                    return 0.2

        except Exception:
            logger.warning(
                "AST parsing risk check failed and was skipped", exc_info=True
            )

        return 0.0

    def _check_injection_keywords(self, content: str) -> float:
        injection_keywords = [
            "eval",
            "exec",
            "compile",
            "__import__",
            "globals",
            "locals",
        ]

        for keyword in injection_keywords:
            if re.search(rf"\b{keyword}\b", content, re.IGNORECASE):
                return 0.2

        return 0.0

    def analyze_code_injection_risk(self, content: str) -> float:
        risk_score = 0.0
        risk_score += self._check_code_pattern_risks(content)
        risk_score += self._check_ast_parsing_risk(content)
        risk_score += self._check_injection_keywords(content)
        return min(risk_score, 1.0)

    def analyze(self, content: str) -> dict[str, Any]:
        tokens = self.extract_tokens(content)
        return {
            "attack_probabilities": self._attack_probabilities_for_tokens(
                set(tokens), content
            ),
            "entropy": self.calculate_entropy(content),
            "encoding_layers": self.detect_encoding_layers(content),
            "is_obfuscated": self.detect_obfuscation(content),
            "suspicious_patterns": self.extract_suspicious_patterns(content),
            "code_injection_risk": self.analyze_code_injection_risk(content),
            "token_count": len(tokens),
        }

    def get_threat_score(self, analysis_results: dict[str, Any]) -> float:
        score = 0.0

        attack_probs = analysis_results.get("attack_probabilities", {})
        if attack_probs:
            max_prob = max(attack_probs.values())
            score += max_prob * 0.3

        if analysis_results.get("is_obfuscated", False):
            score += 0.2

        encoding_layers = analysis_results.get("encoding_layers", 0)
        if encoding_layers > 0:
            score += min(encoding_layers * 0.1, 0.2)

        injection_risk = analysis_results.get("code_injection_risk", 0.0)
        score += injection_risk * 0.2

        patterns = analysis_results.get("suspicious_patterns", [])
        if patterns:
            score += min(len(patterns) * 0.05, 0.1)

        return float(min(score, 1.0))
