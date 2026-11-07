import json
import re
import sys
from functools import partial

from guard_core.sync.handlers import _suspatterns_matchers as matchers
from guard_core.sync.handlers._suspatterns_sources import _SSTI_HASH_BRACE_SHAPE_RE
from tests.host_load_factor import minimum_normalized

_CASES = {
    "curly_keyword": ("CURLY_KEYWORD", "{{", "}}", "xsystem"),
    "percent_keyword": ("PERCENT_KEYWORD", "{%", "%}", "xsystem"),
    "dollar_brace": ("DOLLAR_BRACE_CALL", "${", "}", "7*7"),
    "curly_call": ("CURLY_CALL", "{{", "}}", "7*7"),
    "asp_keyword": ("ASP_KEYWORD", "<%", "%>", "7*7"),
    "hash_brace": ("HASH_BRACE", "#{", "}", "7*7"),
}
_SIZES = (16384, 32768, 65536, 131072)


def _payloads(opening: str, closing: str, attack: str, size: int) -> dict[str, str]:
    return {
        "closed_whitespace": opening + " " * size + closing,
        "closed_digits": opening + "1" * size + closing,
        "closed_words": opening + "a" * size + closing,
        "closed_at_dots": opening + "@" + "." * size + closing,
        "closed_quotes_digits": opening + "'" + "1" * size + "'" + closing,
        "earlier_attack_digit_suffix": opening + attack + " " + "1" * size + closing,
        "repeated_prefix_closed": opening * (size // len(opening)) + closing,
        "repeated_prefix_open": opening * (size // len(opening)),
    }


_ROUNDS = 9


def measure(label: str) -> dict[str, list[float]]:
    source_name, opening, closing, attack = _CASES[label]
    source = (
        _SSTI_HASH_BRACE_SHAPE_RE
        if label == "hash_brace"
        else getattr(matchers, "_TEMPLATE_" + source_name + "_RE")
    )
    compiled = re.compile(source, re.I)
    scanner = getattr(matchers, "_template_" + label + "_scan_matches")
    result: dict[str, list[float]] = {}
    payloads = {size: _payloads(opening, closing, attack, size) for size in _SIZES}
    for shape in payloads[_SIZES[0]]:
        result[shape] = minimum_normalized(
            [partial(scanner, payloads[size][shape], compiled) for size in _SIZES],
            _ROUNDS,
        )
    return result


if __name__ == "__main__":
    print(json.dumps(measure(sys.argv[1])))
