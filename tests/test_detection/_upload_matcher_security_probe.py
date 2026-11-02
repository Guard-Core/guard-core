import json
import re
from functools import partial

from guard_core.handlers import _suspatterns_matchers as matchers
from tests.host_load_factor import timed_normalized

_SIZES = (16384, 32768, 65536, 131072)


def measure() -> dict[str, list[list[float]]]:
    patterns = [
        matchers._FILE_UPLOAD_DANGEROUS_EXTENSION_RE,
        matchers._FILE_UPLOAD_DOUBLE_EXTENSION_RE,
        matchers._FILE_UPLOAD_TRUNCATION_RE,
        matchers._FILE_UPLOAD_DECODED_TRUNCATION_RE,
    ]
    result: dict[str, list[list[float]]] = {}
    for index, source in enumerate(patterns):
        compiled = re.compile(source, re.IGNORECASE)
        for round_index in range(5):
            round_samples: dict[str, dict[int, float]] = {}
            sizes = _SIZES if round_index % 2 == 0 else tuple(reversed(_SIZES))
            for size in sizes:
                texts = {
                    "single_quoted_fields": "filename='x.txt'\n" * (size // 17),
                    "extension_decoys": 'filename="' + ".php" * (size // 4) + '!"',
                    "newline_prefix": "\n" * size + 'nope"',
                }
                for label, text in texts.items():
                    matches, elapsed = timed_normalized(
                        partial(matchers._file_upload_scan_matches, text, compiled)
                    )
                    assert not matches
                    round_samples.setdefault(label, {})[size] = elapsed
            for label, samples_by_size in round_samples.items():
                result.setdefault(f"{index}:{label}", []).append(
                    [samples_by_size[size] for size in _SIZES]
                )
    return result


if __name__ == "__main__":
    print(json.dumps(measure()))
