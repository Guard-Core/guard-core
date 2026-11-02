import re

from guard_core._builtin_import_rows import IMPORT_COMPILED_ROWS

BUILTIN_PATTERN_COMPILE_FLAGS = re.IGNORECASE

IMPORT_COMPILED_TABLE: dict[str, re.Pattern] = {
    source: re.compile(source, BUILTIN_PATTERN_COMPILE_FLAGS)
    for source in IMPORT_COMPILED_ROWS
}
