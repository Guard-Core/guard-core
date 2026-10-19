"""Route gate (a), D-75 as amended: real route templates, real example paths.

Local only (D-15): the RSSHub template list and example paths are AGPL-3.0 data
and are never committed. This script carries none of it; it reads two local TSV
files and fails loudly when one is missing. Run it against any engine tree on
PYTHONPATH:

    python -m tests.detection_gate.route_gate_real_templates \
        TEMPLATES.tsv EXAMPLES.tsv [--no-routes] [--expected FLAGGED_PATHS.txt]

TEMPLATES.tsv: `template<TAB>source` per line, Hono syntax (`:name`, `:name{regex}`,
`:name?`). EXAMPLES.tsv: `example path<TAB>...` per line. Every example gets the most
specific matching template (literal, then parameter, then catch-all) declared as the
route template of the request, converted to the `{name}` form Starlette uses.
`--no-routes` declares nothing (gate (b), the v4.4.0 behavior). Exit code 1 when
`--expected` is given and the flagged set differs from it.
"""

import asyncio
import logging
import re
import sys
from pathlib import Path

from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

_PARAMETER_RE = re.compile(r":(\w+)")
_CATCH_ALL_RE = re.compile(r"\.[+*]")


def _split_parameters(template: str) -> list[tuple[str, str | None, bool]]:
    """Pieces: ("literal", text, False) or (name, regex or None, optional)."""
    pieces: list[tuple[str, str | None, bool]] = []
    position = 0
    while position < len(template):
        match = _PARAMETER_RE.search(template, position)
        if match is None:
            pieces.append(("literal", template[position:], False))
            break
        if match.start() > position:
            pieces.append(("literal", template[position : match.start()], False))
        end = match.end()
        regex = None
        if template[end : end + 1] == "{":
            depth = 0
            for index in range(end, len(template)):
                depth += {"{": 1, "}": -1}.get(template[index], 0)
                if depth == 0:
                    regex = template[end + 1 : index]
                    end = index + 1
                    break
        optional = template[end : end + 1] == "?"
        pieces.append((match.group(1), regex, optional))
        position = end + 1 if optional else end
    return pieces


def declared_template(template: str) -> str:
    return "".join(
        (text or "") if name == "literal" else "{" + name + "}"
        for name, text, _ in _split_parameters(template)
    )


def _matcher(template: str) -> re.Pattern[str]:
    regex = ""
    for name, text, optional in _split_parameters(template):
        if name == "literal":
            regex += re.escape(text or "")
            continue
        inner = f"(?:{text or '[^/]+'})"
        if optional and regex.endswith("/"):
            regex = f"{regex[:-1]}(?:/{inner})?"
        else:
            regex += f"(?:{inner})?" if optional else inner
    return re.compile(f"^{regex}/?$")


def _specificity(template: str) -> tuple[int, int]:
    if any(
        regex and _CATCH_ALL_RE.search(regex)
        for _, regex, _ in _split_parameters(template)
    ):
        return 2, -len(template)
    return (1 if ":" in template else 0), -len(template)


def _read_rows(path: str) -> list[list[str]]:
    return [
        line.rstrip("\n").split("\t")
        for line in Path(path).read_text().splitlines()
        if line.strip()
    ]


async def run(
    templates_path: str, examples_path: str, declare: bool
) -> list[tuple[str, str | None]]:
    templates = []
    for row in _read_rows(templates_path):
        try:
            templates.append((row[0], _matcher(row[0])))
        except re.error:
            continue
    templates.sort(key=lambda item: _specificity(item[0]))
    config = SecurityConfig(enable_redis=False, rate_limit=1_000_000)
    flagged: list[tuple[str, str | None]] = []
    examples = _read_rows(examples_path)
    for row in examples:
        path = row[0]
        chosen = next(
            (name for name, rx in templates if rx.match(path.split("?")[0])), None
        )
        request = MockGuardRequest(path=path)
        if declare and chosen is not None:
            request.state.guard_route_template = declared_template(chosen)
        result = await detect_penetration_attempt(request, config)
        if result.is_threat:
            flagged.append((path, chosen))
    print(
        f"examples {len(examples)} templates {len(templates)} "
        f"routes {'declared' if declare else 'none'} flagged {len(flagged)}"
    )
    for path, chosen in flagged:
        print(f"{path}\t{chosen}")
    return flagged


def main(argv: list[str]) -> int:
    logging.disable(logging.CRITICAL)
    arguments = [a for a in argv if not a.startswith("--")]
    expected = argv[argv.index("--expected") + 1] if "--expected" in argv else None
    if expected is not None:
        arguments.remove(expected)
    flagged = asyncio.run(run(arguments[0], arguments[1], "--no-routes" not in argv))
    if expected is None:
        return 0
    wanted = set(Path(expected).read_text().split())
    return 0 if {path for path, _ in flagged} == wanted else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
