#!/usr/bin/env python3
"""Differential of interop/py_body_surface.py against the engine itself.

For every (body, content-type) input the engine's own _scan_request_body runs
with sus_patterns_handler.detect recording each (value, context) it is asked
to scan (budgets lifted, so the record is the whole surface), and the model's
surface_entries list is compared with that record, value for value and in
scan order. A forced entry (a mongo operator key) ends the engine's walk with
a hit instead of a detect call, so the model list is cut before it and the
engine must have reported the hit.

Inputs: the 220 extraction corpus pairs, the body inputs of the conformance
fixtures (pipeline drives, binary and cost bodies, each carried as text/plain,
JSON, form and multipart), and the WP19 shapes (nested bodies at depths 32 to
512 on every surface, escaped and plain literals nested one to three levels,
repeated keys per level, a flat and a backslash-heavy 257 KB body).

    uv run python interop/body_surface_differential.py [report.json]

Exit 0 when 0 inputs differ.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent))

from extraction_corpus import (
    FORM_CT,
    JSON_CT,
    MPART_CT,
    TEXT_CT,
    _field,
    _multipart,
    corpus,
)
from py_body_surface import surface_entries

from guard_core._utils.body_content_scan import _scan_request_body
from guard_core._utils.detection_scan import (
    _scan_char_cap,
    _scan_value_cap,
)
from guard_core.handlers.suspatterns_handler import sus_patterns_handler

CASES_DIR = Path(__file__).resolve().parent.parent / "specs" / "fixtures" / "cases"
OCTET_CT = "application/octet-stream"
DEPTHS = (1, 2, 31, 32, 33, 64, 200, 511, 512, 513, 600)
ESCAPED_PAYLOADS = {
    "xss-u": "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    "sqli-u": "1\\u0027 OR \\u00271\\u0027=\\u00271",
    "xss-plain": "<script>alert(1)</script>",
    "benign": "hello world",
}
Input = tuple[str, str, str]


def _nested_object(depth: int, leaf: str = "hello") -> str:
    return '{"a":' * depth + json.dumps(leaf) + "}" * depth


def _nested_levels(levels: int, payload: str) -> str:
    text = '{"q":"' + payload + '"}'
    for _ in range(levels - 1):
        text = json.dumps({"x": text})
    return text


def _repeated_key_levels(depth: int) -> str:
    return '{"k":' * depth + '"leaf"' + "}" * depth


def _carriers(label: str, text: str) -> list[Input]:
    form = urlencode([("q", text)], errors="surrogateescape")
    mpart = _multipart([_field("f", text)]).decode("utf-8", "surrogateescape")
    return [
        (f"{label}|text", text, TEXT_CT),
        (f"{label}|octet", text, OCTET_CT),
        (f"{label}|json-field", json.dumps({"q": text}), JSON_CT),
        (f"{label}|json-array", json.dumps({"items": [text, "z"]}), JSON_CT),
        (f"{label}|form", form, FORM_CT),
        (f"{label}|multipart", mpart, MPART_CT),
    ]


def extraction_corpus_inputs() -> list[Input]:
    return [
        (f"corpus|{label}", body.decode("utf-8", "surrogateescape"), content_type)
        for label, body, content_type in corpus()
    ]


def fixture_inputs() -> list[Input]:
    inputs: list[Input] = []
    pipeline_bodies = set()
    for path in sorted(CASES_DIR.glob("pipeline_*.json")):
        for case in json.loads(path.read_text())["cases"]:
            for drive in case.get("drives", []):
                if isinstance(drive.get("body"), str):
                    pipeline_bodies.add(drive["body"])
    for index, body in enumerate(sorted(pipeline_bodies)):
        inputs.extend(_carriers(f"fixture-pipeline-{index}", body))
    for suite in ("binary_bodies", "cost_bodies"):
        for case in json.loads((CASES_DIR / f"{suite}.json").read_text())["cases"]:
            inputs.extend(_carriers(f"fixture-{case['id']}", case["input"]["content"]))
    return inputs


def wp19_inputs() -> list[Input]:
    inputs: list[Input] = []
    attack = "' OR 1=1--"
    for depth in DEPTHS:
        nested = _nested_object(depth)
        inputs += [
            (
                f"wp19|depth{depth}|json-field",
                json.dumps({"q": nested, "z": attack}),
                JSON_CT,
            ),
            (
                f"wp19|depth{depth}|json-array-leaf",
                json.dumps({"items": [nested, attack]}),
                JSON_CT,
            ),
            (
                f"wp19|depth{depth}|form",
                urlencode([("q", nested), ("z", attack)]),
                FORM_CT,
            ),
            (
                f"wp19|depth{depth}|text",
                json.dumps({"q": nested, "z": attack}),
                TEXT_CT,
            ),
            (
                f"wp19|depth{depth}|octet",
                json.dumps({"q": nested, "z": attack}),
                OCTET_CT,
            ),
            (f"wp19|depth{depth}|bare-text", nested, TEXT_CT),
            (f"wp19|depth{depth}|json-body", nested, JSON_CT),
            (
                f"wp19|depth{depth}|multipart",
                _multipart([_field("f", nested)]).decode(),
                MPART_CT,
            ),
            (
                f"wp19|repeat-key{depth}|json-field",
                json.dumps({"q": _repeated_key_levels(depth)}),
                JSON_CT,
            ),
            (
                f"wp19|repeat-key{depth}|form",
                urlencode([("q", _repeated_key_levels(depth))]),
                FORM_CT,
            ),
        ]
    for name, payload in ESCAPED_PAYLOADS.items():
        for levels in (1, 2, 3):
            body = json.dumps({"data": _nested_levels(levels, payload)})
            for content_type in (JSON_CT, TEXT_CT, OCTET_CT):
                inputs.append(
                    (f"wp19|{name}|levels{levels}|{content_type}", body, content_type)
                )
    flat = json.dumps({f"f{i}": "pending review of the order" for i in range(9000)})
    escaped = json.dumps({f"f{i}": "café “quoted” \\ slash" for i in range(4000)})
    heavy = json.dumps(
        {f"f{i}": "a\\\\b\\\\c\\\\d\\\\e" for i in range(6000)}, ensure_ascii=False
    )
    twin = '{"a":"<script>x</script>","b":"\\u003cscript\\u003ex\\u003c/script\\u003e"}'
    for label, body in (
        ("flat257k", flat),
        ("escaped", escaped),
        ("backslash-heavy", heavy),
        ("escaped-twin", twin),
    ):
        for content_type in (TEXT_CT, OCTET_CT, JSON_CT):
            inputs.append((f"wp19|{label}|{content_type}", body, content_type))
    inputs += [
        ("wp19|undeclared-array|text", '[1,"a\\u0041b",["x\\ny"]]', TEXT_CT),
        ("wp19|undeclared-malformed|text", '{"a":"x\\u0041', TEXT_CT),
        ("wp19|undeclared-no-backslash|text", '{"a":"b","c":["d"]}', TEXT_CT),
        (
            "wp19|mongo-key-embedded|form",
            urlencode([("q", '{"a":{"$ne":1}}'), ("r", "x")]),
            FORM_CT,
        ),
        ("wp19|mongo-key|json", '{"a":1,"$where":"x","b":2}', JSON_CT),
        (
            "wp19|too-deep-literals|form",
            urlencode([("q", '{"a":"x\\u0041"}' + "[" * 600 + "]" * 600)]),
            FORM_CT,
        ),
        (
            "wp19|too-deep-literals|json-field",
            json.dumps({"q": "[" * 600 + '"x\\u0041y"' + "]" * 600}),
            JSON_CT,
        ),
    ]
    return inputs


async def engine_scan(
    raw_body: str, content_type: str
) -> tuple[list[tuple[str, str]], bool]:
    recorded: list[tuple[str, str]] = []

    async def record(*, content: str, context: str, **_ignored: Any) -> dict[str, Any]:
        recorded.append((content, context))
        return {"is_threat": False, "threats": []}

    _scan_value_cap.set(10**9)
    _scan_char_cap.set(10**12)
    with patch.object(sus_patterns_handler, "detect", record):
        hit = await _scan_request_body(
            raw_body, content_type, set(), None, "127.0.0.1", "differential", None
        )
    return recorded, bool(hit[0])


def model_scan(raw_body: str, content_type: str) -> tuple[list[tuple[str, str]], bool]:
    listed: list[tuple[str, str]] = []
    for entry in surface_entries(raw_body, content_type):
        if entry.forced:
            return listed, True
        listed.append((entry.value, entry.context))
    return listed, False


def compare(
    label: str, raw_body: str, content_type: str, engine: Any, model: Any
) -> dict[str, Any] | None:
    engine_list, engine_hit = engine
    model_list, model_forced = model
    if engine_list == model_list and engine_hit == model_forced:
        return None
    first = next(
        (
            i
            for i, (a, b) in enumerate(zip(engine_list, model_list, strict=False))
            if a != b
        ),
        min(len(engine_list), len(model_list)),
    )
    return {
        "input": label,
        "content_type": content_type,
        "engine_count": len(engine_list),
        "model_count": len(model_list),
        "engine_hit": engine_hit,
        "model_forced": model_forced,
        "first_difference_index": first,
        "engine_at": [engine_list[first][0][:80], engine_list[first][1]]
        if first < len(engine_list)
        else None,
        "model_at": [model_list[first][0][:80], model_list[first][1]]
        if first < len(model_list)
        else None,
    }


async def main_async() -> int:
    inputs = extraction_corpus_inputs() + fixture_inputs() + wp19_inputs()
    groups = {"corpus": 0, "fixture": 0, "wp19": 0}
    differing: list[dict[str, Any]] = []
    for label, raw_body, content_type in inputs:
        groups[label.split("|", 1)[0].split("-", 1)[0]] += 1
        engine = await asyncio.create_task(engine_scan(raw_body, content_type))
        difference = compare(
            label, raw_body, content_type, engine, model_scan(raw_body, content_type)
        )
        if difference is not None:
            differing.append(difference)
    report = {
        "inputs": len(inputs),
        "by_group": groups,
        "differing": len(differing),
        "differences": differing,
    }
    if len(sys.argv) > 1:
        Path(sys.argv[1]).write_text(json.dumps(report, indent=1) + "\n")
    print(f"inputs {len(inputs)} {groups}, differing {len(differing)}")
    for difference in differing[:20]:
        print(json.dumps(difference))
    return 1 if differing else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main_async()))
