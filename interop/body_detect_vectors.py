#!/usr/bin/env python3
"""Body-surface detect vectors: raw-view and body-scan classes end to end.

Extends the interop suite beyond the single-value detect vectors
(go_php_binary_vectors.py) with vectors that go through each family's real
BODY surface (extraction plus per-value detection, exactly what the
suspicious-activity pipeline scans):

  - backslash probes carried inside real bodies (urlencoded form fields,
    multipart fields, JSON leaves, embedded JSON strings inside form
    values), the raw-view recon scan classes from upstream PR #121;
  - bare-word innocence through real bodies (SAP / default in form fields,
    multipart fields, JSON leaves and query strings);
  - island smuggling: attacks inside binary-dense multipart file parts that
    the island reduction must still hand to the pattern scan;
  - mongo operator keys at the JSON body top level and inside embedded
    JSON form/multipart values;
  - raw-text-spanning attacks on JSON-parsing values (the walk is clean,
    the raw field text carries the pattern: this pins whether a family
    still scans the raw value after a clean embedded walk, which the
    reference does and which the Go/Rust extractors model differently).

Expectations are ALWAYS taken from the live Python engine on the same
input (detect_penetration_attempt), never hardcoded.

Participants:
  Python  in-process (interop/py_body_surface.body_verdict)
  Go      the detect mode of interop/probes/guardcore_body_probe_test.go
          (docker golang:1.26-alpine against a checkout root)
  PHP     the detect mode of interop/probes/guardcore_body_probe.php
          (docker php:8.3-cli against a checkout root with vendor/)
  TS      the pipeline mode of interop/probes/guardcore_body_probe.test.ts
          (initializeSecurityMiddleware pipeline, local vitest)
  Rust    the detect mode of interop/probes/guardcore_rs_probe.rs
          (throwaway cargo project, local cargo)

Run:
    uv run python interop/body_detect_vectors.py
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from py_body_surface import body_verdict

GUARD_CORE_ROOT = Path(__file__).resolve().parent.parent
ECOSYSTEM_ROOT = GUARD_CORE_ROOT.parent.parent
INTEROP_DIR = Path(__file__).resolve().parent
REPORTS_DIR = INTEROP_DIR / "reports"
PROBES_DIR = INTEROP_DIR / "probes"

GO_ROOT = Path(
    os.environ.get(
        "GUARD_EXTRACTION_GO_ROOT", str(ECOSYSTEM_ROOT / "Golang" / "guard-core-go")
    )
)
PHP_ROOT = Path(
    os.environ.get(
        "GUARD_EXTRACTION_PHP_ROOT", str(ECOSYSTEM_ROOT / "PHP" / "guard-core-php")
    )
)
TS_ROOT = Path(
    os.environ.get(
        "GUARD_EXTRACTION_TS_ROOT",
        str(ECOSYSTEM_ROOT / "Typescript" / "guard-core-ts"),
    )
)
RS_ROOT = Path(
    os.environ.get(
        "GUARD_EXTRACTION_RS_ROOT", str(ECOSYSTEM_ROOT / "Rust" / "guard-core-rs")
    )
)

FORM_CT = "application/x-www-form-urlencoded"
JSON_CT = "application/json"
BOUNDARY = "guardbodyvec1"
MPART_CT = f"multipart/form-data; boundary={BOUNDARY}"
TEXT_CT = "text/plain"

ATTACK_ISLAND = bytes([0x85]) * 60 + b"$(cat /etc/passwd)" + bytes([0x87]) * 60
CLEAN_ISLAND = bytes([0x85]) * 60 + b"nothing to see here" + bytes([0x87]) * 60


def _multipart(parts: list[bytes]) -> bytes:
    body = b""
    for part in parts:
        body += b"--" + BOUNDARY.encode() + b"\r\n" + part + b"\r\n"
    body += b"--" + BOUNDARY.encode() + b"--\r\n"
    return body


def _field(name: str, value: str) -> bytes:
    return (
        f'Content-Disposition: form-data; name="{name}"'.encode() + b"\r\n\r\n"
    ) + value.encode("utf-8", "surrogatepass")


def _file(name: str, filename: str, payload: bytes) -> bytes:
    return (
        f'Content-Disposition: form-data; name="{name}"; filename="{filename}"'.encode()
        + b"\r\nContent-Type: application/octet-stream"
        + b"\r\n\r\n"
        + payload
    )


def vectors() -> list[tuple[str, bytes, str, dict[str, str], str]]:
    """(label, body, content_type, query, url_path) triples."""
    cases: list[tuple[str, bytes, str, dict[str, str], str]] = []

    # Backslash probes through real bodies.
    cases.append(
        (
            "body_bs_default_form_field",
            b"next=%5Cdefault",
            FORM_CT,
            {},
            "/",
        )
    )
    cases.append(
        (
            "body_bs_default_mpart_field",
            _multipart([_field("next", "\\default")]),
            MPART_CT,
            {},
            "/",
        )
    )
    cases.append(
        (
            "body_bs_default_json_leaf",
            b'{"next":"\\\\default"}',
            JSON_CT,
            {},
            "/",
        )
    )
    cases.append(
        (
            "body_bs_default_embedded_json",
            b"next=%7B%22next%22%3A%22%5C%5Cdefault%22%7D",
            FORM_CT,
            {},
            "/",
        )
    )

    # Bare-word innocence through real bodies.
    cases.append(("body_bare_sap_query", b"", FORM_CT, {"system": "SAP"}, "/"))
    cases.append(
        ("body_bare_sap_form_field", b"system=SAP", FORM_CT, {}, "/"),
    )
    cases.append(
        (
            "body_bare_sap_mpart_field",
            _multipart([_field("system", "SAP")]),
            MPART_CT,
            {},
            "/",
        )
    )
    cases.append(("body_bare_sap_json_leaf", b'{"system":"SAP"}', JSON_CT, {}, "/"))
    cases.append(
        (
            "body_bare_default_mpart_field",
            _multipart([_field("page", "default")]),
            MPART_CT,
            {},
            "/",
        )
    )

    # Island smuggling through real bodies.
    cases.append(
        (
            "body_island_smuggle_attack",
            _multipart([_file("blob", "blob.bin", ATTACK_ISLAND)]),
            MPART_CT,
            {},
            "/",
        )
    )
    cases.append(
        (
            "body_island_smuggle_clean",
            _multipart([_file("blob", "blob.bin", CLEAN_ISLAND)]),
            MPART_CT,
            {},
            "/",
        )
    )
    cases.append(
        (
            "body_island_smuggle_traversal",
            _multipart(
                [
                    _field("note", "clean note"),
                    _file(
                        "blob",
                        "blob.bin",
                        bytes([0x90]) * 80
                        + b"../../../etc/passwd"
                        + bytes([0x91]) * 80,
                    ),
                ]
            ),
            MPART_CT,
            {},
            "/",
        )
    )

    # Mongo operator keys through real bodies.
    cases.append(
        (
            "body_mongo_top_level",
            b'{"$where":"1==1","user":"bob"}',
            JSON_CT,
            {},
            "/",
        )
    )
    cases.append(
        (
            "body_mongo_nested",
            b'{"filter":{"$ne":1}}',
            JSON_CT,
            {},
            "/",
        )
    )
    cases.append(("body_mongo_form_field", b'q={"$exists":true}', FORM_CT, {}, "/"))
    cases.append(
        (
            "body_mongo_mpart_field",
            _multipart([_field("q", '{"$regex":"^a"}')]),
            MPART_CT,
            {},
            "/",
        )
    )

    # Embedded JSON leaves through real bodies.
    cases.append(
        (
            "body_embedded_json_leaf_attack",
            b'data={"path":"../../../etc/passwd"}',
            FORM_CT,
            {},
            "/",
        )
    )
    cases.append(
        (
            "body_embedded_json_leaf_clean",
            b'data={"name":"bob","tags":["a","b"]}',
            FORM_CT,
            {},
            "/",
        )
    )

    # Raw-text-spanning attacks on JSON-parsing values: the walk leaves are
    # clean, the raw field text carries the pattern. The reference still
    # scans the raw value after a clean walk; extractors that model the
    # embedded walk as replacing the raw scan will differ here.
    cases.append(
        (
            "body_raw_span_sqli_comment",
            b'q={"a":"x/*","b":"*/SELECT"}',
            FORM_CT,
            {},
            "/",
        )
    )
    cases.append(
        (
            "body_raw_span_sqli_comment_json",
            b'{"a":"x/*","b":"*/SELECT"}',
            JSON_CT,
            {},
            "/",
        )
    )
    cases.append(
        (
            "body_raw_json_blob_attack",
            b'{"note":"clean","tail":"1 UNION SELECT password FROM users--"}',
            JSON_CT,
            {},
            "/",
        )
    )

    # Whole-body controls through real bodies.
    cases.append(
        (
            "body_plain_attack_blob",
            b"1' UNION SELECT username,password FROM users--",
            TEXT_CT,
            {},
            "/",
        )
    )
    cases.append(
        ("body_clean_prose_blob", b"completely clean prose body", TEXT_CT, {}, "/")
    )
    return cases


def _run(
    command: list[str],
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> None:
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=1800, env=env, cwd=cwd
    )
    if result.returncode != 0:
        raise SystemExit(
            f"probe failed ({' '.join(command[:6])}...): "
            f"{(result.stdout + result.stderr)[-3000:]}"
        )


def _vector_dicts(
    cases: list[tuple[str, bytes, str, dict[str, str], str]],
) -> list[dict[str, Any]]:
    return [
        {
            "label": label,
            "body_b64": base64.b64encode(body).decode("ascii"),
            "content_type": content_type,
            "query": query,
            "url_path": url_path,
        }
        for label, body, content_type, query, url_path in cases
    ]


def _go_detect(vectors_in: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    input_path = REPORTS_DIR / "go_bodydetect_input.json"
    output_path = REPORTS_DIR / "go_bodydetect_output.json"
    input_path.write_text(json.dumps(vectors_in, indent=2))
    probe_target = GO_ROOT / "guardcore" / "guardcore_body_probe_test.go"
    probe_installed = not probe_target.exists()
    if probe_installed:
        shutil.copy(PROBES_DIR / "guardcore_body_probe_test.go", probe_target)
    try:
        _run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{GO_ROOT}:/app",
                "-v",
                f"{INTEROP_DIR}:/interop",
                "-w",
                "/app",
                "-e",
                "INTEROP_BODY_DETECT_INPUT=/interop/reports/go_bodydetect_input.json",
                "-e",
                "INTEROP_BODY_DETECT_OUTPUT=/interop/reports/go_bodydetect_output.json",
                "-e",
                "GOCACHE=/tmp/gocache",
                "golang:1.26-alpine",
                "go",
                "test",
                "-tags",
                "interop",
                "-run",
                "^TestGuardCoreBodyProbe$",
                "-count=1",
                "./guardcore",
            ]
        )
    finally:
        if probe_installed:
            probe_target.unlink()
    return {entry["label"]: entry for entry in json.loads(output_path.read_text())}


def _php_detect(vectors_in: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    input_path = REPORTS_DIR / "php_bodydetect_input.json"
    output_path = REPORTS_DIR / "php_bodydetect_output.json"
    input_path.write_text(json.dumps(vectors_in, indent=2))
    _run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{PHP_ROOT}:/app",
            "-v",
            f"{PROBES_DIR / 'guardcore_body_probe.php'}:"
            "/app/bin/guardcore_body_probe.php",
            "-v",
            f"{INTEROP_DIR}:/interop",
            "-w",
            "/app",
            "-e",
            "INTEROP_BODY_DETECT_INPUT=/interop/reports/php_bodydetect_input.json",
            "-e",
            "INTEROP_BODY_DETECT_OUTPUT=/interop/reports/php_bodydetect_output.json",
            "php:8.3-cli",
            "php",
            "bin/guardcore_body_probe.php",
        ]
    )
    return {entry["label"]: entry for entry in json.loads(output_path.read_text())}


def _ts_pipeline(vectors_in: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    input_path = REPORTS_DIR / "ts_pipeline_input.json"
    output_path = REPORTS_DIR / "ts_pipeline_output.json"
    input_path.write_text(json.dumps(vectors_in, indent=2))
    probe_dir = TS_ROOT / "packages" / "core" / "tests" / "interop"
    probe_dir.mkdir(parents=True, exist_ok=True)
    probe_target = probe_dir / "guardcore_body_probe.test.ts"
    probe_installed = not probe_target.exists()
    if probe_installed:
        shutil.copy(PROBES_DIR / "guardcore_body_probe.test.ts", probe_target)
    env = dict(os.environ)
    env.update(
        {
            "GUARDCORE_PROBE_MODE": "pipeline",
            "GUARDCORE_PROBE_INPUT": str(input_path),
            "GUARDCORE_PROBE_OUTPUT": str(output_path),
        }
    )
    try:
        _run(
            [
                str(TS_ROOT / "packages" / "core" / "node_modules" / ".bin" / "vitest"),
                "run",
                "tests/interop/guardcore_body_probe.test.ts",
                "--no-coverage",
            ],
            env=env,
            cwd=TS_ROOT / "packages" / "core",
        )
    finally:
        if probe_installed:
            probe_target.unlink()
        try:
            probe_dir.rmdir()
        except OSError:
            pass
    return {entry["label"]: entry for entry in json.loads(output_path.read_text())}


def _rs_materialize() -> Path:
    project = REPORTS_DIR / "rust-probe"
    project.mkdir(parents=True, exist_ok=True)
    (project / "src").mkdir(exist_ok=True)
    engine_crate = RS_ROOT / "crates" / "guard-core-engine"
    tower_crate = ECOSYSTEM_ROOT / "Rust" / "tower-guard-rs"
    (project / "Cargo.toml").write_text(
        "[package]\n"
        'name = "guardcore-rust-probe"\n'
        'version = "0.1.0"\n'
        'edition = "2021"\n\n'
        "[dependencies]\n"
        f'guard-core-engine = {{ path = "{engine_crate}" }}\n'
        f'tower-guard-rs = {{ path = "{tower_crate}" }}\n'
        'bytes = "1.10"\n'
        'http = "1.3"\n'
        'http-body-util = "0.1"\n'
        'tower = { version = "0.5", default-features = false, features = ["util"] }\n'
        'tokio = { version = "1", features = ["macros", "rt-multi-thread"] }\n'
    )
    shutil.copy(PROBES_DIR / "guardcore_rs_probe.rs", project / "src" / "main.rs")
    return project


def _rs_detect(
    vectors_in: list[dict[str, Any]], project: Path
) -> dict[str, dict[str, Any]]:
    input_path = REPORTS_DIR / "rs_bodydetect_input.txt"
    output_path = REPORTS_DIR / "rs_bodydetect_output.txt"
    with input_path.open("w") as handle:
        for vector in vectors_in:
            handle.write(
                f"{vector['label']}\t{vector['content_type']}\t{vector['body_b64']}\n"
            )
    env = dict(os.environ)
    env.update(
        {
            "GUARDCORE_RS_PROBE_MODE": "detect",
            "GUARDCORE_RS_PROBE_INPUT": str(input_path),
            "GUARDCORE_RS_PROBE_OUTPUT": str(output_path),
        }
    )
    _run(
        ["cargo", "run", "--quiet", "--manifest-path", str(project / "Cargo.toml")],
        env=env,
    )
    results: dict[str, dict[str, Any]] = {}
    for line in output_path.read_text().splitlines():
        if not line:
            continue
        label, is_threat, categories = line.split("\t")
        results[label] = {
            "label": label,
            "is_threat": is_threat == "1",
            "categories": sorted(filter(None, categories.split(","))),
        }
    return results


async def main() -> int:
    started = time.monotonic()
    cases = vectors()
    print(f"body detect vectors: {len(cases)}")

    print("python reference (live engine)...")
    py_verdicts: dict[str, dict[str, Any]] = {}
    for label, body, content_type, query, url_path in cases:
        py_verdicts[label] = await body_verdict(body, content_type, query, url_path)

    vectors_in = _vector_dicts(cases)
    print("go detect probe...")
    go_verdicts = _go_detect(vectors_in)
    print("php detect probe...")
    php_verdicts = _php_detect(vectors_in)
    print("ts pipeline probe...")
    ts_verdicts = _ts_pipeline(vectors_in)
    print("rust detect probe...")
    project = _rs_materialize()
    rs_verdicts = _rs_detect(vectors_in, project)

    report: dict[str, Any] = {"vectors": [], "green": 0, "red": 0}
    for label, _body, content_type, query, url_path in cases:
        py = py_verdicts[label]
        row = {
            "label": label,
            "content_type": content_type,
            "query": query,
            "url_path": url_path,
            "py_is_threat": py["is_threat"],
            "py_categories": py["categories"],
            "families": {},
            "diffs": [],
        }
        for family, verdicts, blocked_key in (
            ("go", go_verdicts, "is_threat"),
            ("php", php_verdicts, "is_threat"),
            ("ts", ts_verdicts, "blocked"),
            ("rust", rs_verdicts, "is_threat"),
        ):
            verdict = verdicts.get(label)
            if verdict is None:
                row["families"][family] = "MISSING"
                row["diffs"].append(f"{family}: no verdict")
                continue
            blocked = bool(verdict[blocked_key])
            row["families"][family] = f"{'THREAT' if blocked else 'clean'}" + (
                f" {verdict.get('categories', [])}"
                if blocked and verdict.get("categories")
                else ""
            )
            if blocked != py["is_threat"]:
                row["diffs"].append(
                    f"{family}: is_threat={blocked} != py={py['is_threat']}"
                )
            elif blocked and family in ("go", "php", "rust"):
                family_categories = sorted(verdict.get("categories", []))
                if family_categories and family_categories != py["categories"]:
                    row["diffs"].append(
                        f"{family}: categories {family_categories} != "
                        f"py {py['categories']}"
                    )
        if row["diffs"]:
            report["red"] += 1
            print(f"RED   {label}: {row['diffs']}")
        else:
            report["green"] += 1
            print(f"green {label} (py_is_threat={py['is_threat']})")
        report["vectors"].append(row)

    report["elapsed_s"] = round(time.monotonic() - started, 2)
    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / "body_detect_vectors.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False)
    )
    total = report["green"] + report["red"]
    print(f"\ntotal: {report['green']}/{total} vectors green in {report['elapsed_s']}s")
    print("RESULT:", "GREEN" if report["red"] == 0 else "RED")
    return 0 if report["red"] == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
