#!/usr/bin/env python3
"""Middleware-level equivalence spot checks across the five families.

For every family, ONE end-to-end blocked case and ONE innocence case run
through the family's real middleware/pipeline (not the bare detect()):

  smuggled  a request whose multipart body carries an attack inside a
            binary-dense file part (the island case): the island reduction
            must still hand the printable runs to the pattern scan and the
            request MUST be blocked;
  innocent  a request with `?system=SAP` (the recon leading-separator
            gate's bare-word case): the request MUST pass.

Families and their middleware surfaces:

  Python  SuspiciousActivityCheck (core/checks/implementations/
          suspicious_activity.py) built like
          tests/test_threat_ban_config.py does, check() on a body-carrying
          request stub
  Go      the tag-gated middleware mode of interop/probes/
          guardcore_body_probe_test.go: the real suspiciousActivityCheck
          built like pipeline_test.go, Check() on a body-carrying request
  PHP     the middleware mode of interop/probes/guardcore_body_probe.php:
          SuspiciousActivityCheck->check on a SimpleGuardRequest
  TS      initializeSecurityMiddleware's pipeline executed end to end
          (pipeline mode of interop/probes/guardcore_body_probe.test.ts)
  Rust    the tower GuardLayer service (middleware mode of interop/probes/
          guardcore_rs_probe.rs, throwaway cargo project)

Run:
    uv run python interop/middleware_spot_checks.py
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

from body_detect_vectors import (
    BOUNDARY,
    ECOSYSTEM_ROOT,
    GO_ROOT,
    PHP_ROOT,
    PROBES_DIR,
    REPORTS_DIR,
    RS_ROOT,
    TS_ROOT,
    _file,
    _multipart,
)

GUARD_CORE_ROOT = Path(__file__).resolve().parent.parent
INTEROP_DIR = Path(__file__).resolve().parent

ATTACK_ISLAND = bytes([0x85]) * 60 + b"$(cat /etc/passwd)" + bytes([0x87]) * 60
MPART_CT = f"multipart/form-data; boundary={BOUNDARY}"

CASES: list[dict[str, Any]] = [
    {
        "label": "island_smuggled_attack",
        "expectation": "BLOCK",
        "body": _multipart([_file("blob", "blob.bin", ATTACK_ISLAND)]),
        "content_type": MPART_CT,
        "query": {},
        "url_path": "/api",
    },
    {
        "label": "sap_innocent_query",
        "expectation": "PASS",
        "body": b"",
        "content_type": "application/x-www-form-urlencoded",
        "query": {"system": "SAP"},
        "url_path": "/api",
    },
]


async def _python_checks() -> dict[str, dict[str, Any]]:
    from unittest.mock import AsyncMock, MagicMock

    from guard_core.core.checks.implementations.suspicious_activity import (
        SuspiciousActivityCheck,
    )
    from guard_core.models import SecurityConfig

    config = SecurityConfig(auto_ban_threshold=100, auto_ban_duration=600)
    middleware = MagicMock()
    middleware.config = config
    middleware.suspicious_request_counts = {}
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(
        return_value=MagicMock(status_code=400)
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    check = SuspiciousActivityCheck(middleware)

    class _Request:
        def __init__(self, case: dict[str, Any]) -> None:
            self._body = case["body"]
            self.query_params: dict[str, str] = case["query"]
            self.headers: dict[str, str] = {
                "content-type": case["content_type"],
                "content-length": str(len(self._body)),
            }
            self.url_path = case["url_path"]
            self.url_full = f"http://example.com{case['url_path']}"
            self.url_scheme = "http"
            self.method = "POST"
            self.client_host = "203.0.113.9"
            self.state = type("S", (), {})()
            self.state.client_ip = "203.0.113.9"
            self.state.is_whitelisted = False
            self.state.route_config = None

        async def body(self) -> bytes:
            body: bytes = self._body
            return body

    results = {}
    for case in CASES:
        response = await check.check(_Request(case))  # type: ignore[arg-type]
        results[case["label"]] = {
            "blocked": response is not None,
            "status": getattr(response, "status_code", None),
        }
    return results


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


def _vectors_in() -> list[dict[str, Any]]:
    return [
        {
            "label": case["label"],
            "body_b64": base64.b64encode(case["body"]).decode("ascii"),
            "content_type": case["content_type"],
            "query": case["query"],
            "url_path": case["url_path"],
        }
        for case in CASES
    ]


def _go_checks() -> dict[str, dict[str, Any]]:
    input_path = REPORTS_DIR / "go_middleware_input.json"
    output_path = REPORTS_DIR / "go_middleware_output.json"
    input_path.write_text(json.dumps(_vectors_in(), indent=2))
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
                "INTEROP_MIDDLEWARE_INPUT=/interop/reports/go_middleware_input.json",
                "-e",
                "INTEROP_MIDDLEWARE_OUTPUT=/interop/reports/go_middleware_output.json",
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


def _php_checks() -> dict[str, dict[str, Any]]:
    input_path = REPORTS_DIR / "php_middleware_input.json"
    output_path = REPORTS_DIR / "php_middleware_output.json"
    input_path.write_text(json.dumps(_vectors_in(), indent=2))
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
            "INTEROP_MIDDLEWARE_INPUT=/interop/reports/php_middleware_input.json",
            "-e",
            "INTEROP_MIDDLEWARE_OUTPUT=/interop/reports/php_middleware_output.json",
            "php:8.3-cli",
            "php",
            "bin/guardcore_body_probe.php",
        ]
    )
    return {entry["label"]: entry for entry in json.loads(output_path.read_text())}


def _ts_checks() -> dict[str, dict[str, Any]]:
    input_path = REPORTS_DIR / "ts_middleware_input.json"
    output_path = REPORTS_DIR / "ts_middleware_output.json"
    input_path.write_text(json.dumps(_vectors_in(), indent=2))
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


def _rs_project() -> Path:
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


def _rs_checks(project: Path) -> dict[str, dict[str, Any]]:
    input_path = REPORTS_DIR / "rs_middleware_input.txt"
    output_path = REPORTS_DIR / "rs_middleware_output.txt"
    with input_path.open("w") as handle:
        for case in CASES:
            query_string = "&".join(
                f"{key}={value}" for key, value in case["query"].items()
            )
            uri = case["url_path"] + (f"?{query_string}" if query_string else "")
            handle.write(
                f"{case['label']}\t{uri}\t{case['content_type']}\t"
                f"{base64.b64encode(case['body']).decode('ascii')}\n"
            )
    env = dict(os.environ)
    env.update(
        {
            "GUARDCORE_RS_PROBE_MODE": "middleware",
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
        label, blocked, status = line.split("\t")
        results[label] = {
            "blocked": blocked == "1",
            "status": int(status),
        }
    return results


async def main() -> int:
    started = time.monotonic()
    print("python (real SuspiciousActivityCheck)...")
    py = await _python_checks()
    print("go (suspiciousActivityCheck.Check)...")
    go = _go_checks()
    print("php (SuspiciousActivityCheck->check)...")
    php = _php_checks()
    print("ts (initializeSecurityMiddleware pipeline)...")
    ts = _ts_checks()
    print("rust (tower GuardLayer service)...")
    rust = _rs_checks(_rs_project())

    table: list[dict[str, Any]] = []
    all_ok = True
    for case in CASES:
        label = case["label"]
        expectation = case["expectation"]
        row: dict[str, Any] = {
            "label": label,
            "expectation": expectation,
            "families": {},
        }
        ok = True
        for family, verdicts in (
            ("python", py),
            ("go", go),
            ("php", php),
            ("ts", ts),
            ("rust", rust),
        ):
            verdict = verdicts.get(label)
            blocked = bool(verdict and verdict.get("blocked"))
            matches = (expectation == "BLOCK") == blocked
            ok = ok and matches
            row["families"][family] = (
                f"{'BLOCKED' if blocked else 'PASSED'}"
                + (
                    f" ({verdict.get('status')})"
                    if verdict and verdict.get("status")
                    else ""
                )
                + ("" if matches else " MISMATCH")
            )
        all_ok = all_ok and ok
        row["ok"] = ok
        table.append(row)
        print(f"{'ok  ' if ok else 'FAIL'} {label} (expect {expectation})")

    report = {
        "cases": table,
        "elapsed_s": round(time.monotonic() - started, 2),
        "result": "GREEN" if all_ok else "RED",
    }
    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / "middleware_spot_checks.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False)
    )
    print("\nfamily | smuggled (must BLOCK) | sap (must PASS)")
    for case_label in ("island_smuggled_attack", "sap_innocent_query"):
        row = next(r for r in table if r["label"] == case_label)
        print(f"{case_label} (expect {row['expectation']})")
        for family, verdict in row["families"].items():
            print(f"    {family}: {verdict}")
    print("\nRESULT:", report["result"])
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
