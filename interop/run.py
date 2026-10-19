import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

GUARD_CORE_ROOT = Path(__file__).resolve().parent.parent
INTEROP_DIR = Path(__file__).resolve().parent
REPORTS_DIR = INTEROP_DIR / "reports"
ECOSYSTEM_ROOT = GUARD_CORE_ROOT.parent.parent
GO_REPO = Path(
    os.environ.get(
        "GUARD_CORE_GO_REPO", str(ECOSYSTEM_ROOT / "Golang" / "guard-core-go")
    )
)
PHP_REPO = Path(
    os.environ.get(
        "GUARD_CORE_PHP_REPO", str(ECOSYSTEM_ROOT / "PHP" / "guard-core-php")
    )
)

REDIS_PORT = os.environ.get("GUARD_CORE_INTEROP_REDIS_PORT", "6379")
LEGACY_TREE = os.environ.get("GUARD_CORE_LEGACY_TREE", "")
LEGACY_PYTHON = os.environ.get("GUARD_CORE_LEGACY_PYTHON", "")

PREFIX = "guard_core_interop:"
RATE_WINDOW = 120
PY_HITS_A = 3
GO_HITS_B = 2
PHP_HITS_C = 2
EXEMPT_LIMIT = 2

EXPECTED_A_FIRST = PY_HITS_A + 1
EXPECTED_A_CROSSING = EXPECTED_A_FIRST + 1
EXPECTED_A_PHP = EXPECTED_A_CROSSING + 1
EXPECTED_A_VERIFY = EXPECTED_A_PHP + 1
EXPECTED_A_CROSS_PY = EXPECTED_A_VERIFY + 1
EXPECTED_B_GO = GO_HITS_B
EXPECTED_B_PHP = EXPECTED_B_GO + 1
EXPECTED_B_VERIFY = EXPECTED_B_PHP + 1
EXPECTED_C_VERIFY = PHP_HITS_C + 1

PHASES = [
    "py_write",
    "go_read_then_write",
    "php_read_then_write",
    "py_verify",
    "py_exempt_write",
    "go_exempt_read_then_write",
    "php_exempt_read_then_write",
    "py_exempt_verify",
]
CUSTOM_PATTERN_PHASES = [
    "py_custom_patterns_write",
    "v440_custom_patterns_read",
    "go_custom_patterns_read",
    "php_custom_patterns_read",
    "py_custom_patterns_verify",
]
PHASE_PARTICIPANT = {
    "py_custom_patterns_write": "python",
    "v440_custom_patterns_read": "python_v440",
    "go_custom_patterns_read": "go",
    "php_custom_patterns_read": "php",
    "py_custom_patterns_verify": "python",
    "py_write": "python",
    "go_read_then_write": "go",
    "php_read_then_write": "php",
    "py_verify": "python",
    "py_exempt_write": "python",
    "go_exempt_read_then_write": "go",
    "php_exempt_read_then_write": "php",
    "py_exempt_verify": "python",
}


def preflight(case: str) -> None:
    if case == "custom-patterns" and not (LEGACY_TREE and LEGACY_PYTHON):
        raise SystemExit(
            "custom-patterns needs GUARD_CORE_LEGACY_TREE (a guard-core v4.4.0 "
            "checkout) and GUARD_CORE_LEGACY_PYTHON (its own interpreter)"
        )
    if case == "all" and REDIS_PORT != "6379":
        raise SystemExit(
            "the rate-limit, ban, cloud and exempt phases run the Go and PHP "
            "runners, which connect to port 6379 inside their own repos; set "
            "GUARD_CORE_INTEROP_REDIS_PORT only with the custom-patterns case"
        )
    for command in (
        ["redis-cli", "-h", "127.0.0.1", "-p", REDIS_PORT, "ping"],
        ["docker", "info"],
        ["uv", "--version"],
    ):
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise SystemExit(
                f"preflight failed: {' '.join(command)} exited {result.returncode}: "
                f"{result.stderr.strip()}"
            )
    print("preflight: redis ping PONG, docker daemon up, uv available")


def flush_prefix() -> int:
    scanned = subprocess.run(
        [
            "redis-cli",
            "-p",
            REDIS_PORT,
            "--raw",
            "--scan",
            "--pattern",
            f"{PREFIX}*",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    if not scanned:
        return 0
    subprocess.run(
        ["redis-cli", "-p", REDIS_PORT, "del", *scanned],
        capture_output=True,
        text=True,
        check=True,
    )
    return len(scanned)


def participant_command(
    participant: str, phase: str, report_path: Path, incoming: dict[str, Any]
) -> list[str]:
    if participant == "python":
        return [
            "uv",
            "run",
            "--project",
            str(GUARD_CORE_ROOT),
            "python",
            str(INTEROP_DIR / "py_participant.py"),
        ]
    if participant == "python_v440":
        return [LEGACY_PYTHON, str(INTEROP_DIR / "v440_participant.py")]
    if participant == "go" and phase == "go_custom_patterns_read":
        overlay = REPORTS_DIR / "go_overlay.json"
        overlay.write_text(
            json.dumps(
                {
                    "Replace": {
                        "/app/guardcore/mixedfleet_custom_patterns_probe_test.go": (
                            "/interop/probes/mixedfleet_custom_patterns_probe_test.go"
                        )
                    }
                }
            )
        )
        return [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{GO_REPO}:/app:ro",
            "-v",
            f"{INTEROP_DIR}:/interop",
            "-w",
            "/app",
            "-e",
            "REDIS_HOST=host.docker.internal",
            "-e",
            f"REDIS_PORT={REDIS_PORT}",
            "-e",
            f"INTEROP_INPUT={json.dumps(incoming)}",
            "-e",
            f"INTEROP_REPORT_FILE=/interop/reports/{report_path.name}",
            "-e",
            "GOCACHE=/tmp/gocache",
            "-e",
            "GOFLAGS=-mod=readonly",
            "golang:1.25-alpine",
            "go",
            "test",
            "-overlay",
            "/interop/reports/go_overlay.json",
            "-v",
            "-run",
            "^TestMixedFleetCustomPatternsProbe$",
            "-count=1",
            "./guardcore",
        ]
    if participant == "php" and phase == "php_custom_patterns_read":
        return [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{PHP_REPO}:/app:ro",
            "-v",
            f"{INTEROP_DIR}:/interop",
            "-w",
            "/app",
            "-e",
            "REDIS_HOST=host.docker.internal",
            "-e",
            f"REDIS_PORT={REDIS_PORT}",
            "-e",
            f"INTEROP_INPUT={json.dumps(incoming)}",
            "-e",
            f"INTEROP_REPORT_FILE=/interop/reports/{report_path.name}",
            "php:8.3-cli",
            "php",
            "/interop/probes/mixedfleet_custom_patterns_probe.php",
        ]
    if participant == "go":
        return [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{GO_REPO}:/app",
            "-v",
            f"{INTEROP_DIR}:/interop",
            "-w",
            "/app",
            "-e",
            "REDIS_HOST=host.docker.internal",
            "-e",
            f"INTEROP_PHASE={phase}",
            "-e",
            f"INTEROP_INPUT={json.dumps(incoming)}",
            "-e",
            f"INTEROP_REPORT_FILE=/interop/reports/{report_path.name}",
            "-e",
            "GOCACHE=/tmp/gocache",
            "golang:1.25-alpine",
            "go",
            "test",
            "-tags",
            "interop",
            "-v",
            "-run",
            "^TestInteropRunner$",
            "-count=1",
            "./guardcore",
        ]
    if participant == "php":
        return [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{PHP_REPO}:/app",
            "-v",
            f"{INTEROP_DIR}:/interop",
            "-w",
            "/app",
            "-e",
            "REDIS_HOST=host.docker.internal",
            "-e",
            f"INTEROP_PHASE={phase}",
            "-e",
            f"INTEROP_INPUT={json.dumps(incoming)}",
            "-e",
            f"INTEROP_REPORT_FILE=/interop/reports/{report_path.name}",
            "php:8.3-cli",
            "php",
            "bin/interop.php",
        ]
    raise SystemExit(f"unknown participant {participant!r}")


def participant_env(
    participant: str, phase: str, incoming: dict[str, Any], report_path: Path
) -> dict[str, str]:
    env = dict(os.environ)
    env["INTEROP_PHASE"] = phase
    env["INTEROP_INPUT"] = json.dumps(incoming)
    env["INTEROP_REPORT_FILE"] = str(report_path)
    env["REDIS_PORT"] = REDIS_PORT
    if participant == "python":
        env["REDIS_HOST"] = "127.0.0.1"
    if participant == "python_v440":
        env["PYTHONPATH"] = LEGACY_TREE
        env["IPINFO_TOKEN"] = "x"
    return env


def run_phase(phase: str, incoming: dict[str, Any]) -> dict[str, Any]:
    participant = PHASE_PARTICIPANT[phase]
    report_path = REPORTS_DIR / f"{participant}_{phase}.json"
    command = participant_command(participant, phase, report_path, incoming)
    print(f"\n=== phase {phase} ({participant}) ===")
    print(f"$ {' '.join(command)}")
    started = time.monotonic()
    result = subprocess.run(
        command,
        env=participant_env(participant, phase, incoming, report_path),
        capture_output=True,
        text=True,
        timeout=900,
    )
    elapsed = time.monotonic() - started
    print(result.stdout.rstrip())
    if result.stderr.strip():
        print(f"[stderr] {result.stderr.strip()[:2000]}")
    if result.returncode != 0:
        raise SystemExit(
            f"phase {phase} ({participant}) exited {result.returncode} "
            f"after {elapsed:.1f}s"
        )
    if not report_path.exists():
        raise SystemExit(f"phase {phase} did not write {report_path}")
    report: dict[str, Any] = json.loads(report_path.read_text())
    print(
        f"phase {phase}: {report['passed']}/{report['passed'] + report['failed']} "
        f"green in {elapsed:.1f}s"
    )
    return report


EXPECTED = {
    "expected_a_first": EXPECTED_A_FIRST,
    "expected_a_crossing": EXPECTED_A_CROSSING,
    "expected_b_second": EXPECTED_B_GO,
    "expected_a_blocked": EXPECTED_A_PHP,
    "expected_b_blocked": EXPECTED_B_PHP,
    "a_obs": EXPECTED_A_VERIFY,
    "b_obs": EXPECTED_B_VERIFY,
    "c_obs": EXPECTED_C_VERIFY,
    "expected_exempt_limit": EXEMPT_LIMIT,
}


def build_incoming(artifacts: dict[str, str]) -> dict[str, Any]:
    incoming: dict[str, Any] = dict(EXPECTED)
    incoming.update(artifacts)
    return incoming


def verify_ledger(phase: str, report: dict[str, Any]) -> None:
    artifacts = report.get("artifacts", {})
    required = {
        "py_write": ["py_ban_expiry_raw", "legacy_value_raw", "aws_payload_raw"],
        "go_read_then_write": ["go_ban_expiry_raw", "gcp_payload_raw"],
        "php_read_then_write": ["php_ban_expiry_raw", "azure_payload_raw"],
        "py_custom_patterns_write": [
            f"{scope}_custom_list_raw"
            for scope in ("mf_v440", "mf_go", "mf_php", "mf_py")
        ],
        "v440_custom_patterns_read": ["v440_patterns", "v440_flagged"],
        "go_custom_patterns_read": ["go_patterns"],
        "php_custom_patterns_read": ["php_patterns"],
        "py_exempt_write": ["exempt_n_after_py", "exempt_limit"],
        "go_exempt_read_then_write": ["exempt_n_after_go"],
        "php_exempt_read_then_write": ["exempt_n_after_php"],
    }.get(phase, [])
    missing = [key for key in required if key not in artifacts or artifacts[key] == ""]
    if missing:
        raise SystemExit(f"phase {phase} artifacts missing: {missing}")


def aggregate_matrix(
    reports: list[dict[str, Any]],
) -> dict[str, dict[str, dict[str, int]]]:
    matrix: dict[str, dict[str, dict[str, int]]] = {}
    for report in reports:
        for check in report.get("checks", []):
            row = matrix.setdefault(check["scenario"], {})
            cell = row.setdefault(check["direction"], {"passed": 0, "failed": 0})
            cell["passed" if check["passed"] else "failed"] += 1
    return matrix


def print_matrix(matrix: dict[str, dict[str, dict[str, int]]]) -> None:
    directions = sorted({d for row in matrix.values() for d in row})
    scenarios = sorted(matrix)
    width = max([len("scenario")] + [len(s) for s in scenarios]) + 2
    col_width = max([len(d) for d in directions] + [10]) + 2
    header = "scenario".ljust(width) + "".join(d.ljust(col_width) for d in directions)
    print("\n" + "=" * len(header))
    print("INTEROP MATRIX (scenario x direction, passed/failed)")
    print(header)
    print("-" * len(header))
    for scenario in scenarios:
        row = matrix[scenario]
        cells = []
        for direction in directions:
            cell = row.get(direction)
            if cell is None:
                cells.append("-".ljust(col_width))
            else:
                cells.append(f"{cell['passed']}/{cell['failed']}".ljust(col_width))
        print(scenario.ljust(width) + "".join(cells))
    print("-" * len(header))


def main(case: str = "all") -> int:
    preflight(case)
    phases = CUSTOM_PATTERN_PHASES if case == "custom-patterns" else PHASES
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    removed = flush_prefix()
    print(f"pre-run flush: removed {removed} keys under {PREFIX}*")

    artifacts: dict[str, str] = {}
    reports: list[dict[str, Any]] = []
    started = time.monotonic()
    for phase in phases:
        incoming = (
            {**artifacts, "prefix_root": PREFIX}
            if case == "custom-patterns"
            else build_incoming(artifacts)
        )
        report = run_phase(phase, incoming)
        verify_ledger(phase, report)
        reports.append(report)
        artifacts.update(report.get("artifacts", {}))
    elapsed = time.monotonic() - started

    removed = flush_prefix()
    print(f"\npost-run flush: removed {removed} keys under {PREFIX}*")

    matrix = aggregate_matrix(reports)
    totals = {
        "passed": sum(r["passed"] for r in reports),
        "failed": sum(r["failed"] for r in reports),
    }
    print_matrix(matrix)
    print(
        f"\ntotal: {totals['passed']}/{totals['passed'] + totals['failed']} "
        f"checks green across {len(reports)} phases in {elapsed:.1f}s"
    )

    last_run = {
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "elapsed_seconds": round(elapsed, 1),
        "redis_prefix": PREFIX,
        "phases": [
            {
                "phase": r["phase"],
                "participant": r["participant"],
                "passed": r["passed"],
                "failed": r["failed"],
                "checks": r["checks"],
            }
            for r in reports
        ],
        "totals": totals,
        "matrix": matrix,
    }
    last_run_name = (
        "last_run_custom_patterns.json"
        if case == "custom-patterns"
        else "last_run.json"
    )
    last_run_path = INTEROP_DIR / last_run_name
    last_run_path.write_text(json.dumps(last_run, indent=2))
    print(f"wrote {last_run_path}")

    if totals["failed"] > 0:
        print("RESULT: RED")
        return 1
    print("RESULT: GREEN")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["custom-patterns"]):
        raise SystemExit("usage: run.py [custom-patterns]")
    raise SystemExit(main("custom-patterns" if sys.argv[1:] else "all"))
