import functools
import http.server
import json
import subprocess
import sys
import threading
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.live_smoke import fetch_example_app
from tests.live_smoke.test_fetch_example_app import _git_repo_with_example

STACK = Path(fetch_example_app.__file__).resolve().parent / "stack"


def _wheel(directory: Path, name: str, version: str, extra_metadata: str = "") -> Path:
    path = directory / f"{name}-{version}-py3-none-any.whl"
    dist_info = f"{name}-{version}.dist-info"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            f"{dist_info}/METADATA",
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
            f"{extra_metadata}",
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\n"
            "Tag: py3-none-any\n",
        )
        archive.writestr(f"{dist_info}/RECORD", "")
    return path


@pytest.fixture
def index(tmp_path: Path) -> Iterator[str]:
    """A local PyPI-shaped index: fakeguard 1.0.0 uploaded in 2025, 2.0.0 in 2026-06."""
    served = tmp_path / "served"
    served.mkdir()
    uploads = {"1.0.0": "2025-12-01T00:00:00Z", "2.0.0": "2026-06-01T00:00:00Z"}
    for version in uploads:
        _wheel(served, "fakeguard", version)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.rstrip("/") != "/simple/fakeguard":
                return super().do_GET()
            base = f"http://127.0.0.1:{self.server.server_address[1]}"
            body = json.dumps(
                {
                    "meta": {"api-version": "1.1"},
                    "name": "fakeguard",
                    "files": [
                        {
                            "filename": f"fakeguard-{version}-py3-none-any.whl",
                            "url": f"{base}/fakeguard-{version}-py3-none-any.whl",
                            "hashes": {},
                            "upload-time": stamp,
                        }
                        for version, stamp in uploads.items()
                    ],
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.pypi.simple.v1+json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), functools.partial(Handler, directory=str(served))
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}/simple"
    server.shutdown()
    server.server_close()


def _dry_run(
    *args: str, python: str = sys.executable
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["uv", "pip", "install", "--dry-run", "--python", python, *args],
        capture_output=True,
        text=True,
        check=True,
    )


def test_a_baseline_installs_what_existed_on_its_tag_date(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, index: str
) -> None:
    monkeypatch.setenv("GIT_COMMITTER_DATE", "2026-01-15T12:00:00+01:00")
    repo = _git_repo_with_example(tmp_path / "origin", "v8.0.2")
    stack = tmp_path / "stack"
    (stack / "wheels").mkdir(parents=True)
    monkeypatch.setattr(fetch_example_app, "REPO_URL", str(repo))
    monkeypatch.setattr(fetch_example_app, "STACK_DIR", stack)
    monkeypatch.setattr(fetch_example_app, "DEST", stack / "app")
    monkeypatch.setattr(fetch_example_app, "build_wheel", lambda _: None)
    monkeypatch.delenv("LIVE_SMOKE_FASTAPI_GUARD_LOCAL", raising=False)
    monkeypatch.setenv("LIVE_SMOKE_BASELINE", "v8.0.2")

    fetch_example_app.fetch()

    cutoff = (stack / "wheels" / "baseline-date.txt").read_text().strip()
    assert cutoff == "2026-01-15T12:00:00+01:00"
    assert (
        "fakeguard==1.0.0"
        in _dry_run("--index-url", index, "--exclude-newer", cutoff, "fakeguard").stderr
    )
    assert "fakeguard==2.0.0" in _dry_run("--index-url", index, "fakeguard").stderr


def test_a_checkout_run_leaves_no_baseline_date(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = tmp_path / "stack"
    (stack / "wheels").mkdir(parents=True)
    (stack / "wheels" / "baseline-date.txt").write_text("2020-01-01T00:00:00+00:00\n")
    repo = _git_repo_with_example(tmp_path / "origin", "v9.0.0")
    monkeypatch.setattr(fetch_example_app, "STACK_DIR", stack)
    monkeypatch.setattr(fetch_example_app, "DEST", stack / "app")
    monkeypatch.setattr(fetch_example_app, "build_wheel", lambda _: None)
    monkeypatch.delenv("LIVE_SMOKE_BASELINE", raising=False)

    fetch_example_app.fetch(local_repo=str(repo))

    assert not (stack / "wheels" / "baseline-date.txt").exists()


def test_the_baseline_wheel_install_brings_its_declared_extras(tmp_path: Path) -> None:
    wheel = _wheel(
        tmp_path,
        "v9shaped",
        "9.0.0",
        "Provides-Extra: redis\nRequires-Dist: redis; extra == 'redis'\n"
        "Provides-Extra: geo\nRequires-Dist: maxminddb; extra == 'geo'\n",
    )
    dockerfile = (STACK / "Dockerfile").read_text()
    assert '"$(ls /wheels/fastapi_guard-*.whl)[redis,geo,cloud]"' in dockerfile
    baseline_branch = dockerfile.split("if [ -f /wheels/baseline-date.txt ]")[1].split(
        "else"
    )[0]
    assert '--exclude-newer "$(cat /wheels/baseline-date.txt)"' in baseline_branch
    assert "redis guard-agent" in baseline_branch

    subprocess.run(["uv", "venv", "-q", str(tmp_path / "venv")], check=True)

    result = _dry_run(
        f"{wheel}[redis,geo,cloud]", python=str(tmp_path / "venv" / "bin" / "python")
    )

    assert " + redis==" in result.stderr
    assert " + maxminddb==" in result.stderr
    assert "does not have an extra named `cloud`" in result.stderr


def test_a_server_package_installed_with_the_baseline_wheel_respects_the_cutoff(
    tmp_path: Path, index: str
) -> None:
    wheel = _wheel(tmp_path, "v8shaped", "8.0.2", "Requires-Dist: fakeguard\n")
    subprocess.run(["uv", "venv", "-q", str(tmp_path / "venv")], check=True)
    python = str(tmp_path / "venv" / "bin" / "python")

    one_resolution = _dry_run(
        "--index-url",
        index,
        "--exclude-newer",
        "2026-01-15T12:00:00+01:00",
        "fakeguard",
        str(wheel),
        python=python,
    )

    assert " + fakeguard==1.0.0" in one_resolution.stderr
