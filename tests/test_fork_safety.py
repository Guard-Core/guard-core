import os
import subprocess
import sys
from pathlib import Path

import pytest

import guard_core

REPO_ROOT = Path(guard_core.__file__).resolve().parent.parent

# A real fork: the parent scans (so its shared regex pool has live workers), the child
# is forked after a pause and scans the same texts. Run in a fresh interpreter so the
# test process, with its own threads and loop, is never forked.
_SCRIPT = """
import asyncio, inspect, os, sys, time, warnings, logging
warnings.simplefilter("ignore"); logging.disable(logging.CRITICAL)
tree = sys.argv[1]
if tree == "sync":
    from guard_core.sync.utils import detect_penetration_attempt
    from guard_core.sync.handlers.suspatterns_handler import active_sus_patterns
    from guard_core.sync.detection_engine import compiler
else:
    from guard_core.utils import detect_penetration_attempt
    from guard_core.handlers.suspatterns_handler import active_sus_patterns
    from guard_core.detection_engine import compiler
from guard_core.models import SecurityConfig

class State: pass
class Request:
    def __init__(self, text):
        self._state = State(); self.query_params = {"q": text}
        self.headers = {"user-agent": "probe/1.0", "accept": "*/*"}
    url_path = "/p"; url_scheme = "https"; url_full = "https://t/p"
    method = "GET"; client_host = "203.0.113.9"
    def url_replace_scheme(self, scheme):
        return self.url_full.replace("https", scheme, 1)
    if tree == "sync":
        def body(self): return b""
    else:
        async def body(self): return b""
    @property
    def state(self): return self._state
    @property
    def scope(self): return {}

def call(function, *arguments):
    result = function(*arguments)
    return asyncio.run(result) if inspect.isawaitable(result) else result

config = SecurityConfig(enable_redis=False)

def verdict(text):
    result = call(detect_penetration_attempt, Request(text), config)
    return (result.is_threat, result.body_read_error, sorted(result.threat_categories))

call(detect_penetration_attempt, Request("warm"), config)
call(active_sus_patterns().add_pattern, r"foo\\d+bar", True)
texts = ("hello world", "zz-foo12bar-zz", "x' UNION SELECT password FROM users--")
parent = [verdict(text) for text in texts]
time.sleep(0.3)
reader, writer = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(reader)
    started = time.monotonic()
    child = [verdict(text) for text in texts]
    os.write(writer, repr((child, time.monotonic() - started)).encode())
    os._exit(0)
os.close(writer)
child, seconds = eval(os.read(reader, 65536).decode())
os.waitpid(pid, 0)
print(repr((parent, child, seconds, compiler._shared_executor is not None)))
"""


def _fork_run(tree: str) -> tuple[list[tuple], list[tuple], float, bool]:
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}"
    result = subprocess.run(
        [sys.executable, "-W", "ignore", "-c", _SCRIPT, tree],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=True,
    )
    return eval(result.stdout.strip().splitlines()[-1])


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
@pytest.mark.parametrize("tree", ["async", "sync"])
def test_the_first_scan_in_a_forked_child_gives_the_parents_verdict(tree: str) -> None:
    parent, child, seconds, parent_pool_alive = _fork_run(tree)

    assert parent_pool_alive
    assert child == parent
    assert all(error is None for _threat, error, _categories in child)
    assert child[1][0] is True
    assert seconds < 4
