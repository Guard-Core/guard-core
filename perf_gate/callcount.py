"""The gate's call counter: `sys.setprofile` on the measuring thread only.

`sys.setprofile` is per thread on every interpreter, so a function that runs on a
pool worker counts 0 here. (cProfile counts every thread from 3.12 on, so the
ledger tools match this counter on 3.10 only.) Worker-thread work is gated by
valgrind Ir instead. Frames in `skipped` are not counted, nor is anything they
call; `run_once` is not counted and neither are the C calls it makes itself.
"""

import collections
from typing import Any


class CallCounter:
    def __init__(self, skipped: set[Any], run_once: Any, root: str) -> None:
        self.skipped = skipped
        self.run_once = run_once
        self.root = root
        self.total = 0
        self.python = 0
        self.mine = 0
        self.depth = 0
        self.by_function: collections.Counter[str] | None = None

    def __call__(self, frame: Any, event: str, arg: Any) -> None:
        code = frame.f_code
        if event == "call":
            if code in self.skipped:
                self.depth += 1
            elif self.depth == 0 and code is not self.run_once:
                self.total += 1
                self.python += 1
                if self.by_function is not None:
                    name = f"{code.co_filename}:{code.co_firstlineno}:{code.co_name}"
                    self.by_function[name] += 1
                self.mine += code.co_filename.startswith(self.root)
        elif event == "return":
            if code in self.skipped:
                self.depth -= 1
        elif event == "c_call" and self.depth == 0 and code is not self.run_once:
            self.total += 1
