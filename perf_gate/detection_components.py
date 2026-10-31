"""CPU and memory of the detection engine's components, the numbers the docs quote.

usage: PYTHONPATH=<tree with guard_core/> python -m perf_gate.detection_components
    latency|tuning|memory [--rounds N] [--tree async|sync]
`latency` prints one JSON line per component and content size: CPU microseconds
(process time, so the regex worker threads count) per call, the median, p99 and
maximum over every call, and the A/A spread: each round measures the same
component twice back to back, and the two medians are reported next to each
other. `tuning` times the advice the performance pages give (capture groups,
the semantic threshold, the content length) with every arm interleaved and one
arm repeated as the A/A. `memory` prints one JSON line per step with the bytes
tracemalloc holds and the resident set size of the process after the step.
`--tree sync` runs the same measurements on the `guard_core.sync` tree that the
Flask and Django adapters use.
"""

import argparse
import asyncio
import gc
import importlib
import inspect
import json
import logging
import os
import platform
import re
import statistics
import subprocess
import sys
import time
import tracemalloc
from collections.abc import Callable, Mapping
from functools import partial
from typing import Any

TYPICAL_CHARS = 200
BENIGN = (
    "Quarterly report for the finance team: revenue grew while churn fell, "
    "see the dashboard and the attached notes. "
)
ATTACK = "1' OR '1'='1' UNION SELECT username, password FROM users--"
CLIENT_IP = "203.0.113.9"


def benign_text(size: int) -> str:
    return (BENIGN * (size // len(BENIGN) + 1))[:size]


def attack_text(size: int) -> str:
    return (ATTACK + " " + benign_text(size))[:size]


def cpu_samples(call: Callable[[], object], calls: int) -> list[float]:
    samples: list[float] = []
    gc.collect()
    for _ in range(calls):
        start = time.process_time()
        call()
        samples.append((time.process_time() - start) * 1_000_000)
    return samples


def batch_of(call: Callable[[], object], size: int) -> Callable[[], None]:
    def run() -> None:
        for _ in range(size):
            call()

    return run


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(fraction * len(ordered)))]


def summarize(name: str, arms: list[list[float]]) -> dict[str, Any]:
    every = [value for arm in arms for value in arm]
    return {
        "component": name,
        "calls": len(every),
        "median_us": round(statistics.median(every), 2),
        "p99_us": round(percentile(every, 0.99), 2),
        "max_us": round(max(every), 2),
        "arm_medians_us": [round(statistics.median(arm), 2) for arm in arms],
    }


class RequestFields:
    """The smallest request the engine's detection entry point accepts."""

    url_path = "/probe"
    url_scheme = "https"
    url_full = "https://test/probe"
    method = "GET"
    client_host = CLIENT_IP

    def __init__(self, text: str) -> None:
        self._state = type("State", (), {})()
        self.query_params = {"q": text}
        self.headers = {"user-agent": "probe/1.0", "accept": "*/*"}

    def url_replace_scheme(self, scheme: str) -> str:
        return self.url_full.replace("https", scheme, 1)

    @property
    def state(self) -> object:
        return self._state

    @property
    def scope(self) -> dict[str, object]:
        return {}


class AsyncRequest(RequestFields):
    async def body(self) -> bytes:
        return b""


class SyncRequest(RequestFields):
    def body(self) -> bytes:
        return b""


class Engine:
    """One engine tree (async `guard_core` or sync `guard_core.sync`) and its loop."""

    def __init__(self, tree: str) -> None:
        base = "guard_core.sync" if tree == "sync" else "guard_core"
        self.tree = tree
        self.loop = asyncio.new_event_loop()
        self.request_class: type[RequestFields] = (
            SyncRequest if tree == "sync" else AsyncRequest
        )
        detection = importlib.import_module(f"{base}.detection_engine")
        self.preprocessor_class = detection.ContentPreprocessor
        self.analyzer_class = detection.SemanticAnalyzer
        utils = importlib.import_module(f"{base}.utils")
        self.detect = utils.detect_penetration_attempt
        patterns = importlib.import_module(f"{base}.handlers.suspatterns_handler")
        self.handler = patterns.sus_patterns_handler
        self.manager_for = patterns.sus_patterns_manager_for
        self.config_class = importlib.import_module("guard_core.models").SecurityConfig

    def resolve(self, value: object) -> Any:
        if inspect.isawaitable(value):
            return self.loop.run_until_complete(value)
        return value

    def detect_once(self, config: Any, text: str) -> object:
        return self.resolve(self.detect(self.request_class(text), config))

    def default_rows(self) -> list[re.Pattern[str]]:
        compiled = self.resolve(self.handler.get_default_compiled_patterns())
        return [row[0] for row in compiled]

    def monitor(self, config: Any) -> Any:
        monitor = self.manager_for(config)._detection_state.performance_monitor
        assert monitor is not None
        return monitor


def pattern_summary(
    engine: Engine, text: str, repeats: int, batch: int
) -> dict[str, Any]:
    per_pattern = []
    for pattern in engine.default_rows():
        samples = cpu_samples(batch_of(partial(pattern.search, text), batch), repeats)
        per_pattern.append(statistics.median(samples))
    return {
        "component": "pattern_search_per_default_pattern",
        "patterns": len(per_pattern),
        "chars": len(text),
        "median_us": round(statistics.median(per_pattern) / batch, 3),
        "p99_us": round(percentile(per_pattern, 0.99) / batch, 3),
        "max_us": round(max(per_pattern) / batch, 3),
    }


def component_steps(
    engine: Engine, text: str, preprocessor: Any, analyzer: Any, config: Any
) -> dict[str, Callable[[], object]]:
    return {
        "preprocess": lambda: engine.resolve(preprocessor.preprocess(text)),
        "semantic_analyze": partial(analyzer.analyze, text),
        "detect_penetration_attempt": partial(engine.detect_once, config, text),
    }


def latency(engine: Engine, rounds: int) -> None:
    config = engine.config_class()
    preprocessor = engine.preprocessor_class(
        max_content_length=config.detection_max_content_length,
        preserve_attack_patterns=config.detection_preserve_attack_patterns,
    )
    analyzer = engine.analyzer_class()
    texts = {
        "typical_benign": benign_text(TYPICAL_CHARS),
        "typical_attack": attack_text(TYPICAL_CHARS),
        "max_benign": benign_text(config.detection_max_content_length),
        "max_attack": attack_text(config.detection_max_content_length),
    }
    calls = {"typical_benign": 400, "typical_attack": 400, "max_benign": 100}
    calls["max_attack"] = 100
    print(
        json.dumps(
            {
                "tree": engine.tree,
                "python": platform.python_version(),
                "machine": platform.machine(),
                "max_content_length": config.detection_max_content_length,
                "loadavg": os.getloadavg()[0],
            }
        )
    )
    for label, text in texts.items():
        steps = component_steps(engine, text, preprocessor, analyzer, config)
        for name, step in steps.items():
            step()
            arms: list[list[float]] = [[], []]
            for _ in range(rounds):
                for arm in arms:
                    arm.extend(cpu_samples(step, calls[label]))
            print(json.dumps({"content": label, **summarize(name, arms)}))
    summary = engine.resolve(engine.monitor(config).get_summary_stats())
    print(json.dumps({"component": "engine_monitor_summary", **summary}))
    print(json.dumps(pattern_summary(engine, texts["typical_benign"], 30, 100)))
    print(json.dumps(pattern_summary(engine, texts["max_benign"], 10, 5)))


def resident_kib() -> int:
    out = subprocess.run(
        ["ps", "-o", "rss=", "-p", str(os.getpid())],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return int(out.strip())


def interleaved(
    arms: Mapping[str, Callable[[], object]], rounds: int, calls: int
) -> dict[str, list[float]]:
    samples: dict[str, list[float]] = {name: [] for name in arms}
    for step in arms.values():
        step()
    for index in range(rounds):
        names = list(arms)
        names = names[index % len(names) :] + names[: index % len(names)]
        for name in names:
            samples[name].extend(cpu_samples(arms[name], calls))
    return samples


def ratios_line(label: str, samples: dict[str, list[float]]) -> dict[str, Any]:
    first = next(iter(samples))
    base = statistics.median(samples[first])
    return {
        "tuning": label,
        "calls_per_arm": len(samples[first]),
        "median_us": {n: round(statistics.median(v), 2) for n, v in samples.items()},
        "ratio_to_first": {
            n: round(statistics.median(v) / base, 3) for n, v in samples.items()
        },
    }


def detect_arms(
    engine: Engine, configs: Mapping[str, Any], text: str
) -> dict[str, Callable[[], object]]:
    return {
        name: partial(engine.detect_once, config, text)
        for name, config in configs.items()
    }


def tuning(engine: Engine, rounds: int) -> None:
    capture = re.compile(r"(SELECT|INSERT|UPDATE).*(FROM|INTO)")
    plain = re.compile(r"(?:SELECT|INSERT|UPDATE).*(?:FROM|INTO)")
    for size in (TYPICAL_CHARS, 10000):
        text = benign_text(size)
        arms: dict[str, Callable[[], object]] = {
            "capture_groups": batch_of(partial(capture.search, text), 200),
            "non_capturing_groups": batch_of(partial(plain.search, text), 200),
            "capture_groups_again": batch_of(partial(capture.search, text), 200),
        }
        samples = interleaved(arms, rounds, 20)
        print(json.dumps(ratios_line(f"regex_groups_{size}_chars", samples)))
    for label, text in (
        ("benign", benign_text(TYPICAL_CHARS)),
        ("attack", attack_text(TYPICAL_CHARS)),
    ):
        thresholds = {
            "threshold_0.7": 0.7,
            "threshold_0.8": 0.8,
            "threshold_0.6": 0.6,
            "threshold_0.7_again": 0.7,
        }
        configs = {
            name: engine.config_class(detection_semantic_threshold=value)
            for name, value in thresholds.items()
        }
        arms = detect_arms(engine, configs, text)
        samples = interleaved(arms, rounds, 100)
        print(json.dumps(ratios_line(f"semantic_threshold_{label}", samples)))
    lengths = {
        "max_content_10000": 10000,
        "max_content_2000": 2000,
        "max_content_10000_again": 10000,
    }
    configs = {
        name: engine.config_class(detection_max_content_length=value)
        for name, value in lengths.items()
    }
    arms = detect_arms(engine, configs, benign_text(10000))
    samples = interleaved(arms, rounds, 40)
    print(json.dumps(ratios_line("max_content_length_on_10000_chars", samples)))


def memory_step(step: str, traced_before: int, rss_before: int) -> int:
    gc.collect()
    traced, _ = tracemalloc.get_traced_memory()
    rss = resident_kib()
    print(
        json.dumps(
            {
                "step": step,
                "traced_delta_kib": round((traced - traced_before) / 1024, 1),
                "traced_total_kib": round(traced / 1024, 1),
                "rss_delta_kib": rss - rss_before,
                "rss_kib": rss,
            }
        )
    )
    return traced


def memory(tree: str) -> None:
    tracemalloc.start()
    rss = resident_kib()
    traced = memory_step("start", 0, rss)
    engine = Engine(tree)
    traced = memory_step("import guard_core", traced, rss)
    rss = resident_kib()
    config = engine.config_class()
    traced = memory_step("the first SecurityConfig()", traced, rss)
    rss = resident_kib()
    engine.manager_for(config, bind=True)
    traced = memory_step(
        "its detection state (compiler, preprocessor, ...)", traced, rss
    )
    rss = resident_kib()
    sources = engine.resolve(engine.handler.get_default_patterns())
    source_bytes = sum(sys.getsizeof(source) for source in sources)
    print(json.dumps({"step": "default pattern sources", "bytes": source_bytes}))
    engine.default_rows()
    traced = memory_step("default compiled patterns", traced, rss)
    rss = resident_kib()
    engine.detect_once(config, BENIGN)
    traced = memory_step("first detection", traced, rss)
    rss = resident_kib()
    monitor = engine.monitor(config)
    history = config.detection_monitor_history_size
    for index in range(history):
        record = monitor.record_metric(f"pattern-{index % 100}", 0.001, 100, False)
        engine.resolve(record)
    traced = memory_step(f"performance history ({history} metrics)", traced, rss)
    rss = resident_kib()
    second = engine.config_class(redis_prefix="second_app:")
    engine.manager_for(second, bind=True)
    memory_step("a second SecurityConfig and its detection state", traced, rss)


def main(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("what", choices=["latency", "memory", "tuning"])
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--tree", choices=["async", "sync"], default="async")
    args = parser.parse_args(argv)
    logging.disable(logging.CRITICAL)
    if args.what == "memory":
        memory(args.tree)
    elif args.what == "tuning":
        tuning(Engine(args.tree), args.rounds)
    else:
        latency(Engine(args.tree), args.rounds)


if __name__ == "__main__":
    main(sys.argv[1:])
