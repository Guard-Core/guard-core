import sys
import threading
import time

from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

_RACE_DURATION_SECONDS = 1.5
_PAYLOAD = "A" * 1400 + " UNION SELECT 1"


class _RaceConfig:
    def __init__(
        self, max_length: int, preserve: bool, threshold: float, inspect_bytes: int
    ) -> None:
        self.detection_compiler_timeout = 1.0
        self.detection_max_tracked_patterns = 500
        self.detection_max_content_length = max_length
        self.detection_max_body_inspect_bytes = inspect_bytes
        self.detection_preserve_attack_patterns = preserve
        self.detection_anomaly_threshold = 3.0
        self.detection_slow_pattern_threshold = 0.1
        self.detection_monitor_history_size = 1000
        self.detection_anomaly_emission_cooldown = 60
        self.detection_min_samples_for_anomaly = 30
        self.detection_semantic_threshold = 1.5
        self.detection_threat_score_threshold = threshold


# Config A truncates the payload (blind slice, preserve_attack_patterns=False)
# below the "UNION SELECT" substring at position 1401 -- truncate_safely's
# single memory bound is detection_max_body_inspect_bytes, not
# detection_max_content_length, so THAT is what must be small here -- so the
# sqli pattern never matches: anomaly=0.0, and 0.0 >= A's own threshold (0.5)
# is False.
_CONFIG_A = _RaceConfig(
    max_length=1000, preserve=False, threshold=0.5, inspect_bytes=1000
)
# Config B keeps the whole payload (inspect_bytes=262144 > len(payload)), so
# "UNION SELECT" matches: anomaly=1.0, but 1.0 >= B's own threshold (1.5) is
# also False.
_CONFIG_B = _RaceConfig(
    max_length=2000, preserve=True, threshold=1.5, inspect_bytes=262144
)

# Neither pure A nor pure B can ever report is_threat=True for this payload.
# The only way to get True is a torn read that combines B's preprocessor
# (which preserves the match) with A's threshold (low enough to fire on it) --
# exactly the "compiler set but a preprocessor not yet, or thresholds from two
# different configs" failure mode configure() must never allow detect() to see.


def test_configure_is_atomic_under_concurrent_detect() -> None:
    """A background thread reconfiguring detection (as HandlerInitializer does
    under lazy_init) must never let a concurrent detect() call observe a mix
    of two configuration generations, and configure()/detect() must never
    raise while racing each other.
    """
    SusPatternsManager._instance = None
    manager = SusPatternsManager(_CONFIG_A)

    stop = threading.Event()
    errors: list[BaseException] = []
    false_positives: list[dict] = []

    def configure_loop() -> None:
        try:
            while not stop.is_set():
                manager.configure(_CONFIG_A)
                manager.configure(_CONFIG_B)
        except BaseException as exc:
            errors.append(exc)

    original_switch_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-5)
    configurer = threading.Thread(target=configure_loop, daemon=True)
    configurer.start()
    try:
        end = time.monotonic() + _RACE_DURATION_SECONDS
        while time.monotonic() < end:
            result = manager.detect(
                content=_PAYLOAD,
                ip_address="203.0.113.9",
                context="request_body",
                enabled_categories={"sqli"},
            )
            if result["is_threat"]:
                false_positives.append(result)
    finally:
        stop.set()
        configurer.join(timeout=5)
        sys.setswitchinterval(original_switch_interval)

    assert not configurer.is_alive(), "configure() thread did not finish in time"
    assert errors == [], f"configure()/detect() raised while racing: {errors!r}"
    assert false_positives == [], (
        "detect() reported is_threat=True "
        f"{len(false_positives)} time(s) for a payload neither pure "
        "configuration ever flags -- this proves detect() observed a torn "
        f"mix of two configuration generations (sample: {false_positives[0]!r})"
    )
