import re
from typing import TYPE_CHECKING, TypedDict

from guard_core.sync._utils.scan_config_scope import configure_lock, scoped_state
from guard_core.sync.detection_engine import (
    ContentPreprocessor,
    PerformanceMonitor,
    looks_like_binary_content,
)
from guard_core.sync.detection_engine.monitor_reporting import (
    PatternReport,
    PerformanceSummary,
)
from guard_core.sync.handlers._suspatterns_lazy_rows import disabled_row_sources_of
from guard_core.sync.handlers._suspatterns_sources import (
    _DEFAULT_MAX_SCAN_LENGTH,
    _regex_anomaly,
    _supports_enhanced_config,
)
from guard_core.sync.handlers._suspatterns_state import (
    _build_enhanced_detection_state,
    _DetectionState,
)

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol


class PerformanceStats(TypedDict):
    summary: PerformanceSummary
    slow_patterns: list[PatternReport]
    problematic_patterns: list[PatternReport]


class _SusPatternsEnhancedMixin:
    compiled_custom_patterns: set[tuple[re.Pattern, frozenset[str], str]]
    _config: "SyncSecurityConfig | None" = None
    _disabled_row_sources: frozenset[str] = frozenset()
    agent_handler: "SyncAgentHandlerProtocol | None" = None
    _detection_state: _DetectionState
    _performance_monitor: PerformanceMonitor | None
    _semantic_threshold: float
    _sensitive_headers_union: frozenset[str] = frozenset()
    _sensitive_params_union: frozenset[str] = frozenset()
    _sensitive_body_fields_union: frozenset[str] = frozenset()

    if TYPE_CHECKING:

        @property
        def _events_agent_handler(self) -> "SyncAgentHandlerProtocol | None": ...

    def configure(self, config: object) -> None:
        with configure_lock:
            self._configure_locked(config)

    def _configure_locked(self, config: object) -> None:
        cls = type(self)
        # An app's own manager (it has its own _config) keeps its own names; the
        # default manager accumulates on the class, as it always did.
        owner: _SusPatternsEnhancedMixin | type[_SusPatternsEnhancedMixin] = (
            self if "_config" in vars(self) else cls
        )
        owner._sensitive_headers_union = self._sensitive_headers_union | getattr(
            config, "log_sensitive_headers", frozenset()
        )
        owner._sensitive_params_union = self._sensitive_params_union | getattr(
            config, "log_sensitive_params", frozenset()
        )
        owner._sensitive_body_fields_union = (
            self._sensitive_body_fields_union
            | getattr(config, "log_sensitive_body_fields", frozenset())
        )

        self._disabled_row_sources = disabled_row_sources_of(config)

        if not _supports_enhanced_config(config):
            return
        if "_config" in vars(self):
            self._config = config
        else:
            cls._config = config
        self._detection_state = _build_enhanced_detection_state(config, self)
        try:
            object.__setattr__(config, "_guard_pattern_manager", self)
        except (AttributeError, TypeError):
            return

    def _resolve_state(self, state: _DetectionState | None) -> _DetectionState:
        return state if state is not None else scoped_state(self, self._detection_state)

    def _preprocess_content(
        self,
        content: str,
        correlation_id: str | None,
        *,
        state: _DetectionState | None = None,
    ) -> tuple[str, bool, str | None]:
        state = self._resolve_state(state)
        preprocessor = state.preprocessor
        if not preprocessor:
            max_length = getattr(
                self._config, "detection_max_content_length", _DEFAULT_MAX_SCAN_LENGTH
            )
            return content[:max_length], False, None

        context_preprocessor = ContentPreprocessor(
            max_content_length=preprocessor.max_content_length,
            preserve_attack_patterns=preprocessor.preserve_attack_patterns,
            agent_handler=self._events_agent_handler,
            correlation_id=correlation_id,
            max_full_scan_bytes=preprocessor._MAX_FULL_SCAN_BYTES,
        )
        decode_budget_exhausted = [False]
        processed, decoded = context_preprocessor.preprocess_with_decoded(
            content, decode_budget_exhausted
        )
        return processed, decode_budget_exhausted[0], decoded

    def _check_semantic_threats(
        self,
        content: str,
        *,
        state: _DetectionState | None = None,
        raw_content: str | None = None,
    ) -> tuple[list[dict], float]:
        state = self._resolve_state(state)
        semantic_analyzer = state.semantic_analyzer
        if not semantic_analyzer:
            return [], 0.0

        if looks_like_binary_content(
            raw_content if raw_content is not None else content
        ):
            return [], 0.0

        semantic_threshold = state.semantic_threshold
        semantic_budget = (
            state.preprocessor.max_content_length
            if state.preprocessor
            else len(content)
        )
        semantic_analysis = semantic_analyzer.analyze(content[:semantic_budget])
        semantic_score = semantic_analyzer.get_threat_score(semantic_analysis)
        threats = []

        if semantic_score > semantic_threshold:
            attack_probs = semantic_analysis.get("attack_probabilities", {})

            for attack_type, probability in attack_probs.items():
                if probability >= semantic_threshold:
                    threats.append(
                        {
                            "type": "semantic",
                            "attack_type": attack_type,
                            "probability": probability,
                            "analysis": semantic_analysis,
                        }
                    )

            if not threats and semantic_score >= semantic_threshold:
                threats.append(
                    {
                        "type": "semantic",
                        "attack_type": "suspicious",
                        "threat_score": semantic_score,
                        "analysis": semantic_analysis,
                    }
                )

        return threats, semantic_score

    def _calculate_threat_score(
        self, regex_threats: list, semantic_threats: list
    ) -> float:
        if not (regex_threats or semantic_threats):
            return 0.0

        anomaly = _regex_anomaly(regex_threats)
        semantic_scores = [
            t.get("probability", t.get("threat_score", 0.0)) for t in semantic_threats
        ]
        semantic_max = max(semantic_scores) if semantic_scores else 0.0
        return min(max(anomaly, semantic_max), 1.0)

    @classmethod
    def get_performance_stats(cls) -> PerformanceStats | None:
        instance = cls()
        performance_monitor = instance._performance_monitor
        if performance_monitor:
            return {
                "summary": performance_monitor.get_summary_stats(),
                "slow_patterns": performance_monitor.get_slow_patterns(),
                "problematic_patterns": (
                    performance_monitor.get_problematic_patterns()
                ),
            }
        return None

    @classmethod
    def get_component_status(cls) -> dict[str, bool]:
        instance = cls()
        state = instance._detection_state
        return {
            "compiler": state.compiler is not None,
            "preprocessor": state.preprocessor is not None,
            "semantic_analyzer": state.semantic_analyzer is not None,
            "performance_monitor": state.performance_monitor is not None,
        }

    def configure_semantic_threshold(self, threshold: float) -> None:
        self._semantic_threshold = max(0.0, min(1.0, threshold))
