import re
from typing import Any, NamedTuple

from guard_core.sync.detection_engine import (
    ContentPreprocessor,
    PatternCompiler,
    PerformanceMonitor,
    SemanticAnalyzer,
)
from guard_core.sync.detection_engine._validation_cache import PatternValidationCache


class _DetectionState(NamedTuple):
    compiler: PatternCompiler | None
    preprocessor: ContentPreprocessor | None
    semantic_analyzer: SemanticAnalyzer | None
    performance_monitor: PerformanceMonitor | None
    semantic_threshold: float
    threat_score_threshold: float


_LEGACY_DETECTION_STATE = _DetectionState(
    compiler=None,
    preprocessor=None,
    semantic_analyzer=None,
    performance_monitor=None,
    semantic_threshold=0.7,
    threat_score_threshold=1.0,
)


def _build_enhanced_detection_state(config: Any) -> _DetectionState:
    cache_path = getattr(config, "detection_pattern_validation_cache_path", None)
    validation_cache = PatternValidationCache(cache_path) if cache_path else None
    return _DetectionState(
        compiler=PatternCompiler(
            default_timeout=config.detection_compiler_timeout,
            max_cache_size=config.detection_max_tracked_patterns,
            validation_cache=validation_cache,
        ),
        preprocessor=ContentPreprocessor(
            max_content_length=config.detection_max_content_length,
            preserve_attack_patterns=config.detection_preserve_attack_patterns,
            max_full_scan_bytes=config.detection_max_body_inspect_bytes,
        ),
        semantic_analyzer=SemanticAnalyzer(),
        performance_monitor=PerformanceMonitor(
            anomaly_threshold=config.detection_anomaly_threshold,
            slow_pattern_threshold=config.detection_slow_pattern_threshold,
            history_size=config.detection_monitor_history_size,
            max_tracked_patterns=config.detection_max_tracked_patterns,
            anomaly_emission_cooldown=config.detection_anomaly_emission_cooldown,
            min_samples_for_anomaly=config.detection_min_samples_for_anomaly,
        ),
        semantic_threshold=config.detection_semantic_threshold,
        threat_score_threshold=config.detection_threat_score_threshold,
    )


_HTML_EVENT_HANDLER_ATTRS_PROVENANCE = (
    "re-derived 2026-08-20 as the union of two actively pentested, "
    "regularly-updated XSS references rather than a one-time reading of "
    "spec text: every event handler id in PortSwigger's XSS cheat sheet "
    "(https://portswigger.net/web-security/cross-site-scripting/cheat-"
    "sheet, 142 names, includes vendor-prefixed and experimental handlers "
    "such as onwebkitfullscreenchange and onpagereveal, plus "
    "onafterscriptexecute/onbeforescriptexecute missed by the first "
    "extraction pass and added in a later adversarial review) union every "
    "handler in OWASP's XSS Filter Evasion Cheat Sheet (https://"
    "cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_"
    "Sheet.html, 102 names, includes legacy IE/DHTML-only handlers such "
    "as onbounce and onrowsenter), both extracted verbatim from the live "
    "page's markup, not summarized; this still goes silently stale every "
    "time either source adds a handler this list has not re-absorbed, no "
    "test fails when it does, only recall quietly drops, so it needs "
    "periodic re-derivation against the then-current sources, not a "
    "one-time fix. Deliberately excluded despite resembling a handler: "
    "onpointerlockchange/onpointerlockerror (real Document IDL "
    "properties per the Pointer Lock spec, but confirmed unreflected as "
    "an HTML content attribute in a live Chromium build, so an inline "
    "`<div onpointerlockchange=...>` payload never executes and neither "
    "cheat sheet lists it); oncustomthing and other invented on*-prefixed "
    "words are excluded because they are not handlers at all"
)
_HTML_EVENT_HANDLER_ATTRS = frozenset(
    {
        "onabort",
        "onactivate",
        "onafterprint",
        "onafterscriptexecute",
        "onafterupdate",
        "onanimationcancel",
        "onanimationend",
        "onanimationiteration",
        "onanimationstart",
        "onauxclick",
        "onbeforeactivate",
        "onbeforecopy",
        "onbeforecut",
        "onbeforedeactivate",
        "onbeforeeditfocus",
        "onbeforeinput",
        "onbeforematch",
        "onbeforepaste",
        "onbeforeprint",
        "onbeforescriptexecute",
        "onbeforetoggle",
        "onbeforeunload",
        "onbeforeupdate",
        "onbegin",
        "onblur",
        "onbounce",
        "oncancel",
        "oncanplay",
        "oncanplaythrough",
        "oncellchange",
        "onchange",
        "onclick",
        "onclose",
        "oncommand",
        "oncontentvisibilityautostatechange",
        "oncontextlost",
        "oncontextmenu",
        "oncontextrestored",
        "oncontrolselect",
        "oncopy",
        "oncuechange",
        "oncut",
        "ondataavailable",
        "ondatasetchanged",
        "ondatasetcomplete",
        "ondblclick",
        "ondeactivate",
        "ondevicemotion",
        "ondeviceorientation",
        "ondrag",
        "ondragdrop",
        "ondragend",
        "ondragenter",
        "ondragexit",
        "ondragleave",
        "ondragover",
        "ondragstart",
        "ondrop",
        "ondurationchange",
        "onemptied",
        "onend",
        "onended",
        "onerror",
        "onerrorupdate",
        "onfilterchange",
        "onfinish",
        "onfocus",
        "onfocusin",
        "onfocusout",
        "onformdata",
        "onfullscreenchange",
        "ongesturechange",
        "ongestureend",
        "ongesturestart",
        "ongotpointercapture",
        "onhashchange",
        "onhelp",
        "oninput",
        "oninvalid",
        "onkeydown",
        "onkeypress",
        "onkeyup",
        "onlanguagechange",
        "onlayoutcomplete",
        "onload",
        "onloadeddata",
        "onloadedmetadata",
        "onloadstart",
        "onlocation",
        "onlosecapture",
        "onlostpointercapture",
        "onmediacomplete",
        "onmediaerror",
        "onmessage",
        "onmessageerror",
        "onmousedown",
        "onmouseenter",
        "onmouseleave",
        "onmousemove",
        "onmouseout",
        "onmouseover",
        "onmouseup",
        "onmousewheel",
        "onmove",
        "onmoveend",
        "onmovestart",
        "onmozfullscreenchange",
        "onoffline",
        "ononline",
        "onoutofsync",
        "onpagehide",
        "onpagereveal",
        "onpageshow",
        "onpageswap",
        "onpaste",
        "onpause",
        "onplay",
        "onplaying",
        "onpointercancel",
        "onpointerdown",
        "onpointerenter",
        "onpointerleave",
        "onpointermove",
        "onpointerout",
        "onpointerover",
        "onpointerrawupdate",
        "onpointerup",
        "onpopstate",
        "onprogress",
        "onpromptaction",
        "onpromptdismiss",
        "onpropertychange",
        "onratechange",
        "onreadystatechange",
        "onredo",
        "onrejectionhandled",
        "onrepeat",
        "onreset",
        "onresize",
        "onresizeend",
        "onresizestart",
        "onresume",
        "onreverse",
        "onrowdelete",
        "onrowexit",
        "onrowinserted",
        "onrowsenter",
        "onscroll",
        "onscrollend",
        "onscrollsnapchange",
        "onscrollsnapchanging",
        "onsearch",
        "onsecuritypolicyviolation",
        "onseek",
        "onseeked",
        "onseeking",
        "onselect",
        "onselectionchange",
        "onselectstart",
        "onslotchange",
        "onstalled",
        "onstart",
        "onstop",
        "onstorage",
        "onsubmit",
        "onsuspend",
        "onsyncrestored",
        "ontimeerror",
        "ontimeupdate",
        "ontoggle",
        "ontouchcancel",
        "ontouchend",
        "ontouchmove",
        "ontouchstart",
        "ontrackchange",
        "ontransitioncancel",
        "ontransitionend",
        "ontransitionrun",
        "ontransitionstart",
        "onundo",
        "onunhandledrejection",
        "onunload",
        "onurlflip",
        "onvalidationstatuschange",
        "onvolumechange",
        "onwaiting",
        "onwebkitanimationend",
        "onwebkitanimationiteration",
        "onwebkitanimationstart",
        "onwebkitfullscreenchange",
        "onwebkitmouseforcechanged",
        "onwebkitmouseforcedown",
        "onwebkitmouseforceup",
        "onwebkitmouseforcewillbegin",
        "onwebkitneedkey",
        "onwebkitplaybacktargetavailabilitychanged",
        "onwebkitpresentationmodechanged",
        "onwebkittransitionend",
        "onwebkitwillrevealbottom",
        "onwheel",
    }
)
_HTML_EVENT_HANDLER_ALTERNATION = "|".join(
    re.escape(name)
    for name in sorted(_HTML_EVENT_HANDLER_ATTRS, key=lambda c: (-len(c), c))
)
