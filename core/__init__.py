"""
Core module for otari-sentry: Security Airlock, Configuration, and OpenTelemetry engine.
"""

from core.airlock import Airlock, AirlockResult, ViolationCategory
from core.cache import CachedResponse, SentryCache, get_cache
from core.config import Settings, get_settings
from core.telemetry import (
    TelemetryManager,
    TraceSpan,
    format_traceparent,
    generate_span_id,
    generate_trace_id,
    get_telemetry_manager,
)

__all__ = [
    "Settings",
    "get_settings",
    "TelemetryManager",
    "get_telemetry_manager",
    "TraceSpan",
    "generate_trace_id",
    "generate_span_id",
    "format_traceparent",
    "Airlock",
    "AirlockResult",
    "ViolationCategory",
    "SentryCache",
    "get_cache",
    "CachedResponse",
]
