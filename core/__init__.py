"""
Core module for otari-sentry: Security Airlock, Configuration, and OpenTelemetry engine.
"""

from core.config import Settings, get_settings
from core.telemetry import (
    TelemetryManager,
    TraceSpan,
    format_traceparent,
    generate_span_id,
    generate_trace_id,
    get_telemetry_manager,
)
from core.airlock import Airlock, AirlockResult, ViolationCategory

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
]
