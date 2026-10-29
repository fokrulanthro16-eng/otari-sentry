"""
OpenTelemetry-compatible Telemetry & Tracing Engine.
Provides microsecond timing with time.perf_counter(), W3C Trace Context simulation,
W3C baggage propagation, and structured token audit logging.
"""

import json
import logging
import re
import sys
import threading
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Configure standard structured logger
logger = logging.getLogger("otari-sentry.telemetry")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            fmt='{"timestamp":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":%(message)s}',
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def generate_trace_id() -> str:
    """
    Generate a 32-character lowercase hexadecimal W3C compliant Trace ID (128-bit).
    """
    return uuid.uuid4().hex


def generate_span_id() -> str:
    """
    Generate a 16-character lowercase hexadecimal W3C compliant Span ID (64-bit).
    """
    return uuid.uuid4().hex[:16]


def format_traceparent(trace_id: str, span_id: str, recorded: bool = True) -> str:
    """
    Format standard W3C traceparent header: 00-{trace_id}-{span_id}-{flags}.
    """
    flags = "01" if recorded else "00"
    return f"00-{trace_id.lower()}-{span_id.lower()}-{flags}"


_TRACEPARENT_REGEX = re.compile(
    r"^00-([0-9a-fA-F]{32})-([0-9a-fA-F]{16})-([0-9a-fA-F]{2})$"
)


def parse_traceparent(header_val: Optional[str]) -> Tuple[str, str]:
    """
    Parse an incoming W3C traceparent header.
    Returns (trace_id, parent_span_id). If missing or invalid, generates fresh IDs.
    """
    if header_val:
        match = _TRACEPARENT_REGEX.match(header_val.strip())
        if match:
            return match.group(1).lower(), match.group(2).lower()
    return generate_trace_id(), generate_span_id()


def format_baggage(baggage: Dict[str, str]) -> str:
    """
    Format dictionary as a W3C baggage header string (key1=val1,key2=val2).
    """
    items = []
    for k, v in baggage.items():
        clean_k = str(k).strip().replace("=", "").replace(",", "")
        clean_v = str(v).strip().replace("=", "").replace(",", "")
        items.append(f"{clean_k}={clean_v}")
    return ",".join(items)


def parse_baggage(header_val: Optional[str]) -> Dict[str, str]:
    """
    Parse a W3C baggage header string into a dictionary.
    """
    result: Dict[str, str] = {}
    if not header_val:
        return result
    for pair in header_val.split(","):
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k.strip()] = v.strip()
    return result


@dataclass
class AuditRecord:
    """
    Immutable representation of an executed or blocked LLM interaction.
    """

    trace_id: str
    span_id: str
    timestamp: float
    client_ip: Optional[str]
    endpoint: str
    method: str
    airlock_passed: bool
    airlock_violation: Optional[str] = None
    airlock_reason: Optional[str] = None
    airlock_scan_ms: float = 0.0
    model_requested: Optional[str] = None
    model_served: Optional[str] = None
    fallback_triggered: bool = False
    fallback_reason: Optional[str] = None
    status_code: int = 200
    latency_ms: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    tokens_conserved: int = 0
    baggage: Dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self))


class TraceSpan:
    """
    Context manager for microsecond execution timing and span lifecycle tracking.
    """

    def __init__(
        self,
        name: str,
        trace_id: Optional[str] = None,
        parent_span_id: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ):
        self.name = name
        self.trace_id = trace_id or generate_trace_id()
        self.parent_span_id = parent_span_id
        self.span_id = generate_span_id()
        self.attributes = attributes or {}
        self.start_perf: float = 0.0
        self.end_perf: float = 0.0
        self.duration_ms: float = 0.0
        self.error: Optional[str] = None

    def __enter__(self) -> "TraceSpan":
        self.start_perf = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.end_perf = time.perf_counter()
        self.duration_ms = round((self.end_perf - self.start_perf) * 1000.0, 4)
        if exc_val:
            self.error = str(exc_val)
            self.attributes["error"] = True
            self.attributes["error_message"] = str(exc_val)
        self.attributes["duration_ms"] = self.duration_ms

    def traceparent(self) -> str:
        return format_traceparent(self.trace_id, self.span_id)


class TelemetryManager:
    """
    Central telemetry management engine for otari-sentry.
    Maintains rolling SLA metrics, token conservation counters, and audit logs.
    """

    def __init__(self, max_history: int = 1000):
        self._lock = threading.Lock()
        self._max_history = max_history
        self._audit_history: deque[AuditRecord] = deque(maxlen=max_history)
        self._latencies_ms: deque[float] = deque(maxlen=max_history)

        # Cumulative counters
        self.total_requests: int = 0
        self.successful_requests: int = 0
        self.airlock_blocked_requests: int = 0
        self.fallback_requests: int = 0
        self.total_prompt_tokens: int = 0
        self.total_completion_tokens: int = 0
        self.total_tokens_conserved: int = 0
        self.violations_by_category: Dict[str, int] = {}

    def record_audit(self, record: AuditRecord) -> None:
        """
        Record completed transaction into structured telemetry audit and update live metrics.
        """
        with self._lock:
            self.total_requests += 1
            if record.airlock_passed:
                if record.status_code < 400:
                    self.successful_requests += 1
                if record.fallback_triggered:
                    self.fallback_requests += 1
                self.total_prompt_tokens += record.prompt_tokens
                self.total_completion_tokens += record.completion_tokens
            else:
                self.airlock_blocked_requests += 1
                self.total_tokens_conserved += record.tokens_conserved
                cat = record.airlock_violation or "UNKNOWN"
                self.violations_by_category[cat] = self.violations_by_category.get(cat, 0) + 1

            self._latencies_ms.append(record.latency_ms)
            self._audit_history.append(record)

        # Log structured JSON event for external log shippers (Datadog, FluentBit, Splunk)
        log_payload = record.to_json()
        if record.airlock_passed and record.status_code < 400:
            logger.info(log_payload)
        elif not record.airlock_passed:
            logger.warning(log_payload)
        else:
            logger.error(log_payload)

    def get_metrics(self) -> Dict[str, Any]:
        """
        Calculate rolling SLA metrics, percentile latencies, and token efficiency.
        """
        with self._lock:
            latencies = list(self._latencies_ms)
            total = self.total_requests
            blocked = self.airlock_blocked_requests
            success = self.successful_requests
            fallback = self.fallback_requests

            if latencies:
                sorted_lat = sorted(latencies)
                avg_latency = round(sum(latencies) / len(latencies), 2)
                p50 = round(sorted_lat[int(len(sorted_lat) * 0.50)], 2)
                p95 = round(sorted_lat[int(len(sorted_lat) * 0.95)], 2)
                p99 = round(sorted_lat[min(int(len(sorted_lat) * 0.99), len(sorted_lat) - 1)], 2)
            else:
                avg_latency = p50 = p95 = p99 = 0.0

            return {
                "total_requests": total,
                "successful_requests": success,
                "airlock_blocked_requests": blocked,
                "fallback_requests": fallback,
                "block_rate_percentage": round((blocked / total * 100.0), 2) if total > 0 else 0.0,
                "fallback_rate_percentage": round((fallback / total * 100.0), 2) if total > 0 else 0.0,
                "total_tokens_served": self.total_prompt_tokens + self.total_completion_tokens,
                "total_tokens_conserved": self.total_tokens_conserved,
                "latency_metrics_ms": {
                    "avg": avg_latency,
                    "p50": p50,
                    "p95": p95,
                    "p99": p99,
                },
                "violations_by_category": dict(self.violations_by_category),
            }

    def reset_for_tests(self) -> None:
        """
        Reset all counters for clean test isolation.
        """
        with self._lock:
            self._audit_history.clear()
            self._latencies_ms.clear()
            self.total_requests = 0
            self.successful_requests = 0
            self.airlock_blocked_requests = 0
            self.fallback_requests = 0
            self.total_prompt_tokens = 0
            self.total_completion_tokens = 0
            self.total_tokens_conserved = 0
            self.violations_by_category.clear()


# Global Singleton Telemetry Manager
_GLOBAL_TELEMETRY = TelemetryManager()


def get_telemetry_manager() -> TelemetryManager:
    return _GLOBAL_TELEMETRY
