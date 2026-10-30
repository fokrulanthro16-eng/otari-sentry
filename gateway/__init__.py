"""
Gateway module for Mozilla Otari interaction, dynamic SLA routing, and circuit-breaker failover.
"""

from gateway.otari_client import (
    PYTHON_SANDBOX_TOOL,
    OtariClient,
    OtariGatewayError,
    execute_code_sandbox,
    normalize_otari_model,
)
from gateway.router import CircuitBreaker, CircuitState, RoutedCompletionResponse, SentryRouter

__all__ = [
    "OtariClient",
    "OtariGatewayError",
    "normalize_otari_model",
    "PYTHON_SANDBOX_TOOL",
    "execute_code_sandbox",
    "CircuitState",
    "CircuitBreaker",
    "SentryRouter",
    "RoutedCompletionResponse",
]
