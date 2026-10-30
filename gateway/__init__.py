"""
Gateway module for Mozilla Otari interaction, dynamic SLA routing, and circuit-breaker failover.
"""

from gateway.otari_client import OtariClient, OtariGatewayError, normalize_otari_model
from gateway.router import CircuitBreaker, CircuitState, RoutedCompletionResponse, SentryRouter

__all__ = [
    "OtariClient",
    "OtariGatewayError",
    "normalize_otari_model",
    "CircuitState",
    "CircuitBreaker",
    "SentryRouter",
    "RoutedCompletionResponse",
]
