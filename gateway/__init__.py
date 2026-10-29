"""
Gateway module for Mozilla Otari interaction, dynamic SLA routing, and circuit-breaker failover.
"""

from gateway.otari_client import OtariClient, OtariGatewayError
from gateway.router import CircuitBreaker, CircuitState, RoutedCompletionResponse, SentryRouter

__all__ = [
    "OtariClient",
    "OtariGatewayError",
    "CircuitState",
    "CircuitBreaker",
    "SentryRouter",
    "RoutedCompletionResponse",
]
