"""
Dynamic SLA Router and Circuit Breaker engine for Mozilla Otari Hosted AI Gateway.
Executes primary route with strict 12s timeout, auto-failover on 429/5xx/timeout to open-weight fallback.
"""

import asyncio
import enum
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from core.config import Settings, get_settings
from gateway.otari_client import OtariClient, OtariGatewayError

logger = logging.getLogger("otari-sentry.gateway.router")


class CircuitState(str, enum.Enum):
    """
    Operational states of the Otari resilience circuit breaker.
    """

    CLOSED = "CLOSED"          # Normal operation: primary route active
    OPEN = "OPEN"              # Primary degraded: fast failover to secondary fallback
    HALF_OPEN = "HALF_OPEN"    # Probing primary recovery with canary request


@dataclass
class CircuitBreakerStatus:
    """
    Snapshot of circuit breaker operational telemetry.
    """

    state: CircuitState
    consecutive_failures: int
    failure_threshold: int
    recovery_timeout_seconds: float
    time_in_current_state_seconds: float
    total_trip_count: int
    total_fallback_activations: int


class CircuitBreaker:
    """
    Thread-safe and async-safe circuit breaker protecting Otari Gateway SLA boundaries.
    """

    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_timeout_seconds: float = 30.0,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout_seconds = recovery_timeout_seconds

        self._state: CircuitState = CircuitState.CLOSED
        self._consecutive_failures: int = 0
        self._last_failure_timestamp: float = 0.0
        self._last_state_change: float = time.time()
        self._total_trip_count: int = 0
        self._total_fallback_activations: int = 0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    async def can_attempt_primary(self) -> Tuple[bool, CircuitState]:
        """
        Evaluate whether the primary route can be attempted.
        Automatically transitions OPEN -> HALF_OPEN if cool-down period has elapsed.
        """
        async with self._lock:
            now = time.time()
            if self._state == CircuitState.CLOSED:
                return True, self._state

            if self._state == CircuitState.OPEN:
                elapsed = now - self._last_failure_timestamp
                if elapsed >= self.recovery_timeout_seconds:
                    logger.info(
                        "Circuit breaker recovery timeout (%.1fs) elapsed. Transitioning OPEN -> HALF_OPEN",
                        elapsed,
                    )
                    self._state = CircuitState.HALF_OPEN
                    self._last_state_change = now
                    return True, self._state
                return False, self._state

            # If HALF_OPEN, allow single canary execution
            return True, self._state

    async def record_success(self) -> None:
        """
        Record successful primary model response. Recovers circuit if in HALF_OPEN.
        """
        async with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                logger.info("Canary probe succeeded. Transitioning HALF_OPEN -> CLOSED")
                self._state = CircuitState.CLOSED
                self._last_state_change = time.time()
            self._consecutive_failures = 0

    async def record_failure(self, reason: str) -> None:
        """
        Record primary model failure. Trips circuit to OPEN if threshold exceeded.
        """
        async with self._lock:
            now = time.time()
            self._consecutive_failures += 1
            self._last_failure_timestamp = now
            self._total_fallback_activations += 1

            if self._state == CircuitState.HALF_OPEN:
                logger.warning(
                    "Canary probe failed (%s). Transitioning HALF_OPEN -> OPEN",
                    reason,
                )
                self._state = CircuitState.OPEN
                self._last_state_change = now
                self._total_trip_count += 1

            elif self._state == CircuitState.CLOSED:
                if self._consecutive_failures >= self.failure_threshold:
                    logger.warning(
                        "Circuit breaker threshold reached (%d consecutive failures). Transitioning CLOSED -> OPEN. Reason: %s",
                        self._consecutive_failures,
                        reason,
                    )
                    self._state = CircuitState.OPEN
                    self._last_state_change = now
                    self._total_trip_count += 1

    async def get_status(self) -> CircuitBreakerStatus:
        """
        Retrieve live circuit status telemetry.
        """
        async with self._lock:
            now = time.time()
            return CircuitBreakerStatus(
                state=self._state,
                consecutive_failures=self._consecutive_failures,
                failure_threshold=self.failure_threshold,
                recovery_timeout_seconds=self.recovery_timeout_seconds,
                time_in_current_state_seconds=round(now - self._last_state_change, 2),
                total_trip_count=self._total_trip_count,
                total_fallback_activations=self._total_fallback_activations,
            )

    async def reset(self) -> None:
        """
        Manual circuit breaker reset (useful for testing and ops recovery).
        """
        async with self._lock:
            self._state = CircuitState.CLOSED
            self._consecutive_failures = 0
            self._last_failure_timestamp = 0.0
            self._last_state_change = time.time()


@dataclass
class RoutedCompletionResponse:
    """
    Standardized result wrapper from the Dynamic SLA Router.
    """

    raw_response: Any
    served_model: str
    requested_model: str
    fallback_triggered: bool
    failover_reason: Optional[str]
    circuit_state: CircuitState
    latency_ms: float
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    code_executed: Optional[str] = None
    sandbox_output: Optional[str] = None


class SentryRouter:
    """
    SLA Router: Enforces 12s primary timeout, auto-failover, and circuit-breaker degrade logic.
    Primary target: alibaba/qwen-3.5-35b-a3b
    Fallback target: meta-llama/llama-3.3-70b-instruct
    """

    def __init__(
        self,
        client: Optional[OtariClient] = None,
        settings: Optional[Settings] = None,
    ):
        self.settings = settings or get_settings()
        self.client = client or OtariClient(
            base_url=self.settings.OTARI_BASE_URL,
            api_key=self.settings.OTARI_API_KEY,
            max_retries=self.settings.MAX_RETRIES,
        )
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=self.settings.CIRCUIT_BREAKER_FAILURE_THRESHOLD,
            recovery_timeout_seconds=self.settings.CIRCUIT_BREAKER_RECOVERY_TIME_SECONDS,
        )

    def _extract_token_usage(self, response: Any) -> Tuple[int, int, int]:
        """
        Safely extract usage tokens from OpenAI ChatCompletion response.
        """
        prompt_tokens = 0
        completion_tokens = 0
        total_tokens = 0
        try:
            usage = getattr(response, "usage", None)
            if usage:
                prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
                completion_tokens = getattr(usage, "completion_tokens", 0) or 0
                total_tokens = getattr(usage, "total_tokens", 0) or (prompt_tokens + completion_tokens)
            elif isinstance(response, dict) and "usage" in response:
                u = response["usage"]
                prompt_tokens = u.get("prompt_tokens", 0)
                completion_tokens = u.get("completion_tokens", 0)
                total_tokens = u.get("total_tokens", prompt_tokens + completion_tokens)
        except Exception as exc:
            logger.debug("Failed extracting token usage from response: %s", exc)
        return prompt_tokens, completion_tokens, total_tokens

    async def route_chat_completion(
        self,
        messages: List[Dict[str, Any]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        trace_id: Optional[str] = None,
        **kwargs: Any,
    ) -> RoutedCompletionResponse:
        """
        Execute chat completion through resilient dynamic routing.
        1. Evaluates Circuit Breaker state.
        2. If OPEN, fast-fails to secondary fallback without waiting for primary timeout.
        3. If CLOSED or HALF_OPEN, attempts primary (12s SLA).
        4. On timeout or 429/5xx, auto-failover to secondary fallback.
        """
        primary_model = model or self.settings.PRIMARY_MODEL
        fallback_model = self.settings.FALLBACK_MODEL
        start_perf = time.perf_counter()

        can_attempt, current_state = await self.circuit_breaker.can_attempt_primary()

        # Route fast-failover when circuit is OPEN
        if not can_attempt:
            logger.warning(
                "[Trace %s] Circuit breaker is OPEN. Skipping primary '%s' -> Direct route to fallback '%s'",
                trace_id,
                primary_model,
                fallback_model,
            )
            fallback_res = await self.client.create_chat_completion(
                model=fallback_model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=self.settings.FALLBACK_TIMEOUT_SECONDS,
                extra_headers=extra_headers,
                **kwargs,
            )
            total_duration_ms = round((time.perf_counter() - start_perf) * 1000.0, 2)
            pt, ct, tt = self._extract_token_usage(fallback_res)
            return RoutedCompletionResponse(
                raw_response=fallback_res,
                served_model=fallback_model,
                requested_model=primary_model,
                fallback_triggered=True,
                failover_reason="Circuit breaker OPEN (SLA protection fast-route)",
                circuit_state=current_state,
                latency_ms=total_duration_ms,
                prompt_tokens=pt,
                completion_tokens=ct,
                total_tokens=tt,
                code_executed=getattr(fallback_res, "code_executed", None),
                sandbox_output=getattr(fallback_res, "sandbox_output", None),
            )

        # Attempt primary route with 12s SLA timeout
        try:
            logger.info(
                "[Trace %s] Routing to primary model '%s' (SLA: %.1fs)",
                trace_id,
                primary_model,
                self.settings.PRIMARY_TIMEOUT_SECONDS,
            )
            primary_res = await self.client.create_chat_completion(
                model=primary_model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=self.settings.PRIMARY_TIMEOUT_SECONDS,
                extra_headers=extra_headers,
                **kwargs,
            )
            await self.circuit_breaker.record_success()
            total_duration_ms = round((time.perf_counter() - start_perf) * 1000.0, 2)
            pt, ct, tt = self._extract_token_usage(primary_res)
            return RoutedCompletionResponse(
                raw_response=primary_res,
                served_model=primary_model,
                requested_model=primary_model,
                fallback_triggered=False,
                failover_reason=None,
                circuit_state=self.circuit_breaker.state,
                latency_ms=total_duration_ms,
                prompt_tokens=pt,
                completion_tokens=ct,
                total_tokens=tt,
                code_executed=getattr(primary_res, "code_executed", None),
                sandbox_output=getattr(primary_res, "sandbox_output", None),
            )

        except Exception as exc:
            # Catch 504/timeout, 400 bad request, 429 quota, 5xx or connection failures from primary
            status_code = getattr(exc, "status_code", 504 if "timeout" in str(exc).lower() else 500)
            failover_reason = f"Primary model failure ({status_code}): {str(exc)}"
            logger.warning(
                "[Trace %s] Primary model '%s' failed: %s. Initiating auto-failover to '%s'",
                trace_id,
                primary_model,
                failover_reason,
                fallback_model,
            )
            await self.circuit_breaker.record_failure(failover_reason)

            # Auto-failover execution to fallback open-weight model
            try:
                fallback_res = await self.client.create_chat_completion(
                    model=fallback_model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    timeout=self.settings.FALLBACK_TIMEOUT_SECONDS,
                    extra_headers=extra_headers,
                    **kwargs,
                )
                total_duration_ms = round((time.perf_counter() - start_perf) * 1000.0, 2)
                pt, ct, tt = self._extract_token_usage(fallback_res)
                return RoutedCompletionResponse(
                    raw_response=fallback_res,
                    served_model=fallback_model,
                    requested_model=primary_model,
                    fallback_triggered=True,
                    failover_reason=failover_reason,
                    circuit_state=self.circuit_breaker.state,
                    latency_ms=total_duration_ms,
                    prompt_tokens=pt,
                    completion_tokens=ct,
                    total_tokens=tt,
                    code_executed=getattr(fallback_res, "code_executed", None),
                    sandbox_output=getattr(fallback_res, "sandbox_output", None),
                )

            except Exception as fallback_exc:
                logger.error(
                    "[Trace %s] Both primary ('%s') and fallback ('%s') models failed: %s",
                    trace_id,
                    primary_model,
                    fallback_model,
                    fallback_exc,
                )
                raise OtariGatewayError(
                    message=f"All routes exhausted. Primary failed: {failover_reason}. Fallback failed: {str(fallback_exc)}",
                    status_code=502,
                    is_transient=True,
                ) from fallback_exc
