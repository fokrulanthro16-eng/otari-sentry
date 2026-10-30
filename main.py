"""
otari-sentry: Enterprise Gateway & Deterministic Policy Enforcement Server.
"Rules Engine Decides, AI Explains" — Sub-10ms injection filtering, dynamic SLA failover,
and OpenTelemetry-compatible tracing for Mozilla Otari Hosted AI Gateway.
"""

import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Union

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from core.airlock import Airlock, AirlockResult, ViolationCategory
from core.config import Settings, get_settings
from core.telemetry import (
    AuditRecord,
    TelemetryManager,
    format_baggage,
    format_traceparent,
    generate_span_id,
    get_telemetry_manager,
    parse_baggage,
    parse_traceparent,
)
from gateway.otari_client import OtariClient, OtariGatewayError
from gateway.router import CircuitBreakerStatus, CircuitState, SentryRouter


# ==============================================================================
# Request & Response Schemas (OpenAI Compatible)
# ==============================================================================

class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant", "tool", "function"] = Field(
        ..., description="Role of the message author"
    )
    content: Union[str, List[Dict[str, Any]]] = Field(
        ..., description="Contents of the message"
    )
    name: Optional[str] = Field(
        default=None, description="Optional name of the participant"
    )


class ChatCompletionRequest(BaseModel):
    model: Optional[str] = Field(
        default=None,
        description="Target model. Defaults to primary (alibaba/qwen-3.5-35b-a3b)",
        examples=["alibaba/qwen-3.5-35b-a3b"],
    )
    messages: List[ChatMessage] = Field(
        ..., description="List of conversation messages to be processed"
    )
    temperature: Optional[float] = Field(
        default=0.7, ge=0.0, le=2.0, description="Sampling temperature"
    )
    max_tokens: Optional[int] = Field(
        default=None, ge=1, description="Maximum tokens to generate"
    )
    stream: Optional[bool] = Field(
        default=False, description="Streaming completion (non-streaming gateway standard)"
    )
    top_p: Optional[float] = Field(
        default=1.0, ge=0.0, le=1.0, description="Nucleus sampling probability"
    )
    presence_penalty: Optional[float] = Field(
        default=0.0, ge=-2.0, le=2.0, description="Presence penalty parameter"
    )
    frequency_penalty: Optional[float] = Field(
        default=0.0, ge=-2.0, le=2.0, description="Frequency penalty parameter"
    )

    model_config = {
        "extra": "allow",
        "json_schema_extra": {
            "example": {
                "model": "alibaba/qwen-3.5-35b-a3b",
                "messages": [
                    {"role": "system", "content": "You are a helpful engineering assistant."},
                    {"role": "user", "content": "Explain deterministic validation in distributed systems."}
                ],
                "temperature": 0.7,
                "max_tokens": 512
            }
        }
    }


class AirlockInspectRequest(BaseModel):
    prompt: Optional[str] = Field(
        default=None, description="Single text prompt string to inspect"
    )
    messages: Optional[List[ChatMessage]] = Field(
        default=None, description="List of messages to inspect"
    )


class AirlockInspectResponse(BaseModel):
    passed: bool
    violation_category: Optional[str] = None
    matched_pattern: Optional[str] = None
    reason: Optional[str] = None
    scan_time_ms: float
    estimated_tokens: int
    tokens_conserved: int
    model_served: Optional[str] = None
    completion: Optional[str] = None
    usage: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None

    model_config = {"extra": "allow"}


# ==============================================================================
# Server Lifespan Lifecycle
# ==============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage application state initialization and graceful teardown.
    """
    settings = get_settings()
    telemetry = get_telemetry_manager()

    # Initialize Airlock deterministic guardrail
    airlock = Airlock(
        enabled=settings.AIRLOCK_ENABLED,
        max_prompt_length=settings.AIRLOCK_MAX_PROMPT_LENGTH,
        max_total_tokens=settings.AIRLOCK_MAX_TOTAL_TOKENS_ESTIMATE,
        strict_jailbreak=settings.AIRLOCK_STRICT_JAILBREAK_CHECK,
        strict_sql=settings.AIRLOCK_STRICT_SQL_CHECK,
        strict_credentials=settings.AIRLOCK_STRICT_CREDENTIAL_CHECK,
    )

    # Initialize resilient Otari client and dynamic SLA router
    otari_client = OtariClient(
        base_url=settings.OTARI_BASE_URL,
        api_key=settings.OTARI_API_KEY,
        max_retries=settings.MAX_RETRIES,
    )
    router = SentryRouter(client=otari_client, settings=settings)

    app.state.settings = settings
    app.state.telemetry = telemetry
    app.state.airlock = airlock
    app.state.otari_client = otari_client
    app.state.router = router

    yield

    # Teardown
    await otari_client.close()


# ==============================================================================
# State Accessor Helpers (Defensive Fallback for Test Harnesses)
# ==============================================================================

def get_app_settings(app_instance: FastAPI) -> Settings:
    if not hasattr(app_instance.state, "settings"):
        app_instance.state.settings = get_settings()
    return app_instance.state.settings


def get_app_telemetry(app_instance: FastAPI) -> TelemetryManager:
    if not hasattr(app_instance.state, "telemetry"):
        app_instance.state.telemetry = get_telemetry_manager()
    return app_instance.state.telemetry


def get_app_airlock(app_instance: FastAPI) -> Airlock:
    if not hasattr(app_instance.state, "airlock"):
        settings = get_app_settings(app_instance)
        app_instance.state.airlock = Airlock(
            enabled=settings.AIRLOCK_ENABLED,
            max_prompt_length=settings.AIRLOCK_MAX_PROMPT_LENGTH,
            max_total_tokens=settings.AIRLOCK_MAX_TOTAL_TOKENS_ESTIMATE,
            strict_jailbreak=settings.AIRLOCK_STRICT_JAILBREAK_CHECK,
            strict_sql=settings.AIRLOCK_STRICT_SQL_CHECK,
            strict_credentials=settings.AIRLOCK_STRICT_CREDENTIAL_CHECK,
        )
    return app_instance.state.airlock


def get_app_router(app_instance: FastAPI) -> SentryRouter:
    if not hasattr(app_instance.state, "router"):
        settings = get_app_settings(app_instance)
        client = OtariClient(
            base_url=settings.OTARI_BASE_URL,
            api_key=settings.OTARI_API_KEY,
            max_retries=settings.MAX_RETRIES,
        )
        app_instance.state.otari_client = client
        app_instance.state.router = SentryRouter(client=client, settings=settings)
    return app_instance.state.router


# ==============================================================================
# FastAPI Application Declaration
# ==============================================================================

app = FastAPI(
    title="otari-sentry",
    version="1.0.0",
    description=(
        "Production-grade resilient gateway and deterministic security proxy "
        "protecting Mozilla Otari Hosted AI Gateway. Enforces 'Rules Engine Decides, AI Explains' "
        "via sub-10ms regex injection filtering, zero-token early drops, and dynamic SLA circuit failover."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=[
        "X-Trace-ID",
        "traceparent",
        "baggage",
        "X-Latency-MS",
        "X-Otari-Model-Served",
        "X-Otari-Failover",
        "X-Otari-Circuit-State",
        "X-Tokens-Conserved",
    ],
)


# ==============================================================================
# OpenTelemetry & Timing Middleware
# ==============================================================================

@app.middleware("http")
async def telemetry_middleware(request: Request, call_next):
    """
    Extracts or generates W3C trace context, tracks microsecond execution timing,
    and enriches response with OpenTelemetry headers.
    """
    start_perf = time.perf_counter()

    # Extract or generate W3C Traceparent
    traceparent_hdr = request.headers.get("traceparent")
    trace_id, parent_span_id = parse_traceparent(traceparent_hdr)
    span_id = generate_span_id()

    # Extract or parse incoming baggage
    incoming_baggage = parse_baggage(request.headers.get("baggage"))

    # Attach to request state
    request.state.trace_id = trace_id
    request.state.span_id = span_id
    request.state.parent_span_id = parent_span_id
    request.state.baggage = incoming_baggage
    request.state.start_perf = start_perf

    response: Response = await call_next(request)

    elapsed_ms = round((time.perf_counter() - start_perf) * 1000.0, 3)

    # Standard W3C & OpenTelemetry HTTP Response Headers
    response.headers["X-Trace-ID"] = trace_id
    response.headers["traceparent"] = format_traceparent(trace_id, span_id)
    response.headers["X-Latency-MS"] = str(elapsed_ms)

    # Propagate W3C Baggage simulation
    settings: Settings = getattr(request.app.state, "settings", get_settings())
    if settings.SIMULATE_W3C_BAGGAGE:
        outgoing_baggage = dict(incoming_baggage)
        outgoing_baggage["service"] = settings.SERVICE_NAME
        outgoing_baggage["env"] = settings.ENVIRONMENT
        response.headers["baggage"] = format_baggage(outgoing_baggage)

    return response


# ==============================================================================
# Custom Error Handlers
# ==============================================================================

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Format schema validation errors adhering to OpenAI JSON error standards."""
    trace_id = getattr(request.state, "trace_id", "unknown-trace")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": {
                "message": f"Invalid request payload structure: {str(exc.errors())}",
                "type": "invalid_request_error",
                "code": "parameter_validation_failed",
                "trace_id": trace_id,
            }
        },
    )


@app.exception_handler(OtariGatewayError)
async def otari_gateway_exception_handler(request: Request, exc: OtariGatewayError):
    """Format upstream Otari gateway failures."""
    trace_id = getattr(request.state, "trace_id", "unknown-trace")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "message": exc.message,
                "type": "gateway_upstream_error",
                "code": "otari_gateway_failure",
                "is_transient": exc.is_transient,
                "trace_id": trace_id,
            }
        },
    )


# ==============================================================================
# API Endpoints
# ==============================================================================

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
INDEX_HTML_PATH = TEMPLATES_DIR / "index.html"


@app.get(
    "/",
    response_class=HTMLResponse,
    tags=["Dashboard"],
    summary="Otari-Sentry Interactive Dark-Mode Web Dashboard",
)
async def serve_dashboard():
    """
    Serve the high-contrast dark mode interactive Web UI dashboard.
    """
    if INDEX_HTML_PATH.exists():
        return HTMLResponse(content=INDEX_HTML_PATH.read_text(encoding="utf-8"))
    return HTMLResponse(
        content="""<!DOCTYPE html><html><head><title>Otari-Sentry</title></head>
        <body style='background:#0d1117;color:#fff;font-family:sans-serif;padding:2rem;'>
        <h1>Otari-Sentry Gateway</h1><p>Dashboard template initializing...</p></body></html>""",
        status_code=200,
    )


@app.get(
    "/healthz",
    tags=["System"],
    summary="Health check probe",
)
@app.get("/v1/healthz", tags=["System"], include_in_schema=False)
@app.get(
    "/v1/health",
    tags=["System"],
    summary="Health check & circuit breaker status",
)
@app.get("/health", tags=["System"], include_in_schema=False)
async def health_check(request: Request):
    """
    Retrieve operational health status, circuit breaker telemetry, and gateway configuration.
    """
    router = get_app_router(request.app)
    settings = get_app_settings(request.app)
    cb_status: CircuitBreakerStatus = await router.circuit_breaker.get_status()

    is_healthy = cb_status.state != CircuitState.OPEN
    return {
        "status": "healthy" if is_healthy else "degraded",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "gateway": {
            "base_url": settings.OTARI_BASE_URL,
            "primary_model": settings.PRIMARY_MODEL,
            "fallback_model": settings.FALLBACK_MODEL,
            "primary_timeout_seconds": settings.PRIMARY_TIMEOUT_SECONDS,
            "fallback_timeout_seconds": settings.FALLBACK_TIMEOUT_SECONDS,
        },
        "circuit_breaker": {
            "state": cb_status.state.value,
            "consecutive_failures": cb_status.consecutive_failures,
            "failure_threshold": cb_status.failure_threshold,
            "recovery_timeout_seconds": cb_status.recovery_timeout_seconds,
            "time_in_state_seconds": cb_status.time_in_current_state_seconds,
            "total_trips": cb_status.total_trip_count,
            "total_fallback_activations": cb_status.total_fallback_activations,
        },
        "airlock": {
            "enabled": settings.AIRLOCK_ENABLED,
            "max_prompt_length": settings.AIRLOCK_MAX_PROMPT_LENGTH,
            "max_tokens_budget": settings.AIRLOCK_MAX_TOTAL_TOKENS_ESTIMATE,
        },
    }


@app.get(
    "/v1/telemetry/metrics",
    tags=["Telemetry"],
    summary="OpenTelemetry metrics, SLA percentiles, and token conservation",
)
async def get_metrics(request: Request):
    """
    Retrieve live SLA performance metrics, latency distributions (p50/p95/p99),
    and exact count of tokens saved by early Airlock rejections.
    """
    telemetry = get_app_telemetry(request.app)
    router = get_app_router(request.app)
    cb_status = await router.circuit_breaker.get_status()

    metrics = telemetry.get_metrics()
    metrics["circuit_breaker_state"] = cb_status.state.value
    metrics["circuit_breaker_consecutive_failures"] = cb_status.consecutive_failures
    return metrics


@app.post(
    "/v1/airlock/inspect",
    tags=["Security"],
    summary="Sub-10ms deterministic Airlock inspection and inference proxy",
)
async def airlock_inspect(payload: AirlockInspectRequest, request: Request, response: Response):
    """
    Deterministic audit tool to test inputs against the Airlock security policies.
    Guaranteed sub-10ms response:
    - If policy violation: Returns HTTP 403 Forbidden with 0 token leakage and sub-millisecond execution.
    - If clean: Executes inference via Mozilla Otari gateway, returns completion, and logs token telemetry.
    """
    airlock = get_app_airlock(request.app)
    router = get_app_router(request.app)
    telemetry = get_app_telemetry(request.app)
    trace_id = getattr(request.state, "trace_id", "unknown-trace")
    span_id = getattr(request.state, "span_id", "unknown-span")
    client_ip = request.client.host if request.client else None

    if payload.messages:
        messages_dict = [m.model_dump() for m in payload.messages]
    elif payload.prompt:
        messages_dict = [{"role": "user", "content": payload.prompt}]
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must provide either 'prompt' or 'messages' field.",
        )

    result = airlock.inspect_messages(messages_dict)

    if not result.passed:
        # Rules Engine Decides: Immediate deterministic rejection with ZERO token consumption
        tokens_saved = result.tokens_conserved
        violation_cat = result.violation_category.value if result.violation_category else "UNKNOWN"

        audit = AuditRecord(
            trace_id=trace_id,
            span_id=span_id,
            timestamp=time.time(),
            client_ip=client_ip,
            endpoint="/v1/airlock/inspect",
            method="POST",
            airlock_passed=False,
            airlock_violation=violation_cat,
            airlock_reason=result.reason,
            airlock_scan_ms=result.scan_time_ms,
            model_requested=router.settings.PRIMARY_MODEL,
            model_served=None,
            status_code=403,
            latency_ms=result.scan_time_ms,
            tokens_conserved=tokens_saved,
        )
        telemetry.record_audit(audit)

        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            headers={
                "X-Airlock-Verdict": "REJECTED",
                "X-Airlock-Violation": violation_cat,
                "X-Airlock-Scan-MS": str(result.scan_time_ms),
                "X-Tokens-Conserved": str(tokens_saved),
            },
            content={
                "error": {
                    "message": f"Airlock Security Violation: {result.reason}",
                    "type": "airlock_security_violation",
                    "code": "forbidden_prompt",
                    "violation_category": violation_cat,
                    "matched_pattern": result.matched_pattern,
                    "tokens_conserved": tokens_saved,
                    "scan_time_ms": result.scan_time_ms,
                    "trace_id": trace_id,
                },
                "passed": False,
                "violation_category": violation_cat,
                "matched_pattern": result.matched_pattern,
                "reason": result.reason,
                "scan_time_ms": result.scan_time_ms,
                "estimated_tokens": result.estimated_tokens,
                "tokens_conserved": tokens_saved,
            },
        )

    # Valid prompt: Execute clean inference via Mozilla Otari Gateway
    model_served = router.settings.PRIMARY_MODEL
    completion_text = ""
    prompt_tokens = result.estimated_tokens
    completion_tokens = 0
    total_tokens = prompt_tokens
    raw_dump = None
    fallback_triggered = False
    failover_reason = None
    latency_ms = result.scan_time_ms

    try:
        routed_response = await router.route_chat_completion(
            messages=messages_dict,
            model=router.settings.PRIMARY_MODEL,
            temperature=0.7,
            max_tokens=256,
            trace_id=trace_id,
        )
        model_served = routed_response.served_model
        fallback_triggered = routed_response.fallback_triggered
        failover_reason = routed_response.failover_reason
        latency_ms = routed_response.latency_ms
        prompt_tokens = routed_response.prompt_tokens
        completion_tokens = routed_response.completion_tokens
        total_tokens = routed_response.total_tokens

        raw = routed_response.raw_response
        if hasattr(raw, "choices") and raw.choices:
            c = raw.choices[0]
            msg = getattr(c, "message", None)
            if msg:
                content = getattr(msg, "content", "")
                reasoning = getattr(msg, "reasoning", "") or getattr(msg, "reasoning_content", "")
                completion_text = content or reasoning or ""
        elif isinstance(raw, dict) and "choices" in raw and raw["choices"]:
            msg = raw["choices"][0].get("message", {})
            completion_text = msg.get("content") or msg.get("reasoning") or msg.get("reasoning_content") or ""
        raw_dump = raw.model_dump() if hasattr(raw, "model_dump") else raw

    except Exception as exc:
        completion_text = f"Input verified clean by Airlock ({result.scan_time_ms} ms). Upstream response: {str(exc)}"
        raw_dump = {"info": "Upstream error or offline mode", "detail": str(exc)}

    audit = AuditRecord(
        trace_id=trace_id,
        span_id=span_id,
        timestamp=time.time(),
        client_ip=client_ip,
        endpoint="/v1/airlock/inspect",
        method="POST",
        airlock_passed=True,
        airlock_scan_ms=result.scan_time_ms,
        model_requested=router.settings.PRIMARY_MODEL,
        model_served=model_served,
        fallback_triggered=fallback_triggered,
        fallback_reason=failover_reason,
        status_code=200,
        latency_ms=latency_ms,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
    )
    telemetry.record_audit(audit)

    response.headers["X-Airlock-Verdict"] = "PASSED"
    response.headers["X-Airlock-Scan-MS"] = str(result.scan_time_ms)
    response.headers["X-Otari-Model-Served"] = model_served
    response.headers["X-Otari-Failover"] = "true" if fallback_triggered else "false"

    return {
        "passed": True,
        "violation_category": None,
        "matched_pattern": None,
        "reason": None,
        "scan_time_ms": result.scan_time_ms,
        "estimated_tokens": result.estimated_tokens,
        "tokens_conserved": 0,
        "model_served": model_served,
        "completion": completion_text,
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
        },
        "response": raw_dump,
    }


@app.post(
    "/v1/chat/completions",
    tags=["Gateway"],
    summary="OpenAI-compatible resilient chat completions via Mozilla Otari",
)
async def chat_completions(
    req: ChatCompletionRequest,
    request: Request,
    response: Response,
):
    """
    High-throughput chat completions pipeline:
    1. Deterministic Airlock guardrail check (< 10ms).
       - On violation: Immediately terminates with HTTP 403, 0 tokens consumed.
    2. Dynamic SLA Router invocation:
       - Routes to Mozilla Otari with 12s primary timeout.
       - Auto-failover to secondary open-weight model on 429/5xx/timeout.
    3. Structured OpenTelemetry logging and header propagation.
    """
    trace_id = getattr(request.state, "trace_id", "unknown-trace")
    span_id = getattr(request.state, "span_id", "unknown-span")
    client_ip = request.client.host if request.client else None
    airlock = get_app_airlock(request.app)
    router = get_app_router(request.app)
    telemetry = get_app_telemetry(request.app)

    # Convert Pydantic messages to dictionaries for inspection
    raw_messages = [m.model_dump() for m in req.messages]

    # Step 1: Sub-10ms Deterministic Airlock Inspection
    airlock_result: AirlockResult = airlock.inspect_messages(raw_messages)

    if not airlock_result.passed:
        # Rules Engine Decides: Immediate deterministic rejection with ZERO token consumption
        tokens_saved = airlock_result.tokens_conserved
        violation_cat = airlock_result.violation_category.value if airlock_result.violation_category else "UNKNOWN"

        # Record audit log into telemetry
        audit = AuditRecord(
            trace_id=trace_id,
            span_id=span_id,
            timestamp=time.time(),
            client_ip=client_ip,
            endpoint="/v1/chat/completions",
            method="POST",
            airlock_passed=False,
            airlock_violation=violation_cat,
            airlock_reason=airlock_result.reason,
            airlock_scan_ms=airlock_result.scan_time_ms,
            model_requested=req.model or router.settings.PRIMARY_MODEL,
            model_served=None,
            status_code=403,
            latency_ms=airlock_result.scan_time_ms,
            tokens_conserved=tokens_saved,
        )
        telemetry.record_audit(audit)

        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            headers={
                "X-Airlock-Verdict": "REJECTED",
                "X-Airlock-Violation": violation_cat,
                "X-Airlock-Scan-MS": str(airlock_result.scan_time_ms),
                "X-Tokens-Conserved": str(tokens_saved),
            },
            content={
                "error": {
                    "message": f"Airlock Security Violation: {airlock_result.reason}",
                    "type": "airlock_security_violation",
                    "code": "forbidden_prompt",
                    "violation_category": violation_cat,
                    "matched_pattern": airlock_result.matched_pattern,
                    "tokens_conserved": tokens_saved,
                    "scan_time_ms": airlock_result.scan_time_ms,
                    "trace_id": trace_id,
                }
            },
        )

    # Step 2: Resilient Dynamic SLA Routing
    routed_response = await router.route_chat_completion(
        messages=raw_messages,
        model=req.model,
        temperature=req.temperature or 0.7,
        max_tokens=req.max_tokens,
        trace_id=trace_id,
        extra_headers={"X-Trace-ID": trace_id},
    )

    # Step 3: Record Successful Telemetry Audit
    audit = AuditRecord(
        trace_id=trace_id,
        span_id=span_id,
        timestamp=time.time(),
        client_ip=client_ip,
        endpoint="/v1/chat/completions",
        method="POST",
        airlock_passed=True,
        airlock_scan_ms=airlock_result.scan_time_ms,
        model_requested=routed_response.requested_model,
        model_served=routed_response.served_model,
        fallback_triggered=routed_response.fallback_triggered,
        fallback_reason=routed_response.failover_reason,
        status_code=200,
        latency_ms=routed_response.latency_ms,
        prompt_tokens=routed_response.prompt_tokens,
        completion_tokens=routed_response.completion_tokens,
        total_tokens=routed_response.total_tokens,
    )
    telemetry.record_audit(audit)

    # Enrich Response Headers
    response.headers["X-Otari-Model-Served"] = routed_response.served_model
    response.headers["X-Otari-Failover"] = "true" if routed_response.fallback_triggered else "false"
    response.headers["X-Otari-Circuit-State"] = routed_response.circuit_state.value
    response.headers["X-Airlock-Verdict"] = "PASSED"
    response.headers["X-Airlock-Scan-MS"] = str(airlock_result.scan_time_ms)

    # Convert response to OpenAI-compatible dictionary
    raw = routed_response.raw_response
    if hasattr(raw, "model_dump"):
        return raw.model_dump()
    elif isinstance(raw, dict):
        return raw
    return jsonable_encoder(raw)


def run():
    """
    CLI entry point to launch the Uvicorn server process.
    """
    settings = get_settings()
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        workers=settings.WORKERS,
        log_level="info",
        reload=settings.DEBUG,
    )


if __name__ == "__main__":
    run()
