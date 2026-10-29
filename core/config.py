"""
Configuration management for otari-sentry using Pydantic Settings.
Loads environment variables deterministically with typed fallbacks.
"""

from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application-wide settings.
    Default values reflect Mozilla Otari API gateway standards and strict SLA boundaries.
    """

    # Service Identification
    PROJECT_NAME: str = Field(
        default="otari-sentry",
        description="Name of the service",
    )
    VERSION: str = Field(
        default="1.0.0",
        description="Semantic version of the application",
    )
    ENVIRONMENT: str = Field(
        default="production",
        description="Runtime environment (development, staging, production)",
    )
    DEBUG: bool = Field(
        default=False,
        description="Enable debug mode and verbose logging",
    )

    # Server Configuration
    HOST: str = Field(
        default="0.0.0.0",
        description="Host interface to bind HTTP server",
    )
    PORT: int = Field(
        default=8000,
        description="Port to listen for incoming HTTP traffic",
    )
    WORKERS: int = Field(
        default=1,
        description="Number of Uvicorn worker processes",
    )

    # Mozilla Otari Gateway Credentials & Endpoints
    OTARI_BASE_URL: str = Field(
        default="https://otari.ai/api/v1",
        description="Mozilla Otari API Gateway base URL",
    )
    OTARI_API_KEY: str = Field(
        default="",
        description="Mozilla Otari API Authentication Key",
    )

    # Model Routing Configuration
    PRIMARY_MODEL: str = Field(
        default="alibaba/qwen-3.5-35b-a3b",
        description="Primary high-performance target model",
    )
    FALLBACK_MODEL: str = Field(
        default="meta-llama/llama-3.3-70b-instruct",
        description="Secondary open-weight resilient fallback model",
    )

    # SLA Timeouts & Retry Limits
    PRIMARY_TIMEOUT_SECONDS: float = Field(
        default=12.0,
        description="Strict SLA timeout for primary model execution",
    )
    FALLBACK_TIMEOUT_SECONDS: float = Field(
        default=15.0,
        description="Timeout for secondary fallback model execution",
    )
    MAX_RETRIES: int = Field(
        default=2,
        description="Maximum HTTP client retries before declaring failure",
    )

    # Circuit Breaker Configuration
    CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = Field(
        default=3,
        description="Consecutive failure threshold to trip circuit to OPEN",
    )
    CIRCUIT_BREAKER_RECOVERY_TIME_SECONDS: float = Field(
        default=30.0,
        description="Cool-down duration before attempting HALF_OPEN probe",
    )

    # Airlock Deterministic Security Guardrails
    AIRLOCK_ENABLED: bool = Field(
        default=True,
        description="Enforce sub-10ms deterministic guardrail checks",
    )
    AIRLOCK_MAX_PROMPT_LENGTH: int = Field(
        default=16384,
        description="Maximum allowed character length per individual prompt message",
    )
    AIRLOCK_MAX_TOTAL_TOKENS_ESTIMATE: int = Field(
        default=8192,
        description="Maximum estimated token count across all conversation messages",
    )
    AIRLOCK_STRICT_CREDENTIAL_CHECK: bool = Field(
        default=True,
        description="Strict rejection of private keys, AWS tokens, and secrets",
    )
    AIRLOCK_STRICT_SQL_CHECK: bool = Field(
        default=True,
        description="Strict rejection of SQL injection and table drops",
    )
    AIRLOCK_STRICT_JAILBREAK_CHECK: bool = Field(
        default=True,
        description="Strict rejection of jailbreaks, DAN prompts, and system leaks",
    )

    # Telemetry & Observability
    SERVICE_NAME: str = Field(
        default="otari-sentry",
        description="Service name for OpenTelemetry baggage and tracing",
    )
    SERVICE_VERSION: str = Field(
        default="1.0.0",
        description="Service version tag in telemetry baggage",
    )
    SIMULATE_W3C_BAGGAGE: bool = Field(
        default=True,
        description="Propagate and validate W3C baggage headers",
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache()
def get_settings() -> Settings:
    """
    Retrieve cached application settings instance.
    """
    return Settings()
