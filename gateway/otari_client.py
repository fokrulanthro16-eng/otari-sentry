"""
Resilient OpenAI-compatible client targeted directly to Mozilla Otari Hosted AI Gateway.
Handles async communication, strict timeouts, authentication, and HTTP error normalization.
"""

import logging
from typing import Any, Dict, List, Optional
import httpx
from openai import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    AsyncOpenAI,
    InternalServerError,
    OpenAIError,
    RateLimitError,
)

logger = logging.getLogger("otari-sentry.gateway.client")


def normalize_otari_model(model_name: str) -> str:
    """
    Standardize model strings to match Mozilla Otari catalog identifiers.
    E.g. meta-llama/llama-3.3-70b-instruct -> meta/llama-3.3-70b-instruct
    """
    if not model_name:
        return "alibaba/qwen-3.5-35b-a3b"
    m = model_name.strip()
    if m.startswith("meta-llama/"):
        return m.replace("meta-llama/", "meta/", 1)
    return m


class OtariGatewayError(Exception):
    """Base exception for all Otari Gateway interaction failures."""

    def __init__(
        self,
        message: str,
        status_code: int = 502,
        is_transient: bool = False,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.is_transient = is_transient
        self.original_error = original_error


class OtariClient:
    """
    Async client for Mozilla Otari Hosted AI Gateway (OpenAI compatible).
    """

    def __init__(
        self,
        base_url: str = "https://otari.ai/api/v1",
        api_key: str = "",
        max_retries: int = 2,
    ):
        self.base_url = base_url.rstrip("/")
        # Provide default placeholder key if empty to permit client initialization
        self.api_key = api_key if api_key else "otari-anonymous-key"
        self.max_retries = max_retries

        self._client = AsyncOpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            max_retries=self.max_retries,
        )

    async def create_chat_completion(
        self,
        model: str,
        messages: List[Dict[str, Any]],
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        timeout: float = 30.0,
        extra_headers: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> Any:
        """
        Execute chat completion against Mozilla Otari with strict per-request SLA timeout.
        Standardizes model identifier and sanitizes message payloads.
        """
        target_model = normalize_otari_model(model)

        headers = {
            "User-Agent": "otari-sentry/1.0.0",
        }
        if extra_headers:
            headers.update(extra_headers)

        # Sanitize messages to strictly comply with OpenAI/Otari chat schema
        sanitized_messages: List[Dict[str, str]] = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if isinstance(content, list):
                # Flatten multi-part content if needed
                text_parts = [
                    p.get("text", "")
                    for p in content
                    if isinstance(p, dict) and p.get("type") == "text"
                ]
                content = " ".join(text_parts) if text_parts else str(content)
            elif content is None:
                content = ""
            sanitized_messages.append({"role": str(role), "content": str(content)})

        req_kwargs: Dict[str, Any] = {
            "model": target_model,
            "messages": sanitized_messages,
            "temperature": temperature,
            "timeout": timeout,
            "extra_headers": headers,
        }
        if max_tokens is not None:
            req_kwargs["max_tokens"] = max_tokens
        req_kwargs.update(kwargs)

        try:
            response = await self._client.chat.completions.create(**req_kwargs)
            return response

        except APITimeoutError as exc:
            logger.warning(
                "Otari gateway request timed out after %.2fs for model '%s' (target: '%s'): %s",
                timeout,
                model,
                target_model,
                exc,
            )
            raise OtariGatewayError(
                message=f"Gateway timeout exceeded ({timeout}s) for model {model}",
                status_code=504,
                is_transient=True,
                original_error=exc,
            ) from exc

        except RateLimitError as exc:
            logger.warning(
                "Otari gateway rate limit (429) hit for model '%s': %s",
                model,
                exc,
            )
            raise OtariGatewayError(
                message=f"Rate limit exceeded (429) on Otari gateway for model {model}",
                status_code=429,
                is_transient=True,
                original_error=exc,
            ) from exc

        except InternalServerError as exc:
            logger.warning(
                "Otari gateway 5xx internal error for model '%s': %s",
                model,
                exc,
            )
            raise OtariGatewayError(
                message=f"Otari gateway internal server error (5xx) for model {model}",
                status_code=502,
                is_transient=True,
                original_error=exc,
            ) from exc

        except APIStatusError as exc:
            # 400 (unsupported model, cold start, bad parameter) and 408/429/5xx are eligible for failover
            is_failover_eligible = exc.status_code in {400, 404, 408, 429, 500, 502, 503, 504}
            logger.warning(
                "Otari gateway returned HTTP %d for model '%s' (target: '%s'): %s",
                exc.status_code,
                model,
                target_model,
                exc.message,
            )
            raise OtariGatewayError(
                message=f"Otari gateway error HTTP {exc.status_code}: {exc.message}",
                status_code=exc.status_code,
                is_transient=is_failover_eligible,
                original_error=exc,
            ) from exc

        except APIConnectionError as exc:
            logger.warning(
                "Otari gateway network connection failed for model '%s': %s",
                model,
                exc,
            )
            raise OtariGatewayError(
                message=f"Cannot establish connection to Otari gateway at {self.base_url}",
                status_code=503,
                is_transient=True,
                original_error=exc,
            ) from exc

        except OpenAIError as exc:
            logger.error("Unhandled OpenAI SDK error on Otari client: %s", exc)
            raise OtariGatewayError(
                message=f"Unexpected Otari gateway client error: {str(exc)}",
                status_code=500,
                is_transient=True,
                original_error=exc,
            ) from exc

    async def close(self) -> None:
        """
        Gracefully shut down the underlying async HTTP client session.
        """
        await self._client.close()
