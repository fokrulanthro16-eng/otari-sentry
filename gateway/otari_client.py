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
        timeout: float = 12.0,
        extra_headers: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> Any:
        """
        Execute chat completion against Mozilla Otari with strict per-request SLA timeout.
        """
        headers = {
            "User-Agent": "otari-sentry/1.0.0",
        }
        if extra_headers:
            headers.update(extra_headers)

        req_kwargs: Dict[str, Any] = {
            "model": model,
            "messages": messages,
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
                "Otari gateway request timed out after %.2fs for model '%s': %s",
                timeout,
                model,
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
            is_transient = exc.status_code in {408, 429, 500, 502, 503, 504}
            logger.warning(
                "Otari gateway returned HTTP %d for model '%s': %s",
                exc.status_code,
                model,
                exc,
            )
            raise OtariGatewayError(
                message=f"Otari gateway error HTTP {exc.status_code}: {exc.message}",
                status_code=exc.status_code,
                is_transient=is_transient,
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
                is_transient=False,
                original_error=exc,
            ) from exc

    async def close(self) -> None:
        """
        Gracefully shut down the underlying async HTTP client session.
        """
        await self._client.close()
