"""
LLM factory – single place that builds the ChatOpenAI client for all agents.

Priority:
  1. OpenRouter  (OPENROUTER_API_KEY set)  → any free/paid OSS model
  2. OpenAI      (OPENAI_API_KEY set)       → GPT-4o-mini default
  3. None        → returns None; agents fall back to heuristics + ML

OpenRouter is 100 % compatible with the OpenAI SDK – we just override
`base_url` and `api_key`.  Extra HTTP headers (HTTP-Referer, X-Title)
are recommended by OpenRouter for attribution / rate-limit tracking.
"""
from __future__ import annotations

from typing import Optional
import structlog

logger = structlog.get_logger(__name__)


def get_llm(
    temperature: Optional[float] = None,
    max_tokens: int = 800,
):
    """
    Return a configured ChatOpenAI instance for the active provider,
    or None when no LLM key is configured.

    Parameters
    ----------
    temperature : float | None
        Override the default temperature from settings.
    max_tokens : int
        Maximum tokens in the LLM response.
    """
    from app.core.config import settings  # local import avoids circular deps

    provider = settings.llm_provider

    if provider == "none":
        logger.debug(
            "No LLM API key configured – skipping LLM layer "
            "(set OPENROUTER_API_KEY or OPENAI_API_KEY to enable)"
        )
        return None

    try:
        from langchain_openai import ChatOpenAI

        temp = temperature if temperature is not None else settings.OPENAI_TEMPERATURE

        if provider == "openrouter":
            # OpenRouter requires two extra headers for proper routing / analytics
            default_headers = {
                "HTTP-Referer": settings.OPENROUTER_SITE_URL,
                "X-Title":      settings.OPENROUTER_SITE_NAME,
            }
            llm = ChatOpenAI(
                model       = settings.OPENROUTER_MODEL,
                api_key     = settings.OPENROUTER_API_KEY,
                base_url    = settings.OPENROUTER_BASE_URL,
                temperature = temp,
                max_tokens  = max_tokens,
                default_headers = default_headers,
            )
            logger.debug(
                "LLM provider: OpenRouter",
                model=settings.OPENROUTER_MODEL,
            )

        else:  # openai
            llm = ChatOpenAI(
                model       = settings.OPENAI_MODEL,
                api_key     = settings.OPENAI_API_KEY,
                base_url    = settings.OPENAI_BASE_URL,
                temperature = temp,
                max_tokens  = max_tokens,
            )
            logger.debug(
                "LLM provider: OpenAI",
                model=settings.OPENAI_MODEL,
            )

        return llm

    except Exception as e:
        logger.warning("Failed to initialise LLM client", error=str(e))
        return None


def llm_provider_info() -> dict:
    """Return a dict describing the currently active LLM provider (for /health)."""
    from app.core.config import settings

    provider = settings.llm_provider
    if provider == "openrouter":
        return {
            "provider": "openrouter",
            "model":    settings.OPENROUTER_MODEL,
            "base_url": settings.OPENROUTER_BASE_URL,
        }
    if provider == "openai":
        return {
            "provider": "openai",
            "model":    settings.OPENAI_MODEL,
            "base_url": settings.OPENAI_BASE_URL,
        }
    return {"provider": "none", "model": None}
