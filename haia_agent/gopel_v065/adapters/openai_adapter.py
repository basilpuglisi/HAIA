"""
HAIA Agent Framework - OpenAI ChatGPT Adapter
===============================================
Transport adapter for the OpenAI Chat Completions API.
Sends prompts and collects responses without modification.

v0.6.3 (step 26, addendum 15; S2 / Q6 Option A):
    - Pinned SDK: openai>=3.30,<4 (requirements_v0_6_3.txt).
    - chat.completions.create with max_completion_tokens; temperature is
      sent only when the operator sets one.
    - accepts_temperature=False (configuration) marks a model that does
      not accept temperature: an explicit temperature is then refused
      before any SDK call, as an UNSUPPORTED_CONFIGURATION error response.
    - No default model: the model is set explicitly in configuration.
    - A finish_reason other than "stop", or a refusal, is not reported as
      a success. The text received is kept verbatim.

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

import os
import time
from typing import Optional

from . import (
    INCOMPLETE_RESPONSE,
    AdapterResponse,
    PlatformAdapter,
    require_explicit_model,
)


class OpenAIAdapter(PlatformAdapter):
    """
    Adapter for OpenAI's ChatGPT models via the Chat Completions API.

    Requires:
        pip install "openai>=3.30,<4"
        OPENAI_API_KEY environment variable (or pass api_key)
        An explicit model, for example OpenAIAdapter(model="...")
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        default_model: Optional[str] = None,
        *,
        model: Optional[str] = None,
        accepts_temperature: bool = True,
    ):
        super().__init__(
            platform_id="openai_chatgpt",
            api_key=api_key or os.environ.get("OPENAI_API_KEY"),
            default_model=require_explicit_model("OpenAIAdapter", model, default_model),
        )
        self.accepts_temperature = accepts_temperature
        self._client = None

    def _get_client(self):
        """Lazy initialization of the OpenAI client."""
        if self._client is None:
            try:
                import openai
            except ImportError:
                raise ImportError(
                    "OpenAI SDK not installed. Run: pip install \"openai>=3.30,<4\""
                )
            if not self.api_key:
                raise ValueError(
                    "OPENAI_API_KEY not set. Provide api_key or set environment variable."
                )
            self._client = openai.OpenAI(api_key=self.api_key)
        return self._client

    def send_prompt(
        self,
        prompt: str,
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: Optional[float] = None,
    ) -> AdapterResponse:
        """
        Send prompt to ChatGPT via the Chat Completions API.
        Returns complete, unedited response.
        """
        model = model or self.default_model

        # S2b: refuse an explicit temperature the configured model does not accept.
        if temperature is not None and not self.accepts_temperature:
            return self._make_unsupported_configuration_response(
                model=model,
                reason=(
                    f"temperature={temperature} was set, but model {model!r} is "
                    f"configured as not accepting temperature."
                ),
            )

        start_time = time.monotonic()

        try:
            client = self._get_client()

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            kwargs = {
                "model": model,
                "messages": messages,
                "max_completion_tokens": max_tokens,
            }
            if temperature is not None:
                kwargs["temperature"] = temperature

            response = client.chat.completions.create(**kwargs)

            latency_ms = int((time.monotonic() - start_time) * 1000)

            # Extract response text without modification
            choice = response.choices[0] if response.choices else None
            message = choice.message if choice else None
            response_text = (message.content if message else "") or ""
            refusal = getattr(message, "refusal", None) if message else None
            finish_reason = choice.finish_reason if choice else None

            complete = finish_reason == "stop" and not refusal
            if complete:
                error_detail = ""
            elif refusal:
                error_detail = (
                    f"{INCOMPLETE_RESPONSE}: refusal (finish_reason={finish_reason}): {refusal}"
                )
            else:
                error_detail = f"{INCOMPLETE_RESPONSE}: finish_reason={finish_reason}"

            usage = getattr(response, "usage", None)
            return AdapterResponse(
                platform_id=self.platform_id,
                platform_model=getattr(response, "model", "") or model,
                response_text=response_text,
                token_count=usage.completion_tokens if usage else 0,
                latency_ms=latency_ms,
                success=complete,
                error_detail=error_detail,
                api_confirmation=response.id,
                raw_metadata={
                    "input_tokens": usage.prompt_tokens if usage else 0,
                    "output_tokens": usage.completion_tokens if usage else 0,
                    "finish_reason": finish_reason,
                    "refusal": refusal,
                },
            )

        except Exception as e:
            latency_ms = int((time.monotonic() - start_time) * 1000)
            return self._make_error_response(
                model=model,
                error=str(e),
                latency_ms=latency_ms,
            )
