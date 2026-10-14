"""
HAIA Agent Framework - Anthropic Claude Adapter
=================================================
Transport adapter for the Anthropic Messages API.
Sends prompts and collects responses without modification.

v0.6.3 (step 26, addendum 15; S2 / Q6 Option A):
    - Pinned SDK: anthropic>=1.13,<2 (requirements_v0_6_3.txt).
    - messages.create(model, max_tokens, messages, system if given).
      The Anthropic SDK 1.x messages.create has no temperature parameter,
      so an explicit temperature is refused before any SDK call, as an
      UNSUPPORTED_CONFIGURATION error response.
    - No default model: the model is set explicitly in configuration.
    - A response that stops for any reason other than end_turn or
      stop_sequence (for example max_tokens or refusal) is not reported
      as a success. The text received is kept verbatim.

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


class AnthropicAdapter(PlatformAdapter):
    """
    Adapter for Anthropic's Claude models via the Messages API.

    Requires:
        pip install "anthropic>=1.13,<2"
        ANTHROPIC_API_KEY environment variable (or pass api_key)
        An explicit model, for example AnthropicAdapter(model="...")
    """

    # Anthropic SDK 1.x messages.create accepts no temperature (S2b).
    accepts_temperature = False

    # Stop reasons that mark a complete response.
    COMPLETE_STOP_REASONS = ("end_turn", "stop_sequence")

    def __init__(
        self,
        api_key: Optional[str] = None,
        default_model: Optional[str] = None,
        *,
        model: Optional[str] = None,
    ):
        super().__init__(
            platform_id="anthropic_claude",
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"),
            default_model=require_explicit_model("AnthropicAdapter", model, default_model),
        )
        self._client = None

    def _get_client(self):
        """Lazy initialization of the Anthropic client."""
        if self._client is None:
            try:
                import anthropic
            except ImportError:
                raise ImportError(
                    "Anthropic SDK not installed. Run: pip install \"anthropic>=1.13,<2\""
                )
            if not self.api_key:
                raise ValueError(
                    "ANTHROPIC_API_KEY not set. Provide api_key or set environment variable."
                )
            self._client = anthropic.Anthropic(api_key=self.api_key)
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
        Send prompt to Claude via the Messages API.
        Returns complete, unedited response.
        """
        model = model or self.default_model

        # S2b: refuse an explicit temperature before any SDK call.
        if temperature is not None:
            return self._make_unsupported_configuration_response(
                model=model,
                reason=(
                    f"temperature={temperature} was set, but the Anthropic SDK 1.x "
                    f"messages.create accepts no temperature. Leave temperature unset "
                    f"for this seat."
                ),
            )

        start_time = time.monotonic()

        try:
            client = self._get_client()

            kwargs = {
                "model": model,
                "max_tokens": max_tokens,
                "messages": [{"role": "user", "content": prompt}],
            }
            if system_prompt:
                kwargs["system"] = system_prompt

            response = client.messages.create(**kwargs)

            latency_ms = int((time.monotonic() - start_time) * 1000)

            # Extract text from content blocks without modification
            response_text = ""
            for block in response.content:
                if block.type == "text":
                    response_text += block.text

            stop_reason = getattr(response, "stop_reason", None)
            complete = stop_reason in self.COMPLETE_STOP_REASONS
            usage = getattr(response, "usage", None)

            return AdapterResponse(
                platform_id=self.platform_id,
                platform_model=getattr(response, "model", "") or model,
                response_text=response_text,
                token_count=usage.output_tokens if usage else 0,
                latency_ms=latency_ms,
                success=complete,
                error_detail="" if complete else (
                    f"{INCOMPLETE_RESPONSE}: stop_reason={stop_reason}"
                ),
                api_confirmation=response.id,
                raw_metadata={
                    "input_tokens": usage.input_tokens if usage else 0,
                    "output_tokens": usage.output_tokens if usage else 0,
                    "stop_reason": stop_reason,
                },
            )

        except Exception as e:
            latency_ms = int((time.monotonic() - start_time) * 1000)
            return self._make_error_response(
                model=model,
                error=str(e),
                latency_ms=latency_ms,
            )
