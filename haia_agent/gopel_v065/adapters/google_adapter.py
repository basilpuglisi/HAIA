"""
HAIA Agent Framework - Google Gemini Adapter
=============================================
Transport adapter for the Google Gen AI SDK (google-genai).
Sends prompts and collects responses without modification.

v0.6.3 (step 26, addendum 15; S2 / Q6 Option A):
    - Moves from the deprecated google-generativeai package to google-genai,
      pinned google-genai>=2.30,<3 (requirements_v0_6_3.txt):
      Client(api_key).models.generate_content(model, contents,
      config=types.GenerateContentConfig(...)).
    - Records the provider's real response_id as api_confirmation,
      replacing the timestamp-based value of v0.6.2.
    - temperature is sent only when the operator sets one;
      accepts_temperature=False (configuration) refuses it before any call.
    - No default model: the model is set explicitly in configuration.
    - A finish reason other than STOP is not reported as a success.
      The text received is kept verbatim.

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


def _finish_reason_name(value) -> Optional[str]:
    """Normalize a google-genai FinishReason (enum or string) to its name."""
    if value is None:
        return None
    return str(getattr(value, "value", value))


class GoogleAdapter(PlatformAdapter):
    """
    Adapter for Google's Gemini models via the Google Gen AI SDK.

    Requires:
        pip install "google-genai>=2.30,<3"
        GOOGLE_API_KEY environment variable (or pass api_key)
        An explicit model, for example GoogleAdapter(model="...")
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
            platform_id="google_gemini",
            api_key=api_key or os.environ.get("GOOGLE_API_KEY"),
            default_model=require_explicit_model("GoogleAdapter", model, default_model),
        )
        self.accepts_temperature = accepts_temperature
        self._client = None

    def _get_client(self):
        """Lazy initialization of the google-genai client."""
        if self._client is None:
            try:
                from google import genai
            except ImportError:
                raise ImportError(
                    "Google Gen AI SDK not installed. Run: pip install \"google-genai>=2.30,<3\""
                )
            if not self.api_key:
                raise ValueError(
                    "GOOGLE_API_KEY not set. Provide api_key or set environment variable."
                )
            self._client = genai.Client(api_key=self.api_key)
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
        Send prompt to Gemini via models.generate_content.
        Returns complete, unedited response.
        """
        model_name = model or self.default_model

        # S2b: refuse an explicit temperature the configured model does not accept.
        if temperature is not None and not self.accepts_temperature:
            return self._make_unsupported_configuration_response(
                model=model_name,
                reason=(
                    f"temperature={temperature} was set, but model {model_name!r} is "
                    f"configured as not accepting temperature."
                ),
            )

        start_time = time.monotonic()

        try:
            client = self._get_client()
            from google.genai import types

            config_kwargs = {"max_output_tokens": max_tokens}
            if temperature is not None:
                config_kwargs["temperature"] = temperature
            if system_prompt:
                config_kwargs["system_instruction"] = system_prompt

            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=types.GenerateContentConfig(**config_kwargs),
            )

            latency_ms = int((time.monotonic() - start_time) * 1000)

            # Extract response text without modification
            response_text = getattr(response, "text", None) or ""

            candidates = getattr(response, "candidates", None) or []
            finish_reason = (
                _finish_reason_name(getattr(candidates[0], "finish_reason", None))
                if candidates else None
            )
            complete = finish_reason == "STOP"

            # Token counting (available in usage_metadata)
            token_count = 0
            raw_meta = {"finish_reason": finish_reason}
            meta = getattr(response, "usage_metadata", None)
            if meta:
                token_count = getattr(meta, "candidates_token_count", 0) or 0
                raw_meta.update({
                    "input_tokens": getattr(meta, "prompt_token_count", 0) or 0,
                    "output_tokens": token_count,
                    "total_tokens": getattr(meta, "total_token_count", 0) or 0,
                })

            return AdapterResponse(
                platform_id=self.platform_id,
                platform_model=getattr(response, "model_version", None) or model_name,
                response_text=response_text,
                token_count=token_count,
                latency_ms=latency_ms,
                success=complete,
                error_detail="" if complete else (
                    f"{INCOMPLETE_RESPONSE}: finish_reason={finish_reason}"
                ),
                api_confirmation=getattr(response, "response_id", None) or "",
                raw_metadata=raw_meta,
            )

        except Exception as e:
            latency_ms = int((time.monotonic() - start_time) * 1000)
            return self._make_error_response(
                model=model_name,
                error=str(e),
                latency_ms=latency_ms,
            )
