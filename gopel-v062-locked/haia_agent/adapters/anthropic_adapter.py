"""
HAIA Agent Framework - Anthropic Claude Adapter
=================================================
Transport adapter for the Anthropic Messages API.
Sends prompts and collects responses without modification.

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

import os
import time
from typing import Optional

from . import AdapterResponse, PlatformAdapter


class AnthropicAdapter(PlatformAdapter):
    """
    Adapter for Anthropic's Claude models via the Messages API.

    Requires:
        pip install anthropic
        ANTHROPIC_API_KEY environment variable (or pass api_key)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        default_model: str = "claude-sonnet-4-5-20250929",
    ):
        super().__init__(
            platform_id="anthropic_claude",
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"),
            default_model=default_model,
        )
        self._client = None

    def _get_client(self):
        """Lazy initialization of the Anthropic client."""
        if self._client is None:
            try:
                import anthropic
            except ImportError:
                raise ImportError(
                    "Anthropic SDK not installed. Run: pip install anthropic"
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
        temperature: float = 0.7,
    ) -> AdapterResponse:
        """
        Send prompt to Claude via the Messages API.
        Returns complete, unedited response.
        """
        model = model or self.default_model
        start_time = time.monotonic()

        try:
            client = self._get_client()

            kwargs = {
                "model": model,
                "max_tokens": max_tokens,
                "temperature": temperature,
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

            return AdapterResponse(
                platform_id=self.platform_id,
                platform_model=response.model,
                response_text=response_text,
                token_count=response.usage.output_tokens if response.usage else 0,
                latency_ms=latency_ms,
                success=True,
                api_confirmation=response.id,
                raw_metadata={
                    "input_tokens": response.usage.input_tokens if response.usage else 0,
                    "output_tokens": response.usage.output_tokens if response.usage else 0,
                    "stop_reason": response.stop_reason,
                },
            )

        except Exception as e:
            latency_ms = int((time.monotonic() - start_time) * 1000)
            return self._make_error_response(
                model=model,
                error=str(e),
                latency_ms=latency_ms,
            )
