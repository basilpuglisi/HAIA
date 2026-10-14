"""
HAIA Agent Framework - OpenAI ChatGPT Adapter
===============================================
Transport adapter for the OpenAI Chat Completions API.
Sends prompts and collects responses without modification.

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

import os
import time
from typing import Optional

from . import AdapterResponse, PlatformAdapter


class OpenAIAdapter(PlatformAdapter):
    """
    Adapter for OpenAI's ChatGPT models via the Chat Completions API.

    Requires:
        pip install openai
        OPENAI_API_KEY environment variable (or pass api_key)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        default_model: str = "gpt-4o",
    ):
        super().__init__(
            platform_id="openai_chatgpt",
            api_key=api_key or os.environ.get("OPENAI_API_KEY"),
            default_model=default_model,
        )
        self._client = None

    def _get_client(self):
        """Lazy initialization of the OpenAI client."""
        if self._client is None:
            try:
                import openai
            except ImportError:
                raise ImportError(
                    "OpenAI SDK not installed. Run: pip install openai"
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
        temperature: float = 0.7,
    ) -> AdapterResponse:
        """
        Send prompt to ChatGPT via the Chat Completions API.
        Returns complete, unedited response.
        """
        model = model or self.default_model
        start_time = time.monotonic()

        try:
            client = self._get_client()

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )

            latency_ms = int((time.monotonic() - start_time) * 1000)

            # Extract response text without modification
            choice = response.choices[0] if response.choices else None
            response_text = choice.message.content if choice else ""

            return AdapterResponse(
                platform_id=self.platform_id,
                platform_model=response.model,
                response_text=response_text or "",
                token_count=response.usage.completion_tokens if response.usage else 0,
                latency_ms=latency_ms,
                success=True,
                api_confirmation=response.id,
                raw_metadata={
                    "input_tokens": response.usage.prompt_tokens if response.usage else 0,
                    "output_tokens": response.usage.completion_tokens if response.usage else 0,
                    "finish_reason": choice.finish_reason if choice else None,
                },
            )

        except Exception as e:
            latency_ms = int((time.monotonic() - start_time) * 1000)
            return self._make_error_response(
                model=model,
                error=str(e),
                latency_ms=latency_ms,
            )
