"""
HAIA Agent Framework - Google Gemini Adapter
=============================================
Transport adapter for the Google Generative AI API.
Sends prompts and collects responses without modification.

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

import os
import time
from typing import Optional

from . import AdapterResponse, PlatformAdapter


class GoogleAdapter(PlatformAdapter):
    """
    Adapter for Google's Gemini models via the Generative AI API.

    Requires:
        pip install google-generativeai
        GOOGLE_API_KEY environment variable (or pass api_key)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        default_model: str = "gemini-2.0-flash",
    ):
        super().__init__(
            platform_id="google_gemini",
            api_key=api_key or os.environ.get("GOOGLE_API_KEY"),
            default_model=default_model,
        )
        self._configured = False

    def _configure(self):
        """Lazy configuration of the Google GenAI SDK."""
        if not self._configured:
            try:
                import google.generativeai as genai
            except ImportError:
                raise ImportError(
                    "Google GenAI SDK not installed. Run: pip install google-generativeai"
                )
            if not self.api_key:
                raise ValueError(
                    "GOOGLE_API_KEY not set. Provide api_key or set environment variable."
                )
            genai.configure(api_key=self.api_key)
            self._configured = True

    def send_prompt(
        self,
        prompt: str,
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> AdapterResponse:
        """
        Send prompt to Gemini via the Generative AI API.
        Returns complete, unedited response.
        """
        model_name = model or self.default_model
        start_time = time.monotonic()

        try:
            self._configure()
            import google.generativeai as genai

            generation_config = genai.types.GenerationConfig(
                max_output_tokens=max_tokens,
                temperature=temperature,
            )

            model_kwargs = {}
            if system_prompt:
                model_kwargs["system_instruction"] = system_prompt

            gemini_model = genai.GenerativeModel(
                model_name=model_name,
                generation_config=generation_config,
                **model_kwargs,
            )

            response = gemini_model.generate_content(prompt)

            latency_ms = int((time.monotonic() - start_time) * 1000)

            # Extract response text without modification
            response_text = ""
            if response.parts:
                response_text = "".join(
                    part.text for part in response.parts if hasattr(part, "text")
                )

            # Token counting (available in usage_metadata)
            token_count = 0
            raw_meta = {}
            if hasattr(response, "usage_metadata") and response.usage_metadata:
                meta = response.usage_metadata
                token_count = getattr(meta, "candidates_token_count", 0) or 0
                raw_meta = {
                    "input_tokens": getattr(meta, "prompt_token_count", 0) or 0,
                    "output_tokens": token_count,
                    "total_tokens": getattr(meta, "total_token_count", 0) or 0,
                }

            return AdapterResponse(
                platform_id=self.platform_id,
                platform_model=model_name,
                response_text=response_text,
                token_count=token_count,
                latency_ms=latency_ms,
                success=True,
                api_confirmation=f"gemini_{int(time.time())}",
                raw_metadata=raw_meta,
            )

        except Exception as e:
            latency_ms = int((time.monotonic() - start_time) * 1000)
            return self._make_error_response(
                model=model_name,
                error=str(e),
                latency_ms=latency_ms,
            )
