"""
HAIA Agent Framework - Platform Adapter Base
==============================================
Abstract interface for all AI platform adapters.

Every adapter implements two operations:
    Operation 1 (Dispatch): Send a prompt to the platform
    Operation 2 (Collect): Receive the response without modification

Non-cognitive constraint: Adapters do not modify, prioritize, or
sequence prompts based on content. They do not filter, rank, or
evaluate responses. They are transport mechanisms.

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

import hashlib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AdapterResponse:
    """
    Standardized response from any platform adapter.
    Every adapter returns this exact structure regardless of
    the platform's native response format.
    """
    platform_id: str
    platform_model: str
    response_text: str
    response_hash: str = ""
    token_count: int = 0
    latency_ms: int = 0
    success: bool = True
    error_detail: str = ""
    api_confirmation: str = ""
    raw_metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.response_text and not self.response_hash:
            self.response_hash = hashlib.sha256(
                self.response_text.encode("utf-8")
            ).hexdigest()


class PlatformAdapter(ABC):
    """
    Abstract base for all AI platform adapters.

    Each adapter wraps one provider's API and exposes two operations:
        send_prompt()  -> Operation 1: Dispatch
        The return     -> Operation 2: Collect

    The adapter normalizes the provider's response into an AdapterResponse.
    It does not evaluate, rank, or filter any content.
    """

    def __init__(
        self,
        platform_id: str,
        api_key: Optional[str] = None,
        default_model: str = "",
    ):
        self.platform_id = platform_id
        self.api_key = api_key
        self.default_model = default_model

    @abstractmethod
    def send_prompt(
        self,
        prompt: str,
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> AdapterResponse:
        """
        Send a prompt to the platform and return the response.

        This is Operations 1 and 2 combined:
            1. Dispatch: send the prompt exactly as received
            2. Collect: return the response exactly as received

        The adapter does NOT modify the prompt before sending.
        The adapter does NOT filter or evaluate the response.

        Args:
            prompt: Exact prompt text to send (unmodified)
            model: Specific model to use (overrides default)
            system_prompt: Optional system-level instruction
            max_tokens: Maximum response length
            temperature: Sampling temperature

        Returns:
            AdapterResponse with complete, unedited response
        """
        ...

    def health_check(self) -> bool:
        """
        Verify the adapter can connect to its platform.
        Returns True if the platform is reachable and authenticated.
        """
        try:
            response = self.send_prompt(
                prompt="Respond with exactly: OK",
                max_tokens=10,
            )
            return response.success
        except Exception:
            return False

    def _make_error_response(
        self, model: str, error: str, latency_ms: int = 0
    ) -> AdapterResponse:
        """Create a standardized error response."""
        return AdapterResponse(
            platform_id=self.platform_id,
            platform_model=model,
            response_text="",
            success=False,
            error_detail=error,
            latency_ms=latency_ms,
        )
