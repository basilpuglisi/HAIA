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

v0.6.3 (step 26, addendum 15; S2 / Q6 Option A):
    - temperature defaults to None: no temperature is sent unless the
      operator sets one, and the provider's own default applies.
    - An explicit temperature is refused, before any SDK call, where the
      SDK or the configured model does not accept it (accepts_temperature).
      The refusal is an error response marked UNSUPPORTED_CONFIGURATION.
    - Provider adapters have no default model (require_explicit_model).

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


UNSUPPORTED_CONFIGURATION = "UNSUPPORTED_CONFIGURATION"
INCOMPLETE_RESPONSE = "INCOMPLETE_RESPONSE"


def require_explicit_model(
    adapter_name: str, model: Optional[str], default_model: Optional[str]
) -> str:
    """
    v0.6.3: a provider adapter's model is set explicitly in configuration.

    There is no default model and no silent fallback. Raises ValueError
    when no model is given, or when model and default_model disagree.
    """
    if model and default_model and model != default_model:
        raise ValueError(
            f"{adapter_name}: model={model!r} and default_model={default_model!r} "
            f"disagree. Set the model once, explicitly."
        )
    resolved = model or default_model
    if not resolved or not str(resolved).strip():
        raise ValueError(
            f"{adapter_name}: no model configured. v0.6.3 has no default model; "
            f"set the model explicitly in configuration."
        )
    return resolved


class PlatformAdapter(ABC):
    """
    Abstract base for all AI platform adapters.

    Each adapter wraps one provider's API and exposes two operations:
        send_prompt()  -> Operation 1: Dispatch
        The return     -> Operation 2: Collect

    The adapter normalizes the provider's response into an AdapterResponse.
    It does not evaluate, rank, or filter any content.

    accepts_temperature: whether an explicit temperature may be sent to
    this adapter's SDK and model (v0.6.3, S2b).
    """

    accepts_temperature: bool = True

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
        temperature: Optional[float] = None,
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
            temperature: Sampling temperature, or None (v0.6.3 default) to
                send none and leave the provider's default in effect

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

    def _make_unsupported_configuration_response(
        self, model: str, reason: str
    ) -> AdapterResponse:
        """v0.6.3: refusal of an unsupported configuration, before any SDK call."""
        return self._make_error_response(
            model=model,
            error=f"{UNSUPPORTED_CONFIGURATION}: {reason}",
            latency_ms=0,
        )

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
