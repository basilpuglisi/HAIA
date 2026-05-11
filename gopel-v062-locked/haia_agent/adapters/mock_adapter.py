"""
HAIA Agent Framework - Mock Platform Adapter
==============================================
Deterministic mock adapter for testing the full pipeline
without requiring API keys. Returns configurable responses.

Used for:
    - Unit and integration testing
    - Pipeline validation before going live
    - Demonstration and simulation

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Optional

from . import AdapterResponse, PlatformAdapter


class MockAdapter(PlatformAdapter):
    """
    Mock adapter that returns configurable responses.
    No API calls. No network. Fully deterministic.

    Can be configured to:
        - Return a fixed response
        - Return different responses per call (round-robin)
        - Simulate errors and timeouts
        - Simulate variable latency
    """

    def __init__(
        self,
        platform_id: str = "mock_platform",
        default_model: str = "mock-v1",
        responses: Optional[list[str]] = None,
        simulate_error: bool = False,
        simulate_latency_ms: int = 50,
    ):
        super().__init__(
            platform_id=platform_id,
            api_key="mock_key",
            default_model=default_model,
        )
        self._responses = responses or [
            f"Mock response from {platform_id}. "
            "This is a deterministic test response for pipeline validation."
        ]
        self._call_count = 0
        self._simulate_error = simulate_error
        self._simulate_latency_ms = simulate_latency_ms

    def send_prompt(
        self,
        prompt: str,
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> AdapterResponse:
        """Return a mock response. No network call."""
        model = model or self.default_model

        # Simulate latency
        if self._simulate_latency_ms > 0:
            time.sleep(self._simulate_latency_ms / 1000)

        latency_ms = self._simulate_latency_ms

        # Simulate error if configured
        if self._simulate_error:
            return self._make_error_response(
                model=model,
                error="Simulated platform error for testing",
                latency_ms=latency_ms,
            )

        # Round-robin through configured responses
        response_text = self._responses[self._call_count % len(self._responses)]
        self._call_count += 1

        return AdapterResponse(
            platform_id=self.platform_id,
            platform_model=model,
            response_text=response_text,
            token_count=len(response_text.split()) * 2,
            latency_ms=latency_ms,
            success=True,
            api_confirmation=f"mock_{uuid.uuid4().hex[:8]}",
            raw_metadata={"call_number": self._call_count},
        )

    def health_check(self) -> bool:
        """Mock health check always returns True unless error mode."""
        return not self._simulate_error
