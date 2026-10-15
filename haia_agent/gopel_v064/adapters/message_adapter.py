"""
HAIA Agent Framework - Message Adapters
=======================================
GOPEL v0.6.4, Team Gate (HAIA_Update_Plan_v4, Part C2).

The channel sends a frozen list of chat messages (and any images) to one
platform and collects the reply unaltered. A MessageAdapter is the
transport for one platform. It never reads, ranks, edits, or judges the
text it carries.

    MessageAdapter            the interface the channel calls
    CallableMessageAdapter    wraps a call the hosting process supplies:
                              call(model, messages, images, timeout) returns
                              {"text", "response_id", "stop_reason",
                               "completed", "tokens"}; it is where provider
                              keys are read, inside the hosting process
    MessageMockAdapter        a stand-in for tests: fixed text, a respond
                              callable, or an exception; every call logged

Author: Basil C. Puglisi, MPA
License: Open publication for public infrastructure
"""

from __future__ import annotations

import copy
import time
from abc import ABC, abstractmethod
from typing import Callable, Optional, Union

from . import AdapterResponse


class MessageAdapter(ABC):
    """Transport for one platform: frozen messages out, the reply back unaltered."""

    accepts_temperature: bool = True

    def __init__(self, platform_id: str, service: str = ""):
        if not isinstance(platform_id, str) or not platform_id:
            raise ValueError("A message adapter needs a platform_id.")
        self.platform_id = platform_id
        self.service = service or platform_id

    @abstractmethod
    def send_messages(
        self,
        model: str,
        messages: list,
        images: tuple = (),
        timeout: Optional[float] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> AdapterResponse:
        """Send the messages once and return the reply unaltered."""


def _response(platform_id: str, model: str, reply: dict, started: float) -> AdapterResponse:
    text = reply.get("text")
    meta = {
        "stop_reason": reply.get("stop_reason"),
        "completed": bool(reply.get("completed", True)),
    }
    tokens = reply.get("tokens")
    return AdapterResponse(
        platform_id=platform_id,
        platform_model=model,
        response_text=text if isinstance(text, str) else "",
        token_count=tokens if isinstance(tokens, int) and not isinstance(tokens, bool) and tokens >= 0 else 0,
        latency_ms=int((time.monotonic() - started) * 1000),
        success=isinstance(text, str),
        error_detail="" if isinstance(text, str) else "the call returned no text",
        api_confirmation=str(reply.get("response_id") or ""),
        raw_metadata=meta,
    )


def _failure(platform_id: str, model: str, err: BaseException, started: float) -> AdapterResponse:
    return AdapterResponse(
        platform_id=platform_id,
        platform_model=model,
        response_text="",
        latency_ms=int((time.monotonic() - started) * 1000),
        success=False,
        error_detail=f"{type(err).__name__}: {str(err)[:500]}",
        raw_metadata={"stop_reason": None, "completed": False},
    )


class CallableMessageAdapter(MessageAdapter):
    """
    Wraps a call supplied by the process that hosts GOPEL.

    call(model, messages, images, timeout) returns a dict with "text" and,
    when known, "response_id", "stop_reason", "completed", and "tokens".
    An exception is recorded as a failed call; it is never retried here.
    """

    def __init__(self, platform_id: str, call: Callable, service: str = ""):
        super().__init__(platform_id, service or getattr(call, "service", ""))
        if not callable(call):
            raise ValueError("CallableMessageAdapter needs a callable.")
        self._call = call

    def send_messages(self, model, messages, images=(), timeout=None, max_tokens=None, temperature=None):
        started = time.monotonic()
        try:
            reply = self._call(model, messages, images, timeout)
        except Exception as err:      # recorded, never passed over
            return _failure(self.platform_id, model, err, started)
        if not isinstance(reply, dict):
            return _failure(self.platform_id, model, TypeError("the call did not return a dict"), started)
        return _response(self.platform_id, model, reply, started)


class MessageMockAdapter(MessageAdapter):
    """
    Test stand-in. `respond` is a fixed string, an exception to raise, or a
    callable respond(model, messages, images) returning a string or a dict
    like CallableMessageAdapter's. Every call is logged in `calls`, with a
    deep copy of the messages as received.
    """

    def __init__(self, platform_id: str, respond: Union[str, BaseException, Callable] = "",
                 service: str = ""):
        super().__init__(platform_id, service)
        self.respond = respond
        self.calls: list[dict] = []

    def send_messages(self, model, messages, images=(), timeout=None, max_tokens=None, temperature=None):
        started = time.monotonic()
        self.calls.append({"model": model, "messages": copy.deepcopy(messages), "images": list(images),
                           "max_tokens": max_tokens, "temperature": temperature})
        try:
            if isinstance(self.respond, BaseException):
                raise self.respond
            out = self.respond(model, messages, images) if callable(self.respond) else self.respond
        except Exception as err:
            return _failure(self.platform_id, model, err, started)
        reply = out if isinstance(out, dict) else {"text": out, "response_id": f"mock-{self.platform_id}-"
                                                   f"{len(self.calls)}", "stop_reason": "end_turn"}
        return _response(self.platform_id, model, reply, started)
