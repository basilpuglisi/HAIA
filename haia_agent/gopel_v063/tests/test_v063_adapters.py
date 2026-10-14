"""
GOPEL v0.6.3, step 26 (addendum 15) with settlement S2 (Q6 Option A).

    (a) No temperature is sent unless the operator sets one.
    (b) An explicit temperature is refused where the SDK or the model does
        not accept it (Anthropic SDK 1.x messages.create has no temperature).
    (c) Dispatch and Response records carry generation_settings, including
        whether temperature was set by the operator or left to the provider.
    No adapter has a default model. OpenAI uses max_completion_tokens.
    Google uses google-genai and records the real response_id. A response
    that stops on max_tokens or refusal is not reported as a success.

Provider SDKs are replaced by stand-in modules injected into sys.modules.
No API keys, no network, no real SDK.

Author: Basil C. Puglisi, MPA
"""

import enum
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from haia_agent.gopel_v063.adapters.anthropic_adapter import AnthropicAdapter  # noqa: E402
from haia_agent.gopel_v063.adapters.google_adapter import GoogleAdapter  # noqa: E402
from haia_agent.gopel_v063.adapters.mock_adapter import MockAdapter  # noqa: E402
from haia_agent.gopel_v063.adapters.openai_adapter import OpenAIAdapter  # noqa: E402
from haia_agent.gopel_v063.tests import v063_support as sup  # noqa: E402


# ======================================================================
# Stand-in SDK modules
# ======================================================================

class FinishReason(str, enum.Enum):
    STOP = "STOP"
    MAX_TOKENS = "MAX_TOKENS"
    SAFETY = "SAFETY"


class SDKRecorder:
    """Records every SDK call and holds the canned responses."""

    def __init__(self):
        self.anthropic_calls = []
        self.anthropic_clients = []
        self.anthropic_rejects_temperature = True  # Anthropic SDK 1.x
        self.anthropic_stop_reason = "end_turn"
        self.anthropic_text = "Anthropic stand-in response."
        self.openai_calls = []
        self.openai_finish_reason = "stop"
        self.openai_refusal = None
        self.openai_text = "OpenAI stand-in response."
        self.google_calls = []
        self.google_configs = []
        self.google_finish_reason = FinishReason.STOP
        self.google_text = "Google stand-in response."
        self.google_response_id = "resp-google-7f3a"


def _install_sdks(monkeypatch, rec: SDKRecorder) -> None:
    # --- anthropic ---------------------------------------------------
    anthropic_mod = types.ModuleType("anthropic")

    class _Messages:
        def create(self, **kwargs):
            rec.anthropic_calls.append(kwargs)
            if rec.anthropic_rejects_temperature and "temperature" in kwargs:
                raise TypeError(
                    "Messages.create() got an unexpected keyword argument 'temperature'")
            return SimpleNamespace(
                id="msg_standin_001",
                model=kwargs["model"],
                content=[SimpleNamespace(type="text", text=rec.anthropic_text)],
                stop_reason=rec.anthropic_stop_reason,
                usage=SimpleNamespace(input_tokens=11, output_tokens=7),
            )

    class Anthropic:
        def __init__(self, api_key=None, **kwargs):
            rec.anthropic_clients.append(api_key)
            self.messages = _Messages()

    anthropic_mod.Anthropic = Anthropic
    monkeypatch.setitem(sys.modules, "anthropic", anthropic_mod)

    # --- openai ------------------------------------------------------
    openai_mod = types.ModuleType("openai")

    class _Completions:
        def create(self, **kwargs):
            rec.openai_calls.append(kwargs)
            message = SimpleNamespace(content=rec.openai_text, refusal=rec.openai_refusal)
            return SimpleNamespace(
                id="chatcmpl-standin-001",
                model=kwargs["model"],
                choices=[SimpleNamespace(message=message, finish_reason=rec.openai_finish_reason)],
                usage=SimpleNamespace(prompt_tokens=9, completion_tokens=6),
            )

    class OpenAI:
        def __init__(self, api_key=None, **kwargs):
            self.chat = SimpleNamespace(completions=_Completions())

    openai_mod.OpenAI = OpenAI
    monkeypatch.setitem(sys.modules, "openai", openai_mod)

    # --- google.genai ------------------------------------------------
    google_mod = types.ModuleType("google")
    google_mod.__path__ = []  # namespace-like package
    genai_mod = types.ModuleType("google.genai")
    genai_mod.__path__ = []
    types_mod = types.ModuleType("google.genai.types")

    class GenerateContentConfig:
        def __init__(self, **kwargs):
            rec.google_configs.append(kwargs)
            self.kwargs = kwargs

    types_mod.GenerateContentConfig = GenerateContentConfig
    types_mod.FinishReason = FinishReason

    class _Models:
        def generate_content(self, **kwargs):
            rec.google_calls.append(kwargs)
            return SimpleNamespace(
                text=rec.google_text,
                response_id=rec.google_response_id,
                model_version=kwargs["model"],
                candidates=[SimpleNamespace(finish_reason=rec.google_finish_reason)],
                usage_metadata=SimpleNamespace(
                    prompt_token_count=8, candidates_token_count=5, total_token_count=13),
            )

    class Client:
        def __init__(self, api_key=None, **kwargs):
            self.models = _Models()

    genai_mod.Client = Client
    genai_mod.types = types_mod
    google_mod.genai = genai_mod
    monkeypatch.setitem(sys.modules, "google", google_mod)
    monkeypatch.setitem(sys.modules, "google.genai", genai_mod)
    monkeypatch.setitem(sys.modules, "google.genai.types", types_mod)


@pytest.fixture
def sdk(monkeypatch):
    rec = SDKRecorder()
    _install_sdks(monkeypatch, rec)
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    return rec


def _provider_pipeline(kind, tmp_path):
    anthropic_ad = AnthropicAdapter(api_key="test-key-not-real", default_model="claude-sonnet-5-5")
    openai_ad = OpenAIAdapter(api_key="test-key-not-real", default_model="gpt-standin-model")
    google_ad = GoogleAdapter(api_key="test-key-not-real", default_model="gemini-standin-model")
    pipeline, logger, _ = sup.make_pipeline(
        kind, tmp_path, with_channel=False, adapters=[anthropic_ad, openai_ad, google_ad])
    return pipeline, logger


# ======================================================================
# S2 test first: a default run with an Anthropic seat completes
# ======================================================================

@pytest.mark.parametrize("kind", ["base", "secure"])
def test_default_run_with_anthropic_seat_completes(sdk, tmp_path, kind):
    pipeline, logger = _provider_pipeline(kind, tmp_path)
    result = sup.run(pipeline)  # no temperature set by the operator
    assert result.success, result.error

    by_platform = {r.platform_id: r for r in result.checkpoint_package.platform_responses}
    anthropic_resp = by_platform["anthropic_claude"]
    assert anthropic_resp.success, anthropic_resp.error_detail
    assert len(sdk.anthropic_calls) == 1
    call = sdk.anthropic_calls[0]
    assert "temperature" not in call
    assert call["model"] == "claude-sonnet-5-5"
    assert call["messages"] == [{"role": "user", "content": "Research question for the stop tests."}]
    # OpenAI and Google receive no temperature either (provider default).
    assert "temperature" not in sdk.openai_calls[0]
    assert "temperature" not in sdk.google_configs[0]


# ======================================================================
# S2 test first: an explicit temperature the SDK rejects is refused
# ======================================================================

def test_explicit_temperature_refused_by_anthropic_with_zero_sdk_calls(sdk):
    adapter = AnthropicAdapter(api_key="test-key-not-real", default_model="claude-sonnet-5-5")
    resp = adapter.send_prompt("Hello", temperature=0.5)
    assert resp.success is False
    assert "UNSUPPORTED_CONFIGURATION" in resp.error_detail
    assert "temperature" in resp.error_detail
    assert sdk.anthropic_calls == []


def test_explicit_temperature_in_pipeline_recorded_as_unsupported_configuration(sdk, tmp_path):
    pipeline, logger = _provider_pipeline("base", tmp_path)
    result = sup.run(pipeline, temperature=0.5)
    assert sdk.anthropic_calls == []
    tid = result.transaction_id
    responses = {r["platform_id"]: r for r in sup.records_of(logger, tid, "response")}
    dispatches = {r["platform_id"]: r for r in sup.records_of(logger, tid, "dispatch")}
    assert responses["anthropic_claude"]["response_status"] == "error"
    assert "UNSUPPORTED_CONFIGURATION" in responses["anthropic_claude"]["error_detail"]
    assert dispatches["anthropic_claude"]["dispatch_status"] == "error"
    assert dispatches["anthropic_claude"]["generation_settings"]["temperature"] == 0.5
    assert dispatches["anthropic_claude"]["generation_settings"]["temperature_source"] == "operator"
    # OpenAI and Google accept an explicit temperature and receive it.
    assert sdk.openai_calls[0]["temperature"] == 0.5
    assert sdk.google_configs[0]["temperature"] == 0.5


def test_model_that_does_not_accept_temperature_is_refused(sdk):
    adapter = OpenAIAdapter(api_key="test-key-not-real", default_model="gpt-standin-reasoning",
                            accepts_temperature=False)
    resp = adapter.send_prompt("Hello", temperature=0.2)
    assert resp.success is False
    assert "UNSUPPORTED_CONFIGURATION" in resp.error_detail
    assert sdk.openai_calls == []


# ======================================================================
# No default model, no silent fallback
# ======================================================================

@pytest.mark.parametrize("cls", [AnthropicAdapter, OpenAIAdapter, GoogleAdapter])
def test_missing_model_raises(cls):
    with pytest.raises(ValueError):
        cls(api_key="test-key-not-real")
    with pytest.raises(ValueError):
        cls(api_key="test-key-not-real", default_model="")


# ======================================================================
# Truncation and refusal are not success
# ======================================================================

def test_anthropic_max_tokens_and_refusal_are_not_success(sdk):
    sdk.anthropic_rejects_temperature = False  # isolate the stop_reason handling
    adapter = AnthropicAdapter(api_key="test-key-not-real", default_model="claude-sonnet-5-5")

    sdk.anthropic_stop_reason = "end_turn"
    ok = adapter.send_prompt("Hello", system_prompt="System context.")
    assert ok.success, ok.error_detail
    assert sdk.anthropic_calls[-1]["system"] == "System context."
    assert sdk.anthropic_calls[-1]["max_tokens"] == 4096

    for reason in ("max_tokens", "refusal"):
        sdk.anthropic_stop_reason = reason
        resp = adapter.send_prompt("Hello")
        assert resp.success is False, reason
        assert reason in resp.error_detail
        assert resp.response_text == sdk.anthropic_text  # what arrived is kept verbatim


def test_openai_uses_max_completion_tokens_and_truncation_or_refusal_is_not_success(sdk):
    adapter = OpenAIAdapter(api_key="test-key-not-real", default_model="gpt-standin-model")

    ok = adapter.send_prompt("Hello", max_tokens=321)
    assert ok.success, ok.error_detail
    call = sdk.openai_calls[-1]
    assert call["max_completion_tokens"] == 321
    assert "max_tokens" not in call
    assert "temperature" not in call

    sdk.openai_finish_reason = "length"
    truncated = adapter.send_prompt("Hello")
    assert truncated.success is False
    assert "length" in truncated.error_detail

    sdk.openai_finish_reason = "content_filter"
    assert adapter.send_prompt("Hello").success is False

    sdk.openai_finish_reason = "stop"
    sdk.openai_refusal = "I can't help with that."
    refused = adapter.send_prompt("Hello")
    assert refused.success is False
    assert "refusal" in refused.error_detail


def test_google_genai_records_real_response_id_and_non_stop_is_not_success(sdk):
    adapter = GoogleAdapter(api_key="test-key-not-real", default_model="gemini-standin-model")

    ok = adapter.send_prompt("Hello", system_prompt="System context.", max_tokens=222)
    assert ok.success, ok.error_detail
    assert ok.api_confirmation == "resp-google-7f3a"
    call = sdk.google_calls[-1]
    assert call["model"] == "gemini-standin-model"
    assert call["contents"] == "Hello"
    config = sdk.google_configs[-1]
    assert config["max_output_tokens"] == 222
    assert config["system_instruction"] == "System context."
    assert "temperature" not in config

    for reason in (FinishReason.MAX_TOKENS, FinishReason.SAFETY):
        sdk.google_finish_reason = reason
        resp = adapter.send_prompt("Hello")
        assert resp.success is False
        assert reason.value in resp.error_detail


# ======================================================================
# generation_settings on Dispatch and Response records (S2c)
# ======================================================================

@pytest.mark.parametrize("kind", ["base", "secure"])
def test_generation_settings_recorded_with_temperature_source(tmp_path, kind):
    pipeline, logger, _ = sup.make_pipeline(kind, tmp_path, with_channel=False)
    models = {"mock_alpha": "alpha-model", "mock_beta": "beta-model", "mock_gamma": "gamma-model"}

    default_run = sup.run(pipeline)
    assert default_run.success, default_run.error
    for rtype in ("dispatch", "response"):
        recs = sup.records_of(logger, default_run.transaction_id, rtype)
        assert len(recs) == 3
        for r in recs:
            assert r["generation_settings"] == {
                "model": models[r["platform_id"]],
                "max_tokens": 4096,
                "temperature": None,
                "temperature_source": "provider_default",
            }

    operator_run = sup.run(pipeline, temperature=0.3, max_tokens=1000)
    assert operator_run.success, operator_run.error
    for rtype in ("dispatch", "response"):
        for r in sup.records_of(logger, operator_run.transaction_id, rtype):
            assert r["generation_settings"] == {
                "model": models[r["platform_id"]],
                "max_tokens": 1000,
                "temperature": 0.3,
                "temperature_source": "operator",
            }

    ok, violations = logger.verify_chain_integrity()
    assert ok, violations


def test_requirements_pin_sdk_ranges():
    path = sup.PKG_DIR / "requirements_v0_6_3.txt"
    lines = {
        ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    }
    for pin in (
        "anthropic>=1.13,<2",
        "openai>=3.30,<4",
        "google-genai>=2.30,<3",
        "pydantic>=2.14",
        "cryptography>=50.0.2",
    ):
        assert pin in lines, pin
    assert not any(ln.startswith("google-generativeai") for ln in lines)
