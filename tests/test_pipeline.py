"""
HAIA Agent Framework - Pipeline Integration Tests
===================================================
Tests for Phase 3: Dispatch, Collection, and Routing pipeline.

Uses mock adapters to validate the full 14-step operational sequence
without requiring API keys.

Author: Basil C. Puglisi, MPA
"""

import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from haia_agent import (
    AuditLogger,
    ArbitrationDecision,
    ArbitrationInput,
    GOPELPipeline,
    MockAdapter,
    NavigatorRouter,
    OperatingModel,
    PlatformSelector,
    RECCLINRole,
)


def build_test_pipeline(tmp_dir: str) -> tuple:
    """Build a complete pipeline with three mock adapters and a mock Navigator."""
    audit_path = Path(tmp_dir) / f"pipeline_test_{uuid.uuid4().hex[:8]}.json"
    logger = AuditLogger(audit_file_path=audit_path, operator_id="test")

    # Three mock platform adapters with distinct responses
    adapter_claude = MockAdapter(
        platform_id="anthropic_claude",
        default_model="claude-mock-v1",
        responses=[
            "Claude analysis: The framework shows three key strengths in "
            "governance design, risk classification, and audit trail integrity."
        ],
    )
    adapter_chatgpt = MockAdapter(
        platform_id="openai_chatgpt",
        default_model="gpt-mock-v1",
        responses=[
            "ChatGPT analysis: The framework addresses governance and risk "
            "but lacks implementation specifics for audit trail requirements."
        ],
    )
    adapter_gemini = MockAdapter(
        platform_id="google_gemini",
        default_model="gemini-mock-v1",
        responses=[
            "Gemini analysis: Strong governance model. Risk classification "
            "aligns with EU AI Act. Audit trail design exceeds requirements."
        ],
    )

    # Mock Navigator (uses Claude adapter for synthesis)
    navigator_adapter = MockAdapter(
        platform_id="navigator_claude",
        default_model="claude-nav-mock-v1",
        responses=[
            "CONVERGENCE: All three platforms agree on governance design strength.\n\n"
            "DIVERGENCE: ChatGPT identifies audit trail gaps. Claude and Gemini "
            "consider audit trail adequate or exceeding requirements.\n\n"
            "DISSENT: ChatGPT position on audit trail preserved in full.\n\n"
            "CONFIDENCE: 78\n\n"
            "RECOMMENDATION: Accept governance and risk findings. Flag audit "
            "trail disagreement for human arbitration."
        ],
    )

    # Platform selector
    selector = PlatformSelector(min_rotation=2)
    selector.register_adapter(adapter_claude)
    selector.register_adapter(adapter_chatgpt)
    selector.register_adapter(adapter_gemini)
    selector.set_anchor("anthropic_claude")

    # Navigator router
    navigator = NavigatorRouter(navigator_adapter=navigator_adapter)

    # Pipeline
    pipeline = GOPELPipeline(
        logger=logger,
        selector=selector,
        navigator=navigator,
        operator_id="haia_agent",
    )

    return pipeline, logger, audit_path


# ======================================================================
# TEST 1: Full pipeline execution completes
# ======================================================================

def test_pipeline_executes():
    """Verify the full pipeline runs from prompt to checkpoint package."""
    print("TEST 1: Full pipeline execution...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        pipeline, logger, _ = build_test_pipeline(tmp)

        result = pipeline.execute(
            prompt="Analyze the governance framework for compliance gaps.",
            recclin_role=RECCLINRole.RESEARCHER,
            operating_model=OperatingModel.MODEL_2,
            human_operator_id="test_human",
            task_scope="Compliance gap analysis",
            success_criteria="Identify gaps with evidence",
        )

        assert result.success, f"Pipeline failed: {result.error}"
        assert result.checkpoint_package is not None
        assert result.transaction_id is not None
        print("PASSED")


# ======================================================================
# TEST 2: Checkpoint package contains all required data
# ======================================================================

def test_checkpoint_package_complete():
    """Verify the checkpoint package has everything the human needs."""
    print("TEST 2: Checkpoint package completeness...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        pipeline, logger, _ = build_test_pipeline(tmp)

        result = pipeline.execute(
            prompt="Analyze compliance framework.",
            recclin_role=RECCLINRole.RESEARCHER,
            operating_model=OperatingModel.MODEL_2,
            human_operator_id="test_human",
        )

        pkg = result.checkpoint_package
        assert pkg.transaction_id == result.transaction_id
        assert pkg.recclin_role == RECCLINRole.RESEARCHER
        assert pkg.original_prompt == "Analyze compliance framework."
        assert len(pkg.platform_responses) == 3, (
            f"Expected 3 platform responses, got {len(pkg.platform_responses)}"
        )
        assert pkg.navigator_synthesis is not None
        assert pkg.navigator_synthesis.success
        assert pkg.navigation_record_id != ""
        print("PASSED")


# ======================================================================
# TEST 3: All platform responses collected (none filtered)
# ======================================================================

def test_all_responses_collected():
    """Verify no responses are filtered or omitted."""
    print("TEST 3: All responses collected (none filtered)...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        pipeline, logger, _ = build_test_pipeline(tmp)

        result = pipeline.execute(
            prompt="Test prompt.",
            recclin_role=RECCLINRole.RESEARCHER,
            operating_model=OperatingModel.MODEL_2,
            human_operator_id="test_human",
        )

        responses = result.checkpoint_package.platform_responses
        platform_ids = set(r.platform_id for r in responses)

        assert "anthropic_claude" in platform_ids
        assert "openai_chatgpt" in platform_ids
        assert "google_gemini" in platform_ids

        # Every response should have content
        for r in responses:
            assert r.success, f"{r.platform_id} failed: {r.error_detail}"
            assert len(r.response_text) > 0, f"{r.platform_id} returned empty"
            assert r.response_hash != "", f"{r.platform_id} missing hash"
        print("PASSED")


# ======================================================================
# TEST 4: Audit trail contains complete transaction
# ======================================================================

def test_audit_trail_complete():
    """Verify the audit trail captures the full pipeline execution."""
    print("TEST 4: Audit trail completeness...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        pipeline, logger, _ = build_test_pipeline(tmp)

        result = pipeline.execute(
            prompt="Test prompt for audit.",
            recclin_role=RECCLINRole.RESEARCHER,
            operating_model=OperatingModel.MODEL_2,
            human_operator_id="test_human",
        )

        chain = logger.reconstruct_transaction(result.transaction_id)
        record_types = [r["record_type"] for r in chain]

        # Should have: 1 request + 3 dispatch + 3 response + 1 navigation = 8
        assert "request" in record_types, "Missing Request Record"
        assert record_types.count("dispatch") == 3, "Expected 3 Dispatch Records"
        assert record_types.count("response") == 3, "Expected 3 Response Records"
        assert "navigation" in record_types, "Missing Navigation Record"
        assert len(chain) == 8, f"Expected 8 records pre-arbitration, got {len(chain)}"
        print("PASSED")


# ======================================================================
# TEST 5: Hash chain intact after pipeline execution
# ======================================================================

def test_chain_integrity_after_pipeline():
    """Verify hash chain is intact after full pipeline execution."""
    print("TEST 5: Hash chain integrity after pipeline...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        pipeline, logger, _ = build_test_pipeline(tmp)

        pipeline.execute(
            prompt="Test prompt.",
            recclin_role=RECCLINRole.RESEARCHER,
            operating_model=OperatingModel.MODEL_2,
            human_operator_id="test_human",
        )

        is_valid, violations = logger.verify_chain_integrity()
        assert is_valid, f"Chain broken: {violations}"
        print("PASSED")


# ======================================================================
# TEST 6: Arbitration recording completes the transaction
# ======================================================================

def test_arbitration_recording():
    """Verify arbitration and decision records complete the chain."""
    print("TEST 6: Arbitration recording...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        pipeline, logger, _ = build_test_pipeline(tmp)

        result = pipeline.execute(
            prompt="Test prompt for arbitration.",
            recclin_role=RECCLINRole.RESEARCHER,
            operating_model=OperatingModel.MODEL_2,
            human_operator_id="test_human",
        )

        # Human arbitrates
        pipeline.record_arbitration(
            transaction_id=result.transaction_id,
            human_operator_id="test_human",
            arbitration=ArbitrationInput(
                decision=ArbitrationDecision.MODIFY,
                rationale="Accepted with modifications to address audit gap.",
                modifications="Added audit trail specifics per ChatGPT feedback.",
                final_output="Modified analysis incorporating all platform inputs.",
            ),
            checkpoint_role=RECCLINRole.RESEARCHER,
            navigation_record_id=result.checkpoint_package.navigation_record_id,
        )

        # Full chain should now have 10 records (8 + arbitration + decision)
        chain = logger.reconstruct_transaction(result.transaction_id)
        record_types = [r["record_type"] for r in chain]
        assert "arbitration" in record_types, "Missing Arbitration Record"
        assert "decision" in record_types, "Missing Decision Record"
        assert len(chain) == 10, f"Expected 10 records, got {len(chain)}"

        # Chain still intact
        is_valid, violations = logger.verify_chain_integrity()
        assert is_valid, f"Chain broken after arbitration: {violations}"
        print("PASSED")


# ======================================================================
# TEST 7: Identical prompt dispatch verification
# ======================================================================

def test_identical_dispatch():
    """Verify all platforms received identical prompts (same hash)."""
    print("TEST 7: Identical prompt dispatch...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        pipeline, logger, _ = build_test_pipeline(tmp)

        result = pipeline.execute(
            prompt="Identical prompt test.",
            recclin_role=RECCLINRole.RESEARCHER,
            operating_model=OperatingModel.MODEL_2,
            human_operator_id="test_human",
        )

        chain = logger.reconstruct_transaction(result.transaction_id)
        dispatch_records = [r for r in chain if r["record_type"] == "dispatch"]

        prompt_hashes = set(r["prompt_hash"] for r in dispatch_records)
        assert len(prompt_hashes) == 1, (
            f"Dispatch hashes should be identical, got {len(prompt_hashes)} distinct"
        )
        print("PASSED")


# ======================================================================
# TEST 8: Error handling (platform failure)
# ======================================================================

def test_platform_error_handling():
    """Verify pipeline handles a platform error gracefully."""
    print("TEST 8: Platform error handling...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        audit_path = Path(tmp) / "error_test.json"
        logger = AuditLogger(audit_file_path=audit_path, operator_id="test")

        # One adapter is configured to fail
        adapter_ok1 = MockAdapter(
            platform_id="platform_ok1", responses=["Good response 1"]
        )
        adapter_ok2 = MockAdapter(
            platform_id="platform_ok2", responses=["Good response 2"]
        )
        adapter_fail = MockAdapter(
            platform_id="platform_fail", simulate_error=True
        )

        selector = PlatformSelector()
        selector.register_adapter(adapter_ok1)
        selector.register_adapter(adapter_ok2)
        selector.register_adapter(adapter_fail)
        selector.set_anchor("platform_ok1")

        navigator = NavigatorRouter(
            navigator_adapter=MockAdapter(
                platform_id="nav", responses=["Synthesis with error noted"]
            )
        )

        pipeline = GOPELPipeline(
            logger=logger, selector=selector,
            navigator=navigator, operator_id="test"
        )

        result = pipeline.execute(
            prompt="Error test.",
            recclin_role=RECCLINRole.RESEARCHER,
            operating_model=OperatingModel.MODEL_2,
            human_operator_id="test_human",
        )

        # Pipeline should still complete (errors are logged, not fatal)
        assert result.success, f"Pipeline should not fail on platform error: {result.error}"

        # The error response should be in the collected responses
        responses = result.checkpoint_package.platform_responses
        error_responses = [r for r in responses if not r.success]
        assert len(error_responses) == 1, "Should have exactly 1 error response"
        assert error_responses[0].platform_id == "platform_fail"

        # Error should be logged in audit trail
        chain = logger.reconstruct_transaction(result.transaction_id)
        error_records = [
            r for r in chain
            if r["record_type"] == "response" and r.get("error_detail")
        ]
        assert len(error_records) >= 1, "Error should be in audit trail"
        print("PASSED")


# ======================================================================
# TEST 9: Governance metrics after pipeline
# ======================================================================

def test_governance_metrics_pipeline():
    """Verify governance metrics reflect pipeline execution."""
    print("TEST 9: Governance metrics after pipeline...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        pipeline, logger, _ = build_test_pipeline(tmp)

        result = pipeline.execute(
            prompt="Metrics test.",
            recclin_role=RECCLINRole.RESEARCHER,
            operating_model=OperatingModel.MODEL_2,
            human_operator_id="test_human",
        )

        # Record arbitration
        pipeline.record_arbitration(
            transaction_id=result.transaction_id,
            human_operator_id="test_human",
            arbitration=ArbitrationInput(
                decision=ArbitrationDecision.APPROVE,
                rationale="All findings verified.",
            ),
            checkpoint_role=RECCLINRole.RESEARCHER,
            navigation_record_id=result.checkpoint_package.navigation_record_id,
        )

        metrics = logger.generate_governance_metrics()
        assert metrics["arbitration"]["total"] == 1
        assert metrics["arbitration"]["approve_count"] == 1
        assert metrics["arbitration"]["approve_rate"] == 1.0
        assert len(metrics["platforms"]) == 3
        assert metrics["chain_intact"] is True
        print("PASSED")


# ======================================================================
# TEST 10: Multiple transactions through same pipeline
# ======================================================================

def test_multiple_transactions():
    """Verify pipeline handles sequential transactions with intact chain."""
    print("TEST 10: Multiple transactions...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        pipeline, logger, _ = build_test_pipeline(tmp)

        # Run three transactions
        tids = []
        for i in range(3):
            result = pipeline.execute(
                prompt=f"Transaction {i + 1} prompt.",
                recclin_role=RECCLINRole.RESEARCHER,
                operating_model=OperatingModel.MODEL_2,
                human_operator_id="test_human",
            )
            assert result.success
            tids.append(result.transaction_id)

        # Each transaction should reconstruct independently
        for tid in tids:
            chain = logger.reconstruct_transaction(tid)
            assert len(chain) == 8, f"Transaction {tid[:8]} has {len(chain)} records"

        # Global chain should be intact
        is_valid, violations = logger.verify_chain_integrity()
        assert is_valid, f"Chain broken: {violations}"
        print("PASSED")


# ======================================================================
# RUN ALL TESTS
# ======================================================================

def run_all_tests():
    print("=" * 70)
    print("HAIA AGENT FRAMEWORK - PIPELINE INTEGRATION TESTS")
    print("Phase 3: Dispatch, Collection, and Routing")
    print("=" * 70)
    print()

    tests = [
        test_pipeline_executes,
        test_checkpoint_package_complete,
        test_all_responses_collected,
        test_audit_trail_complete,
        test_chain_integrity_after_pipeline,
        test_arbitration_recording,
        test_identical_dispatch,
        test_platform_error_handling,
        test_governance_metrics_pipeline,
        test_multiple_transactions,
    ]

    passed = 0
    failed = 0
    for test_fn in tests:
        try:
            test_fn()
            passed += 1
        except AssertionError as e:
            print(f"FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR: {type(e).__name__}: {e}")
            failed += 1

    print()
    print("=" * 70)
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    print("=" * 70)
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
