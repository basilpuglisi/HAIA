"""
HAIA Agent Framework - Test Suite
==================================
Tests for Phase 1+2: Audit file schema and logging engine.

Verification targets from the GOPEL specification:
1. Immutability: append-only, no modification or deletion
2. Completeness: all six record types generated and stored
3. Reconstruction: any transaction's full chain retrievable
4. Hash chain integrity: tamper detection works
5. Cross-platform ingestibility: valid JSON output

Usage:
    python -m pytest tests/ -v
    # or
    python tests/test_logging_engine.py
"""

import hashlib
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from haia_agent import (
    AuditLogger,
    ArbitrationDecision,
    ArbitrationRecord,
    DecisionRecord,
    DispatchRecord,
    NavigationRecord,
    OperatingModel,
    PlatformStatus,
    RecordType,
    RECCLINRole,
    RequestRecord,
    ResponseRecord,
    SystemRecord,
)


def create_test_logger(tmp_dir: str) -> AuditLogger:
    """Create a fresh AuditLogger for testing."""
    path = Path(tmp_dir) / f"test_audit_{uuid.uuid4().hex[:8]}.json"
    return AuditLogger(
        audit_file_path=path,
        operator_id="test_operator",
        create_new=True,
    )


def create_full_transaction(logger: AuditLogger) -> str:
    """Create a complete six-record transaction. Returns transaction_id."""
    tid = str(uuid.uuid4())
    prompt = "Test prompt for analysis"
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()

    # 1. Request
    logger.log_request(
        transaction_id=tid,
        operator_id="test_human",
        prompt_text=prompt,
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_2,
        platform_selections=["platform_a", "platform_b", "platform_c"],
        anchor_platform="platform_a",
    )

    # 2. Dispatch (x3)
    for pid in ["platform_a", "platform_b", "platform_c"]:
        logger.log_dispatch(
            transaction_id=tid,
            operator_id="haia_agent",
            platform_id=pid,
            prompt_hash=prompt_hash,
            is_anchor=(pid == "platform_a"),
        )

    # 3. Response (x3)
    resp_ids = []
    for pid in ["platform_a", "platform_b", "platform_c"]:
        r = logger.log_response(
            transaction_id=tid,
            operator_id="haia_agent",
            platform_id=pid,
            response_text=f"Response from {pid}: analysis complete.",
            response_status=PlatformStatus.RECEIVED,
        )
        resp_ids.append(r.record_id)

    # 4. Navigation
    nav = logger.log_navigation(
        transaction_id=tid,
        operator_id="haia_agent",
        navigator_platform="platform_a",
        convergence_summary="All platforms agree on core findings.",
        divergence_summary="No material disagreement.",
        confidence_score=85,
        response_record_ids=resp_ids,
    )

    # 5. Arbitration
    logger.log_arbitration(
        transaction_id=tid,
        operator_id="test_human",
        arbitration_decision=ArbitrationDecision.APPROVE,
        rationale="Findings are consistent and well-supported.",
        checkpoint_role=RECCLINRole.RESEARCHER,
        navigation_record_id=nav.record_id,
    )

    # 6. Decision
    logger.log_decision(
        transaction_id=tid,
        operator_id="test_human",
        final_output="Approved analysis output.",
        upstream_record_ids=resp_ids + [nav.record_id],
        is_final=True,
    )

    return tid


# ======================================================================
# TEST 1: COMPLETENESS - All six record types stored
# ======================================================================

def test_completeness():
    """Verify all six record types are generated and stored."""
    print("TEST 1: Completeness (six record types)...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        logger = create_test_logger(tmp)
        tid = create_full_transaction(logger)
        chain = logger.reconstruct_transaction(tid)

        record_types_found = set(r["record_type"] for r in chain)
        expected = {"request", "dispatch", "response", "navigation",
                    "arbitration", "decision"}

        assert expected.issubset(record_types_found), (
            f"Missing types: {expected - record_types_found}"
        )

        # Count: 1 request + 3 dispatch + 3 response + 1 nav + 1 arb + 1 dec = 10
        assert len(chain) == 10, f"Expected 10 records, got {len(chain)}"
        print("PASSED")


# ======================================================================
# TEST 2: HASH CHAIN INTEGRITY
# ======================================================================

def test_hash_chain_integrity():
    """Verify hash chain links every record to its predecessor."""
    print("TEST 2: Hash chain integrity...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        logger = create_test_logger(tmp)
        create_full_transaction(logger)

        is_valid, violations = logger.verify_chain_integrity()
        assert is_valid, f"Chain broken: {violations}"
        assert len(violations) == 0
        print("PASSED")


# ======================================================================
# TEST 3: TAMPER DETECTION
# ======================================================================

def test_tamper_detection():
    """Verify that modifying any record breaks the hash chain."""
    print("TEST 3: Tamper detection...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        logger = create_test_logger(tmp)
        create_full_transaction(logger)

        # Verify chain is initially valid
        is_valid, _ = logger.verify_chain_integrity()
        assert is_valid, "Chain should be valid before tampering"

        # Tamper with a record (modify response text)
        for i, r in enumerate(logger._records):
            if r.get("record_type") == "response":
                logger._records[i]["response_text"] = "TAMPERED"
                break

        # Chain should now be broken
        is_valid_after, violations = logger.verify_chain_integrity()
        assert not is_valid_after, "Chain should be broken after tampering"
        assert len(violations) > 0, "Should detect at least one violation"
        print(f"PASSED (detected {len(violations)} violation(s))")


# ======================================================================
# TEST 4: TRANSACTION RECONSTRUCTION
# ======================================================================

def test_transaction_reconstruction():
    """Verify any transaction's full chain is retrievable."""
    print("TEST 4: Transaction reconstruction...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        logger = create_test_logger(tmp)

        # Create multiple transactions
        tid1 = create_full_transaction(logger)
        tid2 = create_full_transaction(logger)

        # Reconstruct each independently
        chain1 = logger.reconstruct_transaction(tid1)
        chain2 = logger.reconstruct_transaction(tid2)

        assert len(chain1) == 10, f"Transaction 1: expected 10, got {len(chain1)}"
        assert len(chain2) == 10, f"Transaction 2: expected 10, got {len(chain2)}"

        # Verify no cross-contamination
        tids_in_chain1 = set(r["transaction_id"] for r in chain1)
        tids_in_chain2 = set(r["transaction_id"] for r in chain2)
        assert tids_in_chain1 == {tid1}, "Chain 1 contains wrong transaction"
        assert tids_in_chain2 == {tid2}, "Chain 2 contains wrong transaction"

        # Verify ordering
        seq_numbers = [r["sequence_number"] for r in chain1]
        assert seq_numbers == sorted(seq_numbers), "Records not in sequence order"
        print("PASSED")


# ======================================================================
# TEST 5: APPEND-ONLY IMMUTABILITY
# ======================================================================

def test_append_only():
    """Verify records accumulate and sequence numbers increase monotonically."""
    print("TEST 5: Append-only immutability...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        logger = create_test_logger(tmp)

        # Log several records
        create_full_transaction(logger)
        count_after_first = logger.get_record_count()

        create_full_transaction(logger)
        count_after_second = logger.get_record_count()

        assert count_after_second > count_after_first, (
            "Record count should increase"
        )

        # Verify monotonically increasing sequence numbers
        all_sequences = [r["sequence_number"] for r in logger._records]
        for i in range(1, len(all_sequences)):
            assert all_sequences[i] > all_sequences[i - 1], (
                f"Sequence not monotonic at position {i}"
            )
        print("PASSED")


# ======================================================================
# TEST 6: FILE PERSISTENCE AND RELOAD
# ======================================================================

def test_persistence_and_reload():
    """Verify audit file can be saved and reloaded with chain intact."""
    print("TEST 6: Persistence and reload...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "persist_test.json"

        # Create and populate
        logger1 = AuditLogger(audit_file_path=path, operator_id="test")
        tid = create_full_transaction(logger1)
        original_count = logger1.get_record_count()

        # Reload from file
        logger2 = AuditLogger(audit_file_path=path, operator_id="test", create_new=False)
        reloaded_count = logger2.get_record_count()

        assert original_count == reloaded_count, (
            f"Record count mismatch: {original_count} vs {reloaded_count}"
        )

        # Verify chain integrity on reloaded file
        is_valid, violations = logger2.verify_chain_integrity()
        assert is_valid, f"Chain broken after reload: {violations}"

        # Verify reconstruction works on reloaded file
        chain = logger2.reconstruct_transaction(tid)
        assert len(chain) == 10
        print("PASSED")


# ======================================================================
# TEST 7: VALID JSON OUTPUT (cross-platform ingestibility)
# ======================================================================

def test_valid_json_output():
    """Verify the audit file is valid JSON parseable by any platform."""
    print("TEST 7: Valid JSON output...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "json_test.json"
        logger = AuditLogger(audit_file_path=path, operator_id="test")
        create_full_transaction(logger)

        # Read and parse
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Verify structure
        assert "schema" in data, "Missing schema header"
        assert "records" in data, "Missing records array"
        assert isinstance(data["records"], list), "Records should be a list"
        assert len(data["records"]) > 0, "Records should not be empty"

        # Verify schema is self-documenting
        schema = data["schema"]
        assert "record_types" in schema, "Schema missing record_types"
        assert "hash_algorithm" in schema, "Schema missing hash_algorithm"
        assert "chain_mechanism" in schema, "Schema missing chain_mechanism"
        assert "immutability_rule" in schema, "Schema missing immutability_rule"
        assert schema["framework"] == "HAIA Agent Framework"
        assert schema["architecture"] == "GOPEL (Governance Orchestrator Policy Enforcement Layer)"
        print("PASSED")


# ======================================================================
# TEST 8: GOVERNANCE METRICS (Operation 7: Report)
# ======================================================================

def test_governance_metrics():
    """Verify governance metrics count correctly without interpretation."""
    print("TEST 8: Governance metrics...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        logger = create_test_logger(tmp)
        create_full_transaction(logger)

        metrics = logger.generate_governance_metrics()

        assert metrics["total_records"] > 0
        assert "request" in metrics["records_by_type"]
        assert "dispatch" in metrics["records_by_type"]
        assert "response" in metrics["records_by_type"]
        assert "navigation" in metrics["records_by_type"]
        assert "arbitration" in metrics["records_by_type"]
        assert "decision" in metrics["records_by_type"]

        # One arbitration with APPROVE
        assert metrics["arbitration"]["total"] == 1
        assert metrics["arbitration"]["approve_count"] == 1
        assert metrics["arbitration"]["approve_rate"] == 1.0

        # Three platforms dispatched
        assert len(metrics["platforms"]) == 3

        # Chain should be intact
        assert metrics["chain_intact"] is True
        print("PASSED")


# ======================================================================
# TEST 9: PROMPT HASH PROVES IDENTICAL DISPATCH
# ======================================================================

def test_identical_dispatch_verification():
    """Verify that prompt hashes prove identical prompts were sent."""
    print("TEST 9: Identical dispatch verification...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        logger = create_test_logger(tmp)
        tid = create_full_transaction(logger)

        chain = logger.reconstruct_transaction(tid)
        dispatch_records = [r for r in chain if r["record_type"] == "dispatch"]

        # All dispatch records should have the same prompt_hash
        prompt_hashes = set(r["prompt_hash"] for r in dispatch_records)
        assert len(prompt_hashes) == 1, (
            f"Expected 1 unique prompt hash, got {len(prompt_hashes)}"
        )
        print("PASSED")


# ======================================================================
# TEST 10: RESPONSE HASH INTEGRITY
# ======================================================================

def test_response_hash_integrity():
    """Verify response hashes match response content."""
    print("TEST 10: Response hash integrity...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        logger = create_test_logger(tmp)
        tid = create_full_transaction(logger)

        chain = logger.reconstruct_transaction(tid)
        response_records = [r for r in chain if r["record_type"] == "response"]

        for r in response_records:
            expected_hash = hashlib.sha256(
                r["response_text"].encode("utf-8")
            ).hexdigest()
            assert r["response_hash"] == expected_hash, (
                f"Response hash mismatch for {r['platform_id']}"
            )
        print("PASSED")


# ======================================================================
# RUN ALL TESTS
# ======================================================================

def run_all_tests():
    print("=" * 70)
    print("HAIA AGENT FRAMEWORK - TEST SUITE")
    print("Phase 1+2: Audit Schema and Logging Engine")
    print("=" * 70)
    print()

    tests = [
        test_completeness,
        test_hash_chain_integrity,
        test_tamper_detection,
        test_transaction_reconstruction,
        test_append_only,
        test_persistence_and_reload,
        test_valid_json_output,
        test_governance_metrics,
        test_identical_dispatch_verification,
        test_response_hash_integrity,
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
            print(f"ERROR: {e}")
            failed += 1

    print()
    print("=" * 70)
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    print("=" * 70)

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
