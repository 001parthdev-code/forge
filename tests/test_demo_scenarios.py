"""End-to-end acceptance tests for the judge-facing demo scenarios."""
from pathlib import Path
import shutil

from secure_swe.orchestrator import run_secure_remediation


ROOT = Path(__file__).resolve().parents[1]


def test_scenario_b_feedback_loop_rejects_then_verifies():
    result = run_secure_remediation(
        str(ROOT / "samples" / "scenario_b_feedback_loop"),
        max_attempts=3,
        timeout_seconds=30,
    )
    try:
        assert result.status == "VERIFIED"
        assert result.attempt_count == 2
        assert result.attempts[0].status == "REJECTED"
        assert result.attempts[0].failure_feedback is not None
        assert result.attempts[1].status == "VERIFIED"
        assert result.attempts[0].plan.strategy != result.attempts[1].plan.strategy
    finally:
        if result.workspace_path:
            shutil.rmtree(result.workspace_path, ignore_errors=True)


def test_scenario_c_escalates_without_fabricating_patch():
    result = run_secure_remediation(
        str(ROOT / "samples" / "scenario_c_escalation"),
        max_attempts=3,
        timeout_seconds=30,
    )
    assert result.status == "HUMAN_REVIEW_REQUIRED"
    assert result.attempt_count == 0
    assert result.final_patch is None
    assert result.workspace_path is None
