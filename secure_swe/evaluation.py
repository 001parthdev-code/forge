"""
Evaluation / Metrics — lightweight instrumentation for Secure SWE.

Captures actual measurable values from a workflow result to support
hackathon evaluation and comparison against a manual workflow baseline.

Public interface
----------------
    compute_metrics(result) -> WorkflowMetrics
    metrics_to_dict(metrics) -> dict
"""

from __future__ import annotations

import dataclasses
from typing import List, Optional

from secure_swe.models import RemediationWorkflowResult


@dataclasses.dataclass
class WorkflowMetrics:
    """
    Structured metrics for a single Secure SWE workflow run.

    These metrics are derived from actual workflow data — no fabrication.

    Fields
    ------
    workflow_id:
        Unique workflow identifier.
    final_status:
        VERIFIED | HUMAN_REVIEW_REQUIRED | ERROR
    total_attempts:
        Number of remediation attempts made.
    verified_attempt_number:
        Attempt number that achieved VERIFIED (None if not verified).
    rejected_attempt_count:
        Number of REJECTED attempts (did not pass verification).
    error_attempt_count:
        Number of ERROR attempts (internal failure, no useful feedback).
    automated_stages_per_attempt:
        Fixed number of automated stages: inspect, analyze, plan, patch,
        generate-test, execute, verify = 7 stages.
    total_automated_stages:
        automated_stages_per_attempt * total_attempts.
    existing_test_pass_count:
        Number of attempts where existing tests passed.
    security_test_pass_count:
        Number of attempts where the security regression test passed.
    workflow_duration_seconds:
        Total wall-clock time for the workflow.
    attempt_durations_seconds:
        Per-attempt durations.
    finding_type:
        Vulnerability type that was targeted.
    finding_severity:
        Severity of the finding.
    strategies_attempted:
        Ordered list of remediation strategies tried.
    feedback_loops_triggered:
        Number of times structured failure feedback was generated.
    """

    workflow_id: str
    final_status: str
    total_attempts: int
    verified_attempt_number: Optional[int]
    rejected_attempt_count: int
    error_attempt_count: int
    automated_stages_per_attempt: int
    total_automated_stages: int
    existing_test_pass_count: int
    security_test_pass_count: int
    workflow_duration_seconds: float
    attempt_durations_seconds: List[float]
    finding_type: str
    finding_severity: str
    strategies_attempted: List[str]
    feedback_loops_triggered: int

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


# Constant: how many distinct automated stages run per attempt.
_STAGES_PER_ATTEMPT = 7  # inspect, analyze, plan, patch, gen-test, execute, verify


def compute_metrics(result: RemediationWorkflowResult) -> WorkflowMetrics:
    """
    Derive WorkflowMetrics from an actual RemediationWorkflowResult.

    All values come directly from the result — nothing is fabricated.
    """
    total_attempts = result.attempt_count

    rejected = sum(1 for a in result.attempts if a.status == "REJECTED")
    errors = sum(1 for a in result.attempts if a.status == "ERROR")

    verified_attempt_number: Optional[int] = None
    for a in result.attempts:
        if a.status == "VERIFIED":
            verified_attempt_number = a.attempt_number
            break

    existing_pass = sum(
        1
        for a in result.attempts
        if a.execution is not None and a.execution.existing_tests.passed
    )
    security_pass = sum(
        1
        for a in result.attempts
        if a.execution is not None and a.execution.security_tests.passed
    )

    durations = [a.duration_seconds for a in result.attempts]

    strategies = [a.plan.strategy for a in result.attempts]

    feedback_loops = sum(
        1
        for a in result.attempts
        if a.failure_feedback is not None
    )

    return WorkflowMetrics(
        workflow_id=result.workflow_id,
        final_status=result.status,
        total_attempts=total_attempts,
        verified_attempt_number=verified_attempt_number,
        rejected_attempt_count=rejected,
        error_attempt_count=errors,
        automated_stages_per_attempt=_STAGES_PER_ATTEMPT,
        total_automated_stages=_STAGES_PER_ATTEMPT * total_attempts,
        existing_test_pass_count=existing_pass,
        security_test_pass_count=security_pass,
        workflow_duration_seconds=result.duration_seconds,
        attempt_durations_seconds=durations,
        finding_type=result.original_finding.vulnerability_type,
        finding_severity=result.original_finding.severity,
        strategies_attempted=strategies,
        feedback_loops_triggered=feedback_loops,
    )
