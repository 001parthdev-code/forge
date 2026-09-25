"""
Module 8 — Bounded Remediation Orchestrator

Coordinates the complete Secure SWE engineering loop:

    inspect → analyze → select finding → define desired outcome
        ↓
    FOR attempt = 1..MAX_ATTEMPTS
        create clean isolated workspace
        plan (using failure feedback from previous attempt if available)
        patch
        generate security test + persist it
        execute both test suites
        independently verify outcome
        IF VERIFIED → stop, return success + evidence
        ELSE → collect structured failure feedback, discard workspace, continue
    END
        ↓
    HUMAN_REVIEW_REQUIRED (if all attempts exhausted)

Architecture boundary
---------------------
This module MUST NOT:
  * duplicate the internal logic of any upstream module;
  * select a finding without checking plan support;
  * allow attempt N to begin from attempt N-1's failed workspace;
  * loop forever — MAX_ATTEMPTS is a hard ceiling.

It MUST:
  * create a clean isolated workspace per attempt (baseline snapshot);
  * discard failed workspaces after feedback extraction;
  * retain the successful workspace when VERIFIED (not auto-apply to repo);
  * produce a RemediationWorkflowResult with the full evidence trail.

CANONICAL REPOSITORY SAFETY
----------------------------
A successful workflow does NOT write changes back to the caller's original
repository.  The caller receives:
  * final_patch  — the authorised AppliedPatch artifact
  * workspace_path — path to the retained successful workspace

Applying the verified patch to the source repository is a SEPARATE,
EXPLICIT decision that must be made by the caller.

Public interface
----------------
  run_secure_remediation(repo_path, max_attempts=3, timeout_seconds=60)
      -> RemediationWorkflowResult
"""

from __future__ import annotations

import logging
import shutil
import tempfile
import time
import uuid
from pathlib import Path
from typing import List, Optional

from secure_swe.analyzer import analyze_inventory
from secure_swe.executor import DEFAULT_TIMEOUT_SECONDS, run_test_suites
from secure_swe.inspector import inspect_repository
from secure_swe.models import (
    AppliedPatch,
    AttemptResult,
    AttemptStatus,
    DesiredOutcome,
    FailureFeedback,
    RemediationPlan,
    RemediationWorkflowResult,
    SecurityFinding,
    SecurityRegressionTest,
    TestSuiteResult,
    VerificationResult,
    WorkflowStatus,
)
from secure_swe.patcher import apply_remediation
from secure_swe.remediator import plan_remediation, plan_remediation_with_feedback
from secure_swe.test_generator import (
    GenerationError,
    TraceabilityError,
    generate_security_test,
    persist_security_test,
)
from secure_swe.verifier import verify_remediation, _extract_failed_test_names

logger = logging.getLogger(__name__)

# Hard ceiling on remediation attempts.
MAX_ATTEMPTS: int = 3

# Minimum and maximum values accepted via the parameter.
_MIN_ATTEMPTS: int = 1
_MAX_ATTEMPTS_LIMIT: int = 5


# ---------------------------------------------------------------------------
# Workspace management
# ---------------------------------------------------------------------------


def _create_workspace(baseline: Path, attempt_number: int) -> Path:
    """
    Create a clean isolated copy of *baseline* for attempt *attempt_number*.

    Each attempt receives its own directory so that a failed attempt cannot
    contaminate the starting state of the next attempt.

    The workspace is created inside a system temporary directory.  The caller
    is responsible for cleaning it up on failure (call _discard_workspace).
    A successful workspace is RETAINED so the caller can inspect or apply it.
    """
    ws_name = f"secure_swe_attempt_{attempt_number:03d}"
    parent = Path(tempfile.gettempdir()) / "secure_swe_workspaces"
    parent.mkdir(parents=True, exist_ok=True)

    # Add a short unique suffix to avoid collisions across concurrent runs.
    ws = parent / f"{ws_name}_{uuid.uuid4().hex[:8]}"
    shutil.copytree(str(baseline), str(ws))
    logger.debug("Created workspace '%s' for attempt %d.", ws, attempt_number)
    return ws


def _discard_workspace(workspace: Path) -> None:
    """Delete a failed attempt's workspace directory."""
    try:
        shutil.rmtree(str(workspace), ignore_errors=True)
        logger.debug("Discarded workspace '%s'.", workspace)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not discard workspace '%s': %s", workspace, exc)


# ---------------------------------------------------------------------------
# Failure feedback builder
# ---------------------------------------------------------------------------


def _build_failure_feedback(
    attempt_number: int,
    plan: RemediationPlan,
    suite_result: Optional[TestSuiteResult],
    verification: Optional[VerificationResult],
) -> FailureFeedback:
    """
    Extract structured failure evidence for the next remediation attempt.

    This is the engineering loop's memory: the next attempt receives
    richer context than "it failed".
    """
    failed_existing: List[str] = []
    failed_security: List[str] = []
    remaining_finding_ids: List[str] = []
    verification_failures: List[str] = []

    if suite_result is not None:
        if not suite_result.existing_tests.passed:
            failed_existing = _extract_failed_test_names(
                suite_result.existing_tests.stdout + suite_result.existing_tests.stderr
            )
        if not suite_result.security_tests.passed:
            failed_security = _extract_failed_test_names(
                suite_result.security_tests.stdout + suite_result.security_tests.stderr
            )

    if verification is not None:
        verification_failures = list(verification.failure_reasons)
        if "finding_still_present" in verification.failure_reasons:
            remaining_finding_ids = [verification.finding_id]

    # Build a human-readable summary for the next planner invocation.
    summary_parts: List[str] = [
        f"Attempt {attempt_number} used strategy '{plan.strategy}' and was rejected.",
    ]
    if failed_existing:
        summary_parts.append(f"Existing tests that failed: {failed_existing}.")
    if failed_security:
        summary_parts.append(f"Security regression tests that failed: {failed_security}.")
    if remaining_finding_ids:
        summary_parts.append(
            f"The original finding was still detected after patching.  "
            f"Finding IDs still present: {remaining_finding_ids}."
        )
    if verification_failures:
        summary_parts.append(f"Verification failure codes: {verification_failures}.")

    return FailureFeedback(
        attempt_number=attempt_number,
        previous_plan_id=plan.plan_id,
        previous_strategy=plan.strategy,
        failed_existing_tests=failed_existing,
        failed_security_tests=failed_security,
        remaining_security_finding_ids=remaining_finding_ids,
        verification_failures=verification_failures,
        summary="  ".join(summary_parts),
    )


# ---------------------------------------------------------------------------
# Finding selection
# ---------------------------------------------------------------------------


def _select_supported_finding(
    findings: List[SecurityFinding],
    inventory,
    baseline: Optional[Path] = None,
) -> Optional[SecurityFinding]:
    """
    Return the first finding for which the planner can produce an actionable
    plan AND the plan's original_code is present in the target file.

    This pre-check avoids selecting a finding whose plan would immediately
    fail with drift_detected (e.g. because ast.unparse() produces a
    representation that doesn't match the verbatim source).

    Skips findings whose plan strategy is "unsupported" or "planning_failure",
    and also skips findings whose original_code is absent from the target file.
    Returns None when no suitable finding exists.
    """
    sink_priority = {
        "os.system": 0,
        "subprocess.run": 1,
        "subprocess.call": 2,
        "subprocess.Popen": 3,
    }
    ordered_findings = sorted(
        findings,
        key=lambda f: (sink_priority.get(f.sink, 99), f.file, f.line),
    )
    for finding in ordered_findings:
        plan = plan_remediation(finding, inventory)
        if plan.strategy in ("unsupported", "planning_failure"):
            continue
        if plan.proposed_code is None:
            continue
        # Quick patchability pre-check: verify the original code is present.
        if baseline is not None:
            target = baseline / plan.target_file
            if target.exists():
                try:
                    content = target.read_text(encoding="utf-8", errors="replace")
                    if plan.original_code not in content:
                        continue  # Would produce drift_detected — skip.
                except Exception:
                    pass
        return finding
    return None


# ---------------------------------------------------------------------------
# Single-attempt execution
# ---------------------------------------------------------------------------


def _run_attempt(
    baseline: Path,
    finding: SecurityFinding,
    attempt_number: int,
    previous_feedback: Optional[FailureFeedback],
    timeout_seconds: int,
) -> tuple[AttemptResult, Optional[Path]]:
    """
    Execute one complete remediation attempt.

    Returns (AttemptResult, workspace_path_if_not_discarded).

    The workspace is retained when the attempt is VERIFIED; it is discarded
    (and None returned) for REJECTED or ERROR attempts.
    """
    start = time.monotonic()
    workspace: Optional[Path] = None

    try:
        # --- 1. Create clean isolated workspace ---
        workspace = _create_workspace(baseline, attempt_number)

        # --- 2. Inspect baseline from workspace ---
        inventory = inspect_repository(workspace)

        # --- 3. Plan (with failure feedback if this is a retry) ---
        if previous_feedback is not None:
            plan = plan_remediation_with_feedback(finding, inventory, previous_feedback)
        else:
            plan = plan_remediation(finding, inventory)

        # Guard: if planning failed, return ERROR immediately.
        if plan.strategy in ("unsupported", "planning_failure"):
            logger.info(
                "Attempt %d: planning failed (%s).", attempt_number, plan.strategy
            )
            duration = time.monotonic() - start
            # Produce a synthetic unapplied patch for the evidence trail.
            from secure_swe.patcher import _patch_id
            synthetic_patch = AppliedPatch(
                patch_id=_patch_id(plan.plan_id),
                plan_id=plan.plan_id,
                finding_id=plan.finding_id,
                target_file=plan.target_file,
                before_sha256=None,
                after_sha256=None,
                original_code=plan.original_code,
                replacement_code=plan.proposed_code,
                applied=False,
                status="unsupported_strategy",
                failure_reason=plan.reason,
            )
            # Synthetic test / outcome for evidence trail.
            synthetic_test, desired_outcome = _synthetic_test_and_outcome(finding, plan)
            attempt = AttemptResult(
                attempt_number=attempt_number,
                finding=finding,
                plan=plan,
                patch=synthetic_patch,
                security_test=synthetic_test,
                desired_outcome=desired_outcome,
                execution=None,
                verification=None,
                status="ERROR",
                failure_feedback=None,
                duration_seconds=time.monotonic() - start,
            )
            _discard_workspace(workspace)
            return attempt, None

        # --- 4. Apply patch ---
        patch = apply_remediation(workspace, plan)

        if not patch.applied:
            logger.info(
                "Attempt %d: patch not applied (status: %s).",
                attempt_number,
                patch.status,
            )
            synthetic_test, desired_outcome = _synthetic_test_and_outcome(finding, plan)
            feedback = _build_failure_feedback(attempt_number, plan, None, None)
            attempt = AttemptResult(
                attempt_number=attempt_number,
                finding=finding,
                plan=plan,
                patch=patch,
                security_test=synthetic_test,
                desired_outcome=desired_outcome,
                execution=None,
                verification=None,
                status="REJECTED",
                failure_feedback=feedback,
                duration_seconds=time.monotonic() - start,
            )
            _discard_workspace(workspace)
            workspace = None
            return attempt, None

        # --- 5. Generate and persist security regression test ---
        try:
            security_test, desired_outcome = generate_security_test(
                finding, plan, patch, inventory
            )
            persist_security_test(security_test, workspace)
        except (TraceabilityError, GenerationError) as exc:
            logger.warning(
                "Attempt %d: security test generation failed: %s",
                attempt_number,
                exc,
            )
            # Treat generation failure as ERROR — we cannot verify without a test.
            attempt = AttemptResult(
                attempt_number=attempt_number,
                finding=finding,
                plan=plan,
                patch=patch,
                security_test=_empty_security_test(finding, plan, patch),
                desired_outcome=_empty_desired_outcome(finding),
                execution=None,
                verification=None,
                status="ERROR",
                failure_feedback=None,
                duration_seconds=time.monotonic() - start,
            )
            _discard_workspace(workspace)
            workspace = None
            return attempt, None

        # --- 6. Execute both test suites ---
        suite_result = run_test_suites(
            workspace,
            security_test.test_file,
            timeout_seconds=timeout_seconds,
        )

        # --- 7. Independently verify outcome ---
        verification = verify_remediation(
            finding=finding,
            plan=plan,
            patch=patch,
            desired_outcome=desired_outcome,
            suite_result=suite_result,
            workspace=workspace,
            attempt_number=attempt_number,
        )

        # --- 8. Determine attempt status ---
        if verification.verified:
            status: AttemptStatus = "VERIFIED"
            feedback = None
            logger.info("Attempt %d: VERIFIED.", attempt_number)
        else:
            status = "REJECTED"
            feedback = _build_failure_feedback(
                attempt_number, plan, suite_result, verification
            )
            logger.info(
                "Attempt %d: REJECTED — %s",
                attempt_number,
                ", ".join(verification.failure_reasons),
            )

        attempt = AttemptResult(
            attempt_number=attempt_number,
            finding=finding,
            plan=plan,
            patch=patch,
            security_test=security_test,
            desired_outcome=desired_outcome,
            execution=suite_result,
            verification=verification,
            status=status,
            failure_feedback=feedback,
            duration_seconds=time.monotonic() - start,
        )

        if verification.verified:
            # Retain the workspace — do NOT discard it.
            return attempt, workspace
        else:
            _discard_workspace(workspace)
            workspace = None
            return attempt, None

    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "Attempt %d raised an unexpected exception: %s", attempt_number, exc
        )
        duration = time.monotonic() - start
        if workspace is not None:
            _discard_workspace(workspace)
        # Build a minimal error evidence record.
        from secure_swe.patcher import _patch_id as _pid
        from secure_swe.remediator import _plan_id as _plid
        dummy_plan = RemediationPlan(
            plan_id=_plid(finding.id),
            finding_id=finding.id,
            vulnerability_type=finding.vulnerability_type,
            target_file=finding.file,
            target_line=finding.line,
            strategy="planning_failure",
            security_invariant="",
            reason=f"Orchestrator internal error: {exc}",
            original_code=finding.evidence,
            proposed_code=None,
            validation_requirements=[],
            confidence="LOW",
        )
        dummy_patch = AppliedPatch(
            patch_id=_pid(dummy_plan.plan_id),
            plan_id=dummy_plan.plan_id,
            finding_id=finding.id,
            target_file=finding.file,
            before_sha256=None,
            after_sha256=None,
            original_code=finding.evidence,
            replacement_code=None,
            applied=False,
            status="unsupported_strategy",
            failure_reason=str(exc),
        )
        synthetic_test, desired_outcome = _synthetic_test_and_outcome(finding, dummy_plan)
        attempt = AttemptResult(
            attempt_number=attempt_number,
            finding=finding,
            plan=dummy_plan,
            patch=dummy_patch,
            security_test=synthetic_test,
            desired_outcome=desired_outcome,
            execution=None,
            verification=None,
            status="ERROR",
            failure_feedback=None,
            duration_seconds=duration,
        )
        return attempt, None


# ---------------------------------------------------------------------------
# Evidence-trail stubs for error paths
# ---------------------------------------------------------------------------


def _synthetic_test_and_outcome(
    finding: SecurityFinding,
    plan: RemediationPlan,
) -> tuple[SecurityRegressionTest, DesiredOutcome]:
    """Return minimal stub artifacts for error / planning-failure paths."""
    from secure_swe.models import DesiredOutcome, SecurityRegressionTest
    import hashlib

    patch_id_stub = hashlib.sha256(f"stub|{plan.plan_id}".encode()).hexdigest()[:16]
    test_id_stub = hashlib.sha256(f"sectest|{patch_id_stub}".encode()).hexdigest()[:16]
    outcome_id_stub = hashlib.sha256(f"outcome|{finding.id}".encode()).hexdigest()[:16]

    stub_test = SecurityRegressionTest(
        test_id=test_id_stub,
        finding_id=finding.id,
        plan_id=plan.plan_id,
        patch_id=patch_id_stub,
        target_file=finding.file,
        test_file="tests/security/_stub_not_generated.py",
        test_name="test_stub_not_generated",
        security_property="(not generated — planning or patch error)",
        test_code="# not generated",
        expected_behavior="(not available)",
    )
    stub_outcome = DesiredOutcome(
        outcome_id=outcome_id_stub,
        finding_id=finding.id,
        security_invariants=[],
        regression_requirements=[],
        verification_requirements=[],
    )
    return stub_test, stub_outcome


def _empty_security_test(
    finding: SecurityFinding,
    plan: RemediationPlan,
    patch: AppliedPatch,
) -> SecurityRegressionTest:
    from secure_swe.models import SecurityRegressionTest
    import hashlib

    test_id = hashlib.sha256(f"sectest|{patch.patch_id}".encode()).hexdigest()[:16]
    return SecurityRegressionTest(
        test_id=test_id,
        finding_id=finding.id,
        plan_id=plan.plan_id,
        patch_id=patch.patch_id,
        target_file=finding.file,
        test_file="tests/security/_generation_error.py",
        test_name="test_generation_error",
        security_property="(test generation failed)",
        test_code="# test generation failed",
        expected_behavior="(not available)",
    )


def _empty_desired_outcome(finding: SecurityFinding) -> DesiredOutcome:
    from secure_swe.models import DesiredOutcome
    import hashlib

    outcome_id = hashlib.sha256(f"outcome|{finding.id}".encode()).hexdigest()[:16]
    return DesiredOutcome(
        outcome_id=outcome_id,
        finding_id=finding.id,
        security_invariants=[],
        regression_requirements=[],
        verification_requirements=[],
    )


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def run_secure_remediation(
    repo_path: str,
    max_attempts: int = MAX_ATTEMPTS,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> RemediationWorkflowResult:
    """
    Run the complete bounded security remediation engineering loop.

    The loop:
      1. Inspects *repo_path* and selects the first finding with a supported plan.
      2. Iterates up to *max_attempts* times, each time:
         a. Creating a clean isolated workspace copy.
         b. Planning (revised if previous attempt failed).
         c. Patching, generating the security test, executing, verifying.
         d. Returning VERIFIED immediately on success.
         e. Collecting structured failure feedback and discarding the workspace.
      3. Returns HUMAN_REVIEW_REQUIRED if all attempts are exhausted.

    CANONICAL REPOSITORY SAFETY
    ----------------------------
    This function NEVER writes changes back to *repo_path*.  When the result
    status is VERIFIED, the successful workspace is retained at
    ``result.workspace_path`` for inspection or manual application.

    Parameters
    ----------
    repo_path:
        Absolute (or resolvable) path to the repository to remediate.
        This directory is NEVER modified.
    max_attempts:
        Maximum number of remediation attempts.  Hard ceiling: MAX_ATTEMPTS_LIMIT.
        Must be between 1 and 5 inclusive.
    timeout_seconds:
        Per-suite execution timeout in seconds.

    Returns
    -------
    RemediationWorkflowResult
        Always returns; never raises.  Inspect ``status`` for the outcome.
    """
    workflow_id = uuid.uuid4().hex
    workflow_start = time.monotonic()
    baseline = Path(repo_path).resolve()

    # Clamp max_attempts to the safe range.
    max_attempts = max(_MIN_ATTEMPTS, min(max_attempts, _MAX_ATTEMPTS_LIMIT))

    logger.info(
        "Workflow %s starting for '%s' (max_attempts=%d).",
        workflow_id,
        baseline,
        max_attempts,
    )

    attempts: List[AttemptResult] = []

    # ------------------------------------------------------------------
    # Phase 1: Inspect baseline and select a supported finding
    # ------------------------------------------------------------------
    try:
        inventory = inspect_repository(baseline)
        findings = analyze_inventory(inventory)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Workflow %s: baseline inspection failed: %s", workflow_id, exc)
        return RemediationWorkflowResult(
            workflow_id=workflow_id,
            original_finding=SecurityFinding(
                id="00000000000000",
                vulnerability_type="unknown",
                severity="HIGH",
                file="",
                line=0,
                sink="",
                evidence="",
                reason=f"Inspection failed: {exc}",
                confidence="LOW",
            ),
            status="ERROR",
            attempt_count=0,
            attempts=[],
            final_verification=None,
            final_patch=None,
            workspace_path=None,
            duration_seconds=time.monotonic() - workflow_start,
        )

    if not findings:
        logger.info("Workflow %s: no findings detected.", workflow_id)
        return RemediationWorkflowResult(
            workflow_id=workflow_id,
            original_finding=SecurityFinding(
                id="00000000000000",
                vulnerability_type="none_found",
                severity="INFO",
                file="",
                line=0,
                sink="",
                evidence="",
                reason="No security findings detected in the repository.",
                confidence="HIGH",
            ),
            status="HUMAN_REVIEW_REQUIRED",
            attempt_count=0,
            attempts=[],
            final_verification=None,
            final_patch=None,
            workspace_path=None,
            duration_seconds=time.monotonic() - workflow_start,
        )

    finding = _select_supported_finding(findings, inventory, baseline=baseline)
    if finding is None:
        logger.info("Workflow %s: no supported finding.", workflow_id)
        return RemediationWorkflowResult(
            workflow_id=workflow_id,
            original_finding=findings[0],
            status="HUMAN_REVIEW_REQUIRED",
            attempt_count=0,
            attempts=[],
            final_verification=None,
            final_patch=None,
            workspace_path=None,
            duration_seconds=time.monotonic() - workflow_start,
        )

    logger.info(
        "Workflow %s: selected finding '%s' (%s in '%s' line %d).",
        workflow_id,
        finding.id,
        finding.sink,
        finding.file,
        finding.line,
    )

    # ------------------------------------------------------------------
    # Phase 2: Bounded engineering loop
    # ------------------------------------------------------------------
    previous_feedback: Optional[FailureFeedback] = None
    final_status: WorkflowStatus = "HUMAN_REVIEW_REQUIRED"
    final_verification: Optional[VerificationResult] = None
    final_patch: Optional[AppliedPatch] = None
    final_workspace: Optional[Path] = None

    for attempt_num in range(1, max_attempts + 1):
        logger.info("Workflow %s: starting attempt %d/%d.", workflow_id, attempt_num, max_attempts)

        attempt_result, retained_workspace = _run_attempt(
            baseline=baseline,
            finding=finding,
            attempt_number=attempt_num,
            previous_feedback=previous_feedback,
            timeout_seconds=timeout_seconds,
        )
        attempts.append(attempt_result)

        if attempt_result.status == "VERIFIED":
            final_status = "VERIFIED"
            final_verification = attempt_result.verification
            final_patch = attempt_result.patch
            final_workspace = retained_workspace
            logger.info(
                "Workflow %s: VERIFIED at attempt %d.", workflow_id, attempt_num
            )
            break

        if attempt_result.status == "ERROR":
            # An unrecoverable error — no useful feedback to pass forward.
            # If this was the last attempt, fall through to HUMAN_REVIEW_REQUIRED.
            logger.warning(
                "Workflow %s: attempt %d ended with ERROR.", workflow_id, attempt_num
            )
            previous_feedback = None
            # Keep trying if attempts remain.
            continue

        # REJECTED — collect feedback for the next attempt.
        previous_feedback = attempt_result.failure_feedback

        # If the planner explicitly signalled it has no alternative strategy
        # (by producing a planning_failure in the feedback analysis), stop early.
        if previous_feedback is not None:
            # Check if the next plan would also fail (pre-screen).
            next_plan = plan_remediation_with_feedback(finding, inventory, previous_feedback)
            if next_plan.strategy in ("unsupported", "planning_failure"):
                logger.info(
                    "Workflow %s: planner has no alternative strategy after attempt %d.  "
                    "Stopping early.",
                    workflow_id,
                    attempt_num,
                )
                final_status = "HUMAN_REVIEW_REQUIRED"
                break

    else:
        # Loop exhausted without VERIFIED.
        final_status = "HUMAN_REVIEW_REQUIRED"
        logger.info(
            "Workflow %s: all %d attempts exhausted.  HUMAN_REVIEW_REQUIRED.",
            workflow_id,
            max_attempts,
        )

    return RemediationWorkflowResult(
        workflow_id=workflow_id,
        original_finding=finding,
        status=final_status,
        attempt_count=len(attempts),
        attempts=attempts,
        final_verification=final_verification,
        final_patch=final_patch,
        workspace_path=str(final_workspace) if final_workspace else None,
        duration_seconds=time.monotonic() - workflow_start,
    )
