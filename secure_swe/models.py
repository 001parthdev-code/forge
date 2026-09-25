"""
Data models for Secure SWE Agent.

All models are plain dataclasses and are JSON-serializable via dataclasses.asdict().
"""

from __future__ import annotations

import dataclasses
from typing import Dict, List, Literal, Optional, Union


@dataclasses.dataclass
class FileEntry:
    """Represents a single file discovered during repository inspection."""

    # Path relative to the repository root, using forward-slash separators.
    relative_path: str

    # File extension including the leading dot (e.g. ".py"), or "" for no extension.
    extension: str

    # Size of the file in bytes.
    size_bytes: int

    # True when the file was successfully decoded as UTF-8 text.
    is_text: bool

    # SHA-256 hex digest of the raw file bytes.
    # None only when the file could not be read at all.
    sha256: Optional[str]

    # Text content of the file.
    # None when: binary file, file exceeds CONTENT_SIZE_LIMIT, or read error.
    content: Optional[str]

    # Human-readable reason why content is absent, or None when content is present.
    content_omission_reason: Optional[str]

    # Human-readable error message if the file could not be read, else None.
    read_error: Optional[str]


@dataclasses.dataclass
class InventorySummary:
    """Aggregate statistics for a RepoInventory."""

    # Total number of files in the inventory.
    total_files: int

    # Sum of size_bytes across all FileEntry records.
    total_size_bytes: int

    # Mapping of file extension → count.  Files with no extension use the key "".
    count_by_extension: Dict[str, int]

    # Number of FileEntry records that carry a read_error.
    inspection_error_count: int


@dataclasses.dataclass
class RepoInventory:
    """
    Complete, deterministic snapshot of a repository's file tree.

    Files are sorted lexicographically by relative_path.
    This is the output contract of inspect_repository() and the input contract
    of the downstream security-analysis module.
    """

    # Absolute path to the repository root as supplied to inspect_repository().
    repo_root: str

    # Ordered list of file entries (sorted by relative_path).
    files: List[FileEntry]

    # Aggregate summary statistics.
    summary: InventorySummary

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialisation."""
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Module 2 — Security Analyzer models
# ---------------------------------------------------------------------------

# Severity levels ordered from highest to lowest impact.
Severity = Literal["HIGH", "MEDIUM", "LOW", "INFO"]

# Confidence levels reflecting the strength of evidence.
Confidence = Literal["HIGH", "MEDIUM", "LOW"]


@dataclasses.dataclass
class SecurityFinding:
    """
    A single, evidence-backed security finding produced by the Security Analyzer.

    All fields are JSON-serializable via dataclasses.asdict().

    The *id* is a deterministic hex digest derived from the combination of
    (vulnerability_type, file, line, sink) so that re-analyzing an identical
    inventory yields identical IDs.
    """

    # Stable, deterministic identifier for this specific finding instance.
    # SHA-256 hex of "<vulnerability_type>|<file>|<line>|<sink>".
    id: str

    # Short label for the class of vulnerability (e.g. "command_injection").
    vulnerability_type: str

    # Assessed severity.
    severity: Severity

    # Repository-relative path of the file containing the finding.
    file: str

    # 1-based line number of the dangerous sink call.
    line: int

    # String representation of the dangerous sink expression (e.g. "os.system").
    sink: str

    # Verbatim source snippet or reconstructed expression that demonstrates
    # how dynamic input reaches the sink.  Kept short (single line preferred).
    evidence: str

    # Human-readable explanation of why this pattern is security-relevant.
    reason: str

    # Confidence level in the finding.
    confidence: Confidence

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialisation."""
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Module 3 — Remediation Planner models
# ---------------------------------------------------------------------------

# Remediation strategy labels.
RemediationStrategy = Literal[
    "replace_shell_string_with_arg_list",
    "replace_os_system_with_subprocess_list",
    "unsupported",
    "planning_failure",
]


@dataclasses.dataclass
class RemediationPlan:
    """
    A deterministic, evidence-backed remediation plan produced by the
    Remediation Planner for a single SecurityFinding.

    A plan NEVER modifies repository files.  It records *what* should be
    done and *why*, so that a later patch-application module can act on it.

    The *plan_id* is derived deterministically from the *finding_id*, so
    the same finding always produces the same plan identifier.

    All fields are JSON-serializable via dataclasses.asdict().
    """

    # Stable, deterministic identifier for this plan.
    # SHA-256 hex of "plan|<finding_id>", truncated to 16 chars.
    plan_id: str

    # The SecurityFinding.id that caused this plan.  Explicit traceability link.
    finding_id: str

    # Mirrors SecurityFinding.vulnerability_type for convenience.
    vulnerability_type: str

    # Repository-relative path of the file to be remediated.
    target_file: str

    # 1-based line number of the dangerous sink call.
    target_line: int

    # Machine-readable strategy label.
    strategy: RemediationStrategy

    # The security invariant this plan enforces.
    security_invariant: str

    # Human-readable explanation of the chosen strategy.
    reason: str

    # Verbatim source snippet of the vulnerable expression (from the finding).
    original_code: str

    # Proposed replacement code snippet.
    # None when strategy is "unsupported" or "planning_failure".
    proposed_code: Optional[str]

    # Ordered list of requirements a later verification stage must satisfy.
    validation_requirements: List[str]

    # Planner confidence in the proposed transformation.
    confidence: Confidence

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialisation."""
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Module 4 — Controlled Patcher models
# ---------------------------------------------------------------------------

# Possible outcomes of a patch-application attempt.
PatchStatus = Literal[
    "applied",
    "already_applied",
    "drift_detected",
    "path_traversal",
    "target_missing",
    "unsupported_strategy",
    "write_error",
]


@dataclasses.dataclass
class AppliedPatch:
    """
    Record of a single patch-application attempt performed by the Controlled
    Patcher.

    Traceability chain:
        SecurityFinding → RemediationPlan → AppliedPatch

    All fields are JSON-serializable via dataclasses.asdict() / to_dict().
    """

    # Deterministic identifier: SHA-256 hex of "patch|<plan_id>", 16 chars.
    patch_id: str

    # The RemediationPlan.plan_id that authorised this patch.
    plan_id: str

    # The SecurityFinding.id that originated the plan.  Preserved for full
    # traceability: finding → plan → patch.
    finding_id: str

    # Repository-relative path of the file that was (or was to be) modified.
    target_file: str

    # SHA-256 hex digest of the target file *before* the patch was applied.
    # None when the file could not be read (e.g. target_missing).
    before_sha256: Optional[str]

    # SHA-256 hex digest of the target file *after* a successful patch.
    # None when applied is False.
    after_sha256: Optional[str]

    # Verbatim original code fragment that was replaced (mirrors plan.original_code).
    original_code: str

    # Verbatim replacement code that was written (mirrors plan.proposed_code).
    # None when the plan carried no proposed_code.
    replacement_code: Optional[str]

    # True when the patch was written to disk and the file was mutated.
    applied: bool

    # One of the PatchStatus literals above.
    status: PatchStatus

    # Human-readable explanation when applied is False, else None.
    failure_reason: Optional[str]

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialisation."""
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Module 5 — Security Test Generator models
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class SecurityRegressionTest:
    """
    A behavioral security regression test produced by the Test Generator.

    Traceability chain:
        SecurityFinding → RemediationPlan → AppliedPatch → SecurityRegressionTest

    The test is intended to provide behavioral evidence that the remediated
    implementation treats dynamic/untrusted input as data, not as shell syntax.
    It does NOT execute real processes; mock-based verification is used instead.

    All fields are JSON-serializable via dataclasses.asdict() / to_dict().
    """

    # Deterministic identifier: SHA-256 hex of "sectest|<patch_id>", 16 chars.
    test_id: str

    # The SecurityFinding.id this test guards against.  Explicit traceability.
    finding_id: str

    # The RemediationPlan.plan_id that produced the patch under test.
    plan_id: str

    # The AppliedPatch.patch_id that this test verifies.
    patch_id: str

    # Repository-relative path of the file under test.
    target_file: str

    # Repository-relative path where this test should be written.
    test_file: str

    # Name of the test function (importable pytest test name).
    test_name: str

    # One-line description of the security property this test exercises.
    security_property: str

    # Complete source code of the generated test function (a valid Python string).
    test_code: str

    # Human-readable description of the behavior the test must confirm.
    expected_behavior: str

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialisation."""
        return dataclasses.asdict(self)


@dataclasses.dataclass
class DesiredOutcome:
    """
    Explicit specification of what the bounded engineering loop must achieve
    before a remediation attempt is considered complete.

    This model describes the *desired state*.  It does NOT record whether the
    state has been reached — that is the responsibility of a later Verifier.

    Traceability chain:
        SecurityFinding → DesiredOutcome

    All fields are JSON-serializable via dataclasses.asdict() / to_dict().
    """

    # Deterministic identifier: SHA-256 hex of "outcome|<finding_id>", 16 chars.
    outcome_id: str

    # The SecurityFinding.id this outcome specifies.
    finding_id: str

    # Ordered list of security invariants the remediation must enforce.
    # None of these are satisfied at creation time; satisfaction is verified
    # externally by a later Verifier module.
    security_invariants: List[str]

    # Ordered list of regression requirements that must hold after remediation.
    regression_requirements: List[str]

    # Ordered list of independent verification requirements.
    verification_requirements: List[str]

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialisation."""
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Module 6 — Executor models
# ---------------------------------------------------------------------------

# Category distinguishing which test suite produced the result.
TestCategory = Literal["existing", "security"]


@dataclasses.dataclass
class ExecutionResult:
    """
    Structured evidence from a single test-suite execution.

    SECURITY NOTE
    -------------
    The current executor uses subprocess without container isolation.
    It is a *controlled* execution mechanism — it enforces argument arrays,
    timeouts, and working-directory constraints — but it does NOT provide
    host-level OS sandboxing.  A future Rust enforcement boundary may add
    stronger isolation.  Do not treat ``passed=True`` as evidence of sandboxed
    execution.

    All fields are JSON-serializable via dataclasses.asdict().
    """

    # The exact argument array passed to subprocess (no shell expansion).
    command: List[str]

    # Process exit code, or -1 when the process was killed by timeout.
    exit_code: int

    # Captured standard output (UTF-8, errors replaced).
    stdout: str

    # Captured standard error (UTF-8, errors replaced).
    stderr: str

    # Wall-clock duration in seconds.
    duration_seconds: float

    # True when the process was terminated because it exceeded the timeout.
    timed_out: bool

    # True only when exit_code == 0 AND timed_out is False.
    # NEVER inferred from stdout content alone.
    passed: bool

    # Which test suite this result represents ("existing" or "security").
    test_category: TestCategory

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialisation."""
        return dataclasses.asdict(self)


@dataclasses.dataclass
class TestSuiteResult:
    """
    Combined execution evidence from both test suites run against a workspace.

    overall_passed is True only when BOTH suites passed.

    All fields are JSON-serializable via dataclasses.asdict().
    """

    # Result of running the project's pre-existing test suite.
    existing_tests: ExecutionResult

    # Result of running the generated security regression test.
    security_tests: ExecutionResult

    # True only when both existing_tests.passed AND security_tests.passed.
    overall_passed: bool

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialisation."""
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Module 7 — Verifier models
# ---------------------------------------------------------------------------

# All possible reasons a verification can fail.
VerificationFailureReason = Literal[
    "patch_not_applied",
    "existing_tests_failed",
    "security_regression_failed",
    "finding_still_present",
    "security_invariant_failed",
    "execution_timeout",
]


@dataclasses.dataclass
class VerificationResult:
    """
    Independent verification outcome for one remediation attempt.

    ``verified`` is True ONLY when ALL of the following hold:

        1. patch.applied is True
        2. existing_tests_passed is True
        3. security_tests_passed is True
        4. security_invariant_satisfied is True
        5. finding_eliminated is True

    Every condition is independently evaluated.  ``tests passed`` alone does
    NOT imply ``security verified``.  ``finding disappeared`` alone does NOT
    imply ``behavior preserved``.

    All fields are JSON-serializable via dataclasses.asdict().
    """

    # Stable identifier: SHA-256 hex of "verify|<patch_id>|<attempt>", 16 chars.
    verification_id: str

    # Traceability links.
    finding_id: str
    plan_id: str
    patch_id: str
    attempt_number: int

    # Individual verification dimensions.
    existing_tests_passed: bool
    security_tests_passed: bool
    security_invariant_satisfied: bool
    finding_eliminated: bool

    # Composite: True only when ALL four dimensions above are True AND patch
    # was successfully applied.
    verified: bool

    # Structured list of failure reasons; empty when verified is True.
    failure_reasons: List[VerificationFailureReason]

    # Human-readable summary of what was verified and why it passed or failed.
    evidence: str

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialisation."""
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Module 8 — Attempt models
# ---------------------------------------------------------------------------

# Terminal status of one remediation attempt.
AttemptStatus = Literal["VERIFIED", "REJECTED", "ERROR"]


@dataclasses.dataclass
class FailureFeedback:
    """
    Structured failure evidence produced by a rejected remediation attempt.

    This is consumed by the planner in the NEXT attempt to guide a *revised*
    remediation strategy rather than blindly repeating the previous one.

    All fields are JSON-serializable via dataclasses.asdict().
    """

    # Which attempt number this feedback originates from.
    attempt_number: int

    # The plan that was tried and failed.
    previous_plan_id: str
    previous_strategy: str

    # Names of existing tests that failed (empty when existing tests passed).
    failed_existing_tests: List[str]

    # Names of security regression tests that failed (empty when they passed).
    failed_security_tests: List[str]

    # Security findings still detected in the patched workspace.
    # Each entry is a finding_id string.
    remaining_security_finding_ids: List[str]

    # Structured verification failure codes from VerificationResult.
    verification_failures: List[str]

    # Human-readable summary suitable for guiding the next remediation attempt.
    summary: str

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialisation."""
        return dataclasses.asdict(self)


@dataclasses.dataclass
class AttemptResult:
    """
    Complete evidence record for one remediation attempt.

    Every attempt — whether it succeeds or fails — produces an inspectable
    evidence trail.  No attempt is silently discarded.

    All fields are JSON-serializable via dataclasses.asdict().
    """

    # 1-based attempt counter within the current workflow.
    attempt_number: int

    # --- Input artifacts ---
    finding: SecurityFinding
    plan: RemediationPlan
    patch: AppliedPatch
    security_test: SecurityRegressionTest
    desired_outcome: DesiredOutcome

    # --- Execution and verification evidence ---
    # None when execution could not be started (e.g. workspace error).
    execution: Optional[TestSuiteResult]

    # None when execution did not complete (e.g. error before verification).
    verification: Optional[VerificationResult]

    # Terminal status for this attempt.
    status: AttemptStatus

    # Populated when status is REJECTED; None when VERIFIED or ERROR.
    failure_feedback: Optional[FailureFeedback]

    # Wall-clock duration of this attempt in seconds.
    duration_seconds: float

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialisation."""
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Module 9 — Workflow result model
# ---------------------------------------------------------------------------

# Final status of the complete remediation workflow.
WorkflowStatus = Literal["VERIFIED", "HUMAN_REVIEW_REQUIRED", "ERROR"]


@dataclasses.dataclass
class RemediationWorkflowResult:
    """
    Top-level result of the bounded remediation engineering loop.

    CANONICAL REPOSITORY SAFETY
    ---------------------------
    A VERIFIED status means the remediation passed all checks in an isolated
    workspace.  The successful workspace is *retained* but the patch is NOT
    automatically written back to the caller's original repository.

    Applying the verified patch to the canonical repository is a separate,
    explicit decision.  The ``final_patch`` field contains the authorised
    patch artifact; ``workspace_path`` contains the retained workspace.

    All fields are JSON-serializable via dataclasses.asdict().
    """

    # Stable workflow run identifier: UUID4 hex string.
    workflow_id: str

    # The SecurityFinding this workflow was initiated for.
    original_finding: SecurityFinding

    # VERIFIED, HUMAN_REVIEW_REQUIRED, or ERROR.
    status: WorkflowStatus

    # Number of remediation attempts made (≤ max_attempts).
    attempt_count: int

    # Complete ordered evidence trail — one AttemptResult per attempt.
    attempts: List[AttemptResult]

    # Present when status is VERIFIED; None otherwise.
    final_verification: Optional[VerificationResult]

    # Present when status is VERIFIED; None otherwise.
    final_patch: Optional[AppliedPatch]

    # Absolute path to the retained successful workspace when VERIFIED.
    # None when status is not VERIFIED.
    # NOTE: This workspace is NOT automatically applied to the source
    # repository.  The caller is responsible for that decision.
    workspace_path: Optional[str]

    # Total wall-clock duration of the workflow in seconds.
    duration_seconds: float

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialisation."""
        return dataclasses.asdict(self)
