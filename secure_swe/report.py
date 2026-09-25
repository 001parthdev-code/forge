"""
Workflow Report — human-readable text summary of a RemediationWorkflowResult.

Produces a concise, evidence-backed report that makes it obvious:
- what was found
- what each attempt did
- why each attempt was accepted or rejected
- the final status and elapsed time

Public interface
----------------
    render_workflow_report(result) -> str
"""

from __future__ import annotations

from typing import Optional

from secure_swe.models import (
    AttemptResult,
    RemediationWorkflowResult,
)


def render_workflow_report(result: RemediationWorkflowResult) -> str:
    """
    Render a human-readable report from a RemediationWorkflowResult.

    Returns a multi-line string suitable for writing to a file or printing.
    """
    lines: list[str] = []

    def ln(text: str = "") -> None:
        lines.append(text)

    def rule(char: str = "─", width: int = 60) -> None:
        lines.append(char * width)

    rule("═")
    ln("SECURE SWE — WORKFLOW REPORT")
    rule("═")
    ln()

    # -----------------------------------------------------------------
    # Finding
    # -----------------------------------------------------------------
    ln("ORIGINAL FINDING")
    rule()
    f = result.original_finding
    ln(f"  Type:       {f.vulnerability_type}")
    ln(f"  Severity:   {f.severity}")
    ln(f"  File:       {f.file}")
    ln(f"  Line:       {f.line}")
    ln(f"  Sink:       {f.sink}")
    ln(f"  Evidence:   {f.evidence}")
    ln(f"  Confidence: {f.confidence}")
    ln(f"  Reason:     {_wrap(f.reason, indent=14, width=80)}")
    ln()

    # -----------------------------------------------------------------
    # Attempts
    # -----------------------------------------------------------------
    ln("REMEDIATION ATTEMPTS")
    rule()
    ln(f"  Total attempts: {result.attempt_count}")
    ln()

    for attempt in result.attempts:
        _render_attempt(ln, rule, attempt)

    # -----------------------------------------------------------------
    # Final status
    # -----------------------------------------------------------------
    ln("FINAL STATUS")
    rule()
    ln(f"  Status:   {result.status}")
    ln(f"  Duration: {result.duration_seconds:.2f}s")

    if result.status == "VERIFIED":
        if result.final_patch:
            p = result.final_patch
            ln(f"  Patch:    {p.patch_id}  ({p.status})")
            if p.before_sha256:
                ln(f"  Before:   {p.before_sha256[:32]}…")
            if p.after_sha256:
                ln(f"  After:    {p.after_sha256[:32]}…")
        if result.workspace_path:
            ln(f"  Workspace: {result.workspace_path}")
        if result.final_verification:
            v = result.final_verification
            ln(f"  Verification evidence: {_wrap(v.evidence, indent=26, width=80)}")
    elif result.status == "HUMAN_REVIEW_REQUIRED":
        ln()
        ln("  The remediation engine could not produce a verified fix within the")
        ln("  configured attempt budget.  Human review is required.")
        ln()
        if result.attempts:
            last = result.attempts[-1]
            if last.verification and last.verification.failure_reasons:
                ln(f"  Last failure reasons: {', '.join(last.verification.failure_reasons)}")
            elif last.failure_feedback:
                ln(f"  Last feedback: {_wrap(last.failure_feedback.summary, indent=18, width=80)}")

    ln()
    rule("═")
    ln()

    return "\n".join(lines)


def _render_attempt(
    ln,
    rule,
    attempt: AttemptResult,
) -> None:
    n = attempt.attempt_number
    ln(f"  Attempt {n}")
    rule("·")

    # Plan
    plan = attempt.plan
    ln(f"  Strategy:        {plan.strategy}")
    ln(f"  Confidence:      {plan.confidence}")
    ln(f"  Rationale:       {_wrap(plan.reason, indent=19, width=80)}")
    if plan.proposed_code:
        ln(f"  Proposed patch:  {plan.proposed_code}")
    ln()

    # Patch
    patch = attempt.patch
    ln(f"  Patch applied:   {'yes' if patch.applied else 'no'}")
    if patch.before_sha256:
        ln(f"  Before SHA256:   {patch.before_sha256[:32]}…")
    if patch.after_sha256:
        ln(f"  After SHA256:    {patch.after_sha256[:32]}…")
    if not patch.applied and patch.failure_reason:
        ln(f"  Patch failure:   {_wrap(patch.failure_reason, indent=19, width=80)}")
    ln()

    # Test results
    if attempt.execution:
        ex = attempt.execution
        sec_pass = "PASS" if ex.security_tests.passed else "FAIL"
        reg_pass = "PASS" if ex.existing_tests.passed else "FAIL"
        ln(f"  Existing tests:  {reg_pass}  (exit {ex.existing_tests.exit_code}, {ex.existing_tests.duration_seconds:.1f}s)")
        ln(f"  Security test:   {sec_pass}  (exit {ex.security_tests.exit_code}, {ex.security_tests.duration_seconds:.1f}s)")
        if not ex.existing_tests.passed:
            snippet = _snippet(ex.existing_tests.stdout + ex.existing_tests.stderr)
            if snippet:
                ln(f"  Existing output: {snippet}")
        if not ex.security_tests.passed:
            snippet = _snippet(ex.security_tests.stdout + ex.security_tests.stderr)
            if snippet:
                ln(f"  Security output: {snippet}")
    else:
        ln("  Tests:           (not executed — patch not applied)")
    ln()

    # Verification
    if attempt.verification:
        v = attempt.verification
        v_str = "VERIFIED" if v.verified else "REJECTED"
        ln(f"  Verification:    {v_str}")
        if v.failure_reasons:
            ln(f"  Failure reasons: {', '.join(v.failure_reasons)}")
        ln(f"  Evidence:        {_wrap(v.evidence, indent=19, width=80)}")
    else:
        ln("  Verification:    (not reached)")
    ln()

    # Attempt status
    ln(f"  Attempt status:  {attempt.status}  ({attempt.duration_seconds:.1f}s)")

    # Failure feedback
    if attempt.failure_feedback and attempt.status != "VERIFIED":
        fb = attempt.failure_feedback
        ln()
        ln(f"  FAILURE FEEDBACK (→ Attempt {n + 1} will use this)")
        ln(f"  {_wrap(fb.summary, indent=2, width=80)}")
        if fb.failed_existing_tests:
            ln(f"  Failed existing tests: {fb.failed_existing_tests}")
        if fb.failed_security_tests:
            ln(f"  Failed security tests: {fb.failed_security_tests}")

    ln()
    rule("·")
    ln()


def _wrap(text: str, indent: int = 0, width: int = 80) -> str:
    """
    Minimally wrap long text for report output.

    Replaces newlines with spaces and truncates to fit.  For a real report
    you would use textwrap; this keeps it dependency-free.
    """
    text = text.replace("\n", " ").strip()
    effective_width = width - indent
    if len(text) <= effective_width:
        return text
    # Truncate with a continuation marker.
    return text[:effective_width - 3] + "..."


def _snippet(output: str, max_len: int = 120) -> str:
    """Extract a useful snippet from test output."""
    if not output:
        return ""
    # Find first non-empty line that looks interesting
    for line in output.splitlines():
        line = line.strip()
        if line and not line.startswith("===") and not line.startswith("---"):
            if len(line) > max_len:
                line = line[:max_len - 3] + "..."
            return line
    return output[:max_len].replace("\n", " ")
