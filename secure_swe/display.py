"""
Workflow Display — developer-facing console output for the Secure SWE workflow.

Renders a clear, staged view of:
    INSPECT → DETECT → ENGINEER (per attempt) → FINAL RESULT

Uses only stdlib (no rich/colorama dependency).
"""

from __future__ import annotations

import sys
from typing import Optional

from secure_swe.models import (
    AttemptResult,
    RemediationWorkflowResult,
)


# ---------------------------------------------------------------------------
# ANSI colour helpers (gracefully degraded if terminal doesn't support them)
# ---------------------------------------------------------------------------

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_MAGENTA = "\033[35m"
_WHITE = "\033[37m"


def _supports_ansi() -> bool:
    """Return True if the output terminal appears to support ANSI escapes."""
    if not hasattr(sys.stdout, "isatty"):
        return False
    if not sys.stdout.isatty():
        return False
    # Windows: colour works in modern terminals but not old cmd.exe
    return True


_USE_COLOUR = _supports_ansi()


def _c(text: str, *codes: str) -> str:
    if not _USE_COLOUR:
        return text
    prefix = "".join(codes)
    return f"{prefix}{text}{_RESET}"


def _bold(text: str) -> str:
    return _c(text, _BOLD)


def _dim(text: str) -> str:
    return _c(text, _DIM)


def _green(text: str) -> str:
    return _c(text, _GREEN)


def _red(text: str) -> str:
    return _c(text, _RED)


def _yellow(text: str) -> str:
    return _c(text, _YELLOW)


def _cyan(text: str) -> str:
    return _c(text, _CYAN)


def _magenta(text: str) -> str:
    return _c(text, _MAGENTA)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

_RULE = "─" * 44


def _rule() -> str:
    return _dim(_RULE)


def _section(label: str) -> str:
    return _bold(_c(f"[{label}]", _CYAN))


def _pass_label() -> str:
    return _c("PASS", _GREEN, _BOLD)


def _fail_label() -> str:
    return _c("FAIL", _RED, _BOLD)


def _status_label(status: str) -> str:
    if status == "VERIFIED":
        return _c("✓ VERIFIED", _GREEN, _BOLD)
    elif status == "REJECTED":
        return _c("✗ REJECTED", _RED, _BOLD)
    elif status == "ERROR":
        return _c("⚠ ERROR", _YELLOW, _BOLD)
    return status


def _trunc(text: str, max_len: int = 80) -> str:
    """Truncate long evidence strings for display."""
    text = text.replace("\n", " ").strip()
    if len(text) > max_len:
        return text[:max_len - 3] + "..."
    return text


# ---------------------------------------------------------------------------
# Display class
# ---------------------------------------------------------------------------


class WorkflowDisplay:
    """
    Renders the Secure SWE workflow to stdout.

    When ``quiet=True`` all output is suppressed (used with --json mode).
    """

    def __init__(self, quiet: bool = False) -> None:
        self._quiet = quiet

    def _out(self, text: str = "") -> None:
        if not self._quiet:
            print(text)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def header(self, repo_path: str) -> None:
        self._out()
        self._out(_bold("SECURE SWE"))
        self._out(_rule())
        self._out()
        self._out(f"  {_bold('Target')}")
        self._out(f"    {repo_path}")
        self._out()

    def render_result(self, result: RemediationWorkflowResult) -> None:
        """Render the full workflow result to stdout."""
        self._render_inspect(result)
        self._render_detect(result)
        self._render_engineer(result)
        self._render_final(result)

    # ------------------------------------------------------------------
    # Stage renderers
    # ------------------------------------------------------------------

    def _render_inspect(self, result: RemediationWorkflowResult) -> None:
        self._out(_section("INSPECT"))

        # Derive file count from attempt data if available
        file_count: Optional[int] = None
        if result.attempts:
            # Use finding file as a proxy; we don't have the raw inventory here
            pass

        self._out("  Repository inspected")
        if result.original_finding.file:
            self._out(f"  Target file: {result.original_finding.file}")
        self._out()

    def _render_detect(self, result: RemediationWorkflowResult) -> None:
        self._out(_section("DETECT"))

        f = result.original_finding
        if f.vulnerability_type == "none_found":
            self._out("  No security findings detected.")
            self._out()
            return

        self._out(f"  Finding:    {_bold(f.vulnerability_type.replace('_', ' ').title())}")
        self._out(f"  Severity:   {_bold(f.severity)}")
        self._out(f"  File:       {f.file}")
        self._out(f"  Line:       {f.line}")
        self._out(f"  Sink:       {f.sink}")
        self._out(f"  Evidence:   {_dim(_trunc(f.evidence))}")
        self._out()

    def _render_engineer(self, result: RemediationWorkflowResult) -> None:
        if not result.attempts:
            return

        self._out(_section("ENGINEER"))
        self._out()

        for attempt in result.attempts:
            self._render_attempt(attempt)

    def _render_attempt(self, attempt: AttemptResult) -> None:
        n = attempt.attempt_number
        self._out(f"  {_bold(f'Attempt {n}')}")
        self._out()

        # Plan
        plan = attempt.plan
        self._out(f"    {_bold('Plan')}")
        self._out(f"      Strategy:  {plan.strategy}")
        self._out(f"      Rationale: {_dim(_trunc(plan.reason, 70))}")
        if plan.proposed_code:
            self._out(f"      Proposed:  {_dim(_trunc(plan.proposed_code, 70))}")
        self._out()

        # Patch
        patch = attempt.patch
        self._out(f"    {_bold('Patch')}")
        self._out(f"      Applied:   {'yes' if patch.applied else 'no'}")
        if patch.before_sha256:
            self._out(f"      Before:    {patch.before_sha256[:16]}…")
        if patch.after_sha256:
            self._out(f"      After:     {patch.after_sha256[:16]}…")
        if not patch.applied and patch.failure_reason:
            self._out(f"      Reason:    {_dim(_trunc(patch.failure_reason, 70))}")
        self._out()

        # Test results
        if attempt.execution:
            ex = attempt.execution
            sec_label = _pass_label() if ex.security_tests.passed else _fail_label()
            reg_label = _pass_label() if ex.existing_tests.passed else _fail_label()
            self._out(f"    {_bold('Security Regression Test')}")
            self._out(f"      Result:    {sec_label}")
            if not ex.security_tests.passed:
                output_snippet = _trunc(
                    ex.security_tests.stdout + ex.security_tests.stderr, 120
                )
                if output_snippet:
                    self._out(f"      Output:    {_dim(output_snippet)}")
            self._out()
            self._out(f"    {_bold('Existing Tests')}")
            self._out(f"      Result:    {reg_label}")
            if not ex.existing_tests.passed:
                output_snippet = _trunc(
                    ex.existing_tests.stdout + ex.existing_tests.stderr, 120
                )
                if output_snippet:
                    self._out(f"      Output:    {_dim(output_snippet)}")
            self._out()
        else:
            self._out(f"    {_bold('Tests')}")
            self._out(f"      (skipped — patch not applied)")
            self._out()

        # Verification
        if attempt.verification:
            v = attempt.verification
            v_label = _pass_label() if v.verified else _fail_label()
            self._out(f"    {_bold('Verification')}")
            self._out(f"      Result:    {v_label}")
            if not v.verified and v.failure_reasons:
                reasons = ", ".join(v.failure_reasons)
                self._out(f"      Reasons:   {_red(reasons)}")
            if v.evidence:
                self._out(f"      Evidence:  {_dim(_trunc(v.evidence, 80))}")
            self._out()
        else:
            self._out(f"    {_bold('Verification')}")
            self._out(f"      (not reached)")
            self._out()

        # Attempt outcome
        status_str = _status_label(attempt.status)
        self._out(f"    Outcome:   {status_str}  ({attempt.duration_seconds:.1f}s)")

        # Failure feedback
        if attempt.failure_feedback and attempt.status != "VERIFIED":
            fb = attempt.failure_feedback
            self._out()
            self._out(f"    {_bold('Failure Evidence')}")
            self._out(f"      {_dim(_trunc(fb.summary, 120))}")
            self._out(f"    → starting clean attempt")

        self._out()

    def _render_final(self, result: RemediationWorkflowResult) -> None:
        self._out(_rule())
        self._out(_section("FINAL RESULT"))
        self._out()

        status = result.status
        if status == "VERIFIED":
            label = _c("  ✓  VERIFIED", _GREEN, _BOLD)
        elif status == "HUMAN_REVIEW_REQUIRED":
            label = _c("  ⚠  HUMAN_REVIEW_REQUIRED", _YELLOW, _BOLD)
        else:
            label = _c("  ✗  ERROR", _RED, _BOLD)

        self._out(label)
        self._out()
        self._out(f"  Attempts:  {result.attempt_count}")
        self._out(f"  Duration:  {result.duration_seconds:.2f}s")

        if result.status == "VERIFIED" and result.workspace_path:
            self._out(f"  Workspace: {result.workspace_path}")

        self._out()
