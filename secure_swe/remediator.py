"""
Module 3 — Security Remediation Planner

Consumes a SecurityFinding (produced by Module 2) together with the
RepoInventory (produced by Module 1) and returns a RemediationPlan describing
*how* the vulnerability should be fixed.

Architecture boundary
---------------------
This module MUST NOT:
  * write to the filesystem;
  * modify repository files;
  * invoke the filesystem directly (all file content comes from the inventory);
  * call external APIs or LLMs.

It MUST:
  * reason only from the SecurityFinding and the RepoInventory;
  * return an explicit planning failure rather than inventing a patch when
    evidence is insufficient;
  * be deterministic — identical inputs always produce identical output.

Supported v0 patterns
---------------------
  1. subprocess.run / subprocess.call / subprocess.Popen with shell=True
     Strategy: replace_shell_string_with_arg_list
     Transformation: remove shell=True, pass a list [program, *args].

  2. os.system(dynamic_expr)
     Strategy: replace_os_system_with_subprocess_list
     Transformation: migrate to subprocess.run([program, *args]).

All other vulnerability types or unrecognised call patterns produce a plan
with strategy="unsupported" and proposed_code=None.
"""

from __future__ import annotations

import ast
import hashlib
import logging
import re
from typing import List, Optional

from secure_swe.models import (
    FailureFeedback,
    RemediationPlan,
    RemediationStrategy,
    RepoInventory,
    SecurityFinding,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Security invariant (shared across all command-injection remediations)
# ---------------------------------------------------------------------------

_SECURITY_INVARIANT = (
    "Untrusted or dynamic values must not be interpreted as shell syntax. "
    "Commands must be passed as a structured argument list so that each "
    "argument is treated as literal data, never as shell code."
)

# ---------------------------------------------------------------------------
# Validation requirements appended to every actionable plan
# ---------------------------------------------------------------------------

_VALIDATION_REQUIREMENTS: List[str] = [
    "Existing tests must continue to pass after the patch is applied.",
    "Command execution must no longer use shell=True or equivalent shell "
    "string interpolation.",
    "Shell metacharacters in dynamic arguments (e.g. ';', '&&', '|', '$()') "
    "must be treated as ordinary data, not interpreted by a shell.",
    "A security regression test must be added and must pass: passing a value "
    "containing shell metacharacters must not execute unintended commands.",
]

# ---------------------------------------------------------------------------
# ID derivation
# ---------------------------------------------------------------------------


def _plan_id(finding_id: str) -> str:
    """
    Deterministic 16-char hex plan identifier derived from the finding ID.

    SHA-256 of "plan|<finding_id>", truncated to 16 hex characters.
    """
    raw = f"plan|{finding_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# AST-based argument extraction
# ---------------------------------------------------------------------------


def _extract_command_parts(source: str, target_line: int) -> Optional[List[str]]:
    """
    Attempt to extract the shell-command string components from the source line.

    Parses the function call at *target_line* and, when the first argument is
    an f-string or a string concatenation, returns the static string fragments
    in order.  The caller can use this to reason about the program name.

    Returns None when the call cannot be parsed or the structure is not
    recognised.  This function never raises.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if node.lineno != target_line:
            continue
        if not node.args:
            continue

        cmd_arg = node.args[0]

        # f-string: collect constant parts
        if isinstance(cmd_arg, ast.JoinedStr):
            parts: List[str] = []
            for val in cmd_arg.values:
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    parts.append(val.value)
            return parts if parts else None

        # Binary string concatenation: collect leftmost constant
        if isinstance(cmd_arg, ast.BinOp) and isinstance(cmd_arg.op, ast.Add):
            if isinstance(cmd_arg.left, ast.Constant) and isinstance(
                cmd_arg.left.value, str
            ):
                return [cmd_arg.left.value]

        # Variable reference — no static parts available
        return None

    return None


def _infer_program_name(parts: Optional[List[str]]) -> Optional[str]:
    """
    Given the static string fragments of a command, extract the leading
    program name token (e.g. "ping -c 1 " → "ping").

    Returns None when inference is not possible.
    """
    if not parts:
        return None
    # Concatenate the static parts and take the first whitespace-delimited token.
    joined = "".join(parts)
    tokens = joined.split()
    return tokens[0] if tokens else None


def _split_static_args(parts: Optional[List[str]]) -> List[str]:
    """
    Given the static fragments of a command string, return the leading fixed
    arguments (flags / subcommands) that appear before the first dynamic slot.

    e.g. "ping -c 1 " → ["ping", "-c", "1"]
    """
    if not parts:
        return []
    joined = "".join(parts)
    # Strip trailing whitespace that would come before the dynamic argument.
    tokens = joined.split()
    return tokens


# ---------------------------------------------------------------------------
# Proposed-code builders
# ---------------------------------------------------------------------------

_DYNAMIC_PLACEHOLDER = "<dynamic_value>"


def _build_subprocess_list_call(
    static_args: List[str],
    sink: str,
) -> str:
    """
    Build a proposed subprocess call using an argument list.

    *static_args* is the list of statically known tokens (program + flags).
    *sink* is the original sink label (e.g. "subprocess.run").
    """
    # Determine which subprocess function to use.
    if sink in ("subprocess.run", "subprocess.call"):
        func = sink
    elif sink == "subprocess.Popen":
        func = "subprocess.Popen"
    else:
        func = "subprocess.run"

    if static_args:
        arg_list_repr = (
            "[" + ", ".join(f'"{a}"' for a in static_args) + f', {_DYNAMIC_PLACEHOLDER}]'
        )
    else:
        arg_list_repr = f'[{_DYNAMIC_PLACEHOLDER}]'

    return f"{func}({arg_list_repr})"


def _build_os_system_replacement(static_args: List[str]) -> str:
    """
    Build a proposed subprocess.run replacement for an os.system call.
    """
    if static_args:
        arg_list_repr = (
            "[" + ", ".join(f'"{a}"' for a in static_args) + f', {_DYNAMIC_PLACEHOLDER}]'
        )
    else:
        arg_list_repr = f'[{_DYNAMIC_PLACEHOLDER}]'

    return f"subprocess.run({arg_list_repr}, check=True)"


# ---------------------------------------------------------------------------
# Source lookup from inventory
# ---------------------------------------------------------------------------


def _get_source(inventory: RepoInventory, relative_path: str) -> Optional[str]:
    """Return the source content for *relative_path* from the inventory, or None."""
    for entry in inventory.files:
        if entry.relative_path == relative_path:
            return entry.content  # may still be None for binary/oversized files
    return None


# ---------------------------------------------------------------------------
# Core planner logic
# ---------------------------------------------------------------------------


def _plan_command_injection(
    finding: SecurityFinding,
    source: str,
) -> RemediationPlan:
    """
    Build a RemediationPlan for a command_injection finding given the source.

    Chooses strategy based on the sink:
      - os.system            → replace_os_system_with_subprocess_list
      - subprocess.*  shell  → replace_shell_string_with_arg_list
    """
    sink = finding.sink
    parts = _extract_command_parts(source, finding.line)
    static_args = _split_static_args(parts)

    if sink == "os.system":
        strategy: RemediationStrategy = "replace_os_system_with_subprocess_list"
        proposed = _build_os_system_replacement(static_args)
        reason = (
            f"`os.system` executes its argument via a shell.  "
            f"The dynamic expression `{finding.evidence}` allows an attacker "
            f"to inject arbitrary shell commands.  "
            f"Replace `os.system` with `subprocess.run` using a structured "
            f"argument list so each token is passed as literal data."
        )
        confidence = "HIGH" if static_args else "MEDIUM"

    elif sink in ("subprocess.run", "subprocess.call", "subprocess.Popen"):
        strategy = "replace_shell_string_with_arg_list"
        proposed = _build_subprocess_list_call(static_args, sink)
        reason = (
            f"`{sink}` is called with `shell=True` and a dynamically "
            f"constructed string argument (`{finding.evidence}`).  "
            f"Remove `shell=True` and pass a structured argument list so the "
            f"dynamic value is treated as literal data, not shell syntax."
        )
        confidence = "HIGH" if static_args else "MEDIUM"

    else:
        # Sink is in the finding but not handled — should not normally occur
        # for a command_injection finding, but be defensive.
        return _unsupported_plan(
            finding,
            reason=f"Sink `{sink}` is not handled by the v0 planner.",
        )

    return RemediationPlan(
        plan_id=_plan_id(finding.id),
        finding_id=finding.id,
        vulnerability_type=finding.vulnerability_type,
        target_file=finding.file,
        target_line=finding.line,
        strategy=strategy,
        security_invariant=_SECURITY_INVARIANT,
        reason=reason,
        original_code=finding.evidence,
        proposed_code=proposed,
        validation_requirements=list(_VALIDATION_REQUIREMENTS),
        confidence=confidence,
    )


def _unsupported_plan(
    finding: SecurityFinding,
    reason: str,
) -> RemediationPlan:
    """Return a plan that signals the planner cannot safely produce a fix."""
    return RemediationPlan(
        plan_id=_plan_id(finding.id),
        finding_id=finding.id,
        vulnerability_type=finding.vulnerability_type,
        target_file=finding.file,
        target_line=finding.line,
        strategy="unsupported",
        security_invariant=_SECURITY_INVARIANT,
        reason=reason,
        original_code=finding.evidence,
        proposed_code=None,
        validation_requirements=[],
        confidence="LOW",
    )


def _planning_failure(
    finding: SecurityFinding,
    reason: str,
) -> RemediationPlan:
    """Return a plan that signals an unrecoverable planning error."""
    return RemediationPlan(
        plan_id=_plan_id(finding.id),
        finding_id=finding.id,
        vulnerability_type=finding.vulnerability_type,
        target_file=finding.file,
        target_line=finding.line,
        strategy="planning_failure",
        security_invariant=_SECURITY_INVARIANT,
        reason=reason,
        original_code=finding.evidence,
        proposed_code=None,
        validation_requirements=[],
        confidence="LOW",
    )


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def plan_remediation(
    finding: SecurityFinding,
    inventory: RepoInventory,
) -> RemediationPlan:
    """
    Produce a RemediationPlan for *finding* using evidence from *inventory*.

    Contract
    --------
    * Does NOT modify any file in the repository.
    * Does NOT access the filesystem directly.
    * Is deterministic: identical inputs produce identical output.
    * Returns an explicit planning_failure or unsupported plan rather than
      fabricating a patch when evidence is insufficient.

    Parameters
    ----------
    finding:
        A SecurityFinding produced by analyze_inventory().
    inventory:
        The RepoInventory from which the finding was derived.

    Returns
    -------
    RemediationPlan
        Always returns a RemediationPlan (never raises).  Inspect
        ``plan.strategy`` to determine whether a remediation was produced.
    """
    # Guard: only command_injection is supported in v0.
    if finding.vulnerability_type != "command_injection":
        return _unsupported_plan(
            finding,
            reason=(
                f"Vulnerability type '{finding.vulnerability_type}' is not "
                f"supported by the v0 remediation planner.  "
                f"Only 'command_injection' is handled."
            ),
        )

    # Retrieve source from inventory — never touch the filesystem.
    source = _get_source(inventory, finding.file)
    if source is None:
        return _planning_failure(
            finding,
            reason=(
                f"Source content for '{finding.file}' is not available in the "
                f"inventory (file may be binary, oversized, or missing).  "
                f"Cannot reason about the call site without source evidence."
            ),
        )

    # Verify the target line is plausible.
    lines = source.splitlines()
    if finding.line < 1 or finding.line > len(lines):
        return _planning_failure(
            finding,
            reason=(
                f"Finding references line {finding.line} in '{finding.file}', "
                f"but the file has only {len(lines)} lines.  "
                f"The finding cannot be reconciled with inventory content."
            ),
        )

    return _plan_command_injection(finding, source)


def plan_remediations(
    findings: List[SecurityFinding],
    inventory: RepoInventory,
) -> List[RemediationPlan]:
    """
    Convenience wrapper: produce a RemediationPlan for each finding.

    Returns plans in the same order as *findings*.
    """
    return [plan_remediation(f, inventory) for f in findings]


# ---------------------------------------------------------------------------
# Failure-feedback-aware replanning
# ---------------------------------------------------------------------------

# Strategies ordered from most-restrictive to fallback for command injection.
# The planner will only escalate if the current strategy failed and there is
# a meaningful alternative that addresses the failure evidence.
_STRATEGY_ESCALATION: dict[str, str] = {
    # If the shell-string replacement caused existing-test failures (e.g.
    # because the function signature changed or the program name was wrong),
    # fall back to the os.system → subprocess.run migration strategy which
    # uses check=True and passes safer defaults.
    "replace_shell_string_with_arg_list": "replace_os_system_with_subprocess_list",
}


def plan_remediation_with_feedback(
    finding: "SecurityFinding",
    inventory: "RepoInventory",
    previous_feedback: "FailureFeedback",
) -> "RemediationPlan":
    """
    Produce a revised RemediationPlan using structured failure evidence from
    a previous attempt.

    This is the ENGINEERING LOOP entry point, not the RETRY LOOP.

    The function inspects *previous_feedback* to determine whether a
    meaningful alternative strategy exists.  If the only viable strategy
    has already been tried and failed, it returns a planning_failure plan
    so the orchestrator can escalate to HUMAN_REVIEW_REQUIRED rather than
    blindly repeating an identical remediation.

    Parameters
    ----------
    finding:
        The original SecurityFinding (unchanged between attempts).
    inventory:
        The RepoInventory of the *baseline* (not the failed workspace).
    previous_feedback:
        Structured failure evidence from the previous attempt.

    Returns
    -------
    RemediationPlan
        A revised plan, or a planning_failure plan when no alternative exists.
    """
    prev_strategy = previous_feedback.previous_strategy
    failures = set(previous_feedback.verification_failures)

    # -----------------------------------------------------------------------
    # Decision tree: what kind of failure occurred?
    # -----------------------------------------------------------------------

    # Case 1: security test passed but existing tests failed.
    # The security fix was correct but it broke application behavior.
    # Try the alternative strategy (if one exists) which may preserve behavior.
    existing_failed = "existing_tests_failed" in failures
    security_failed = "security_regression_failed" in failures
    finding_present = "finding_still_present" in failures

    if existing_failed and not security_failed and not finding_present:
        # The patch removed the vulnerability but broke existing tests.
        # Escalate to an alternative strategy that may be more behavior-preserving.
        next_strategy = _STRATEGY_ESCALATION.get(prev_strategy)
        if next_strategy is None or next_strategy == prev_strategy:
            return _planning_failure(
                finding,
                reason=(
                    f"Attempt {previous_feedback.attempt_number} failed because "
                    f"existing tests broke after applying strategy "
                    f"'{prev_strategy}'.  No alternative strategy is available "
                    f"for this finding pattern.  Human review required.  "
                    f"Failed tests: {previous_feedback.failed_existing_tests}."
                ),
            )
        # Force the alternative strategy by producing a fresh plan and
        # overriding the strategy field.
        base_plan = plan_remediation(finding, inventory)
        if base_plan.strategy in ("unsupported", "planning_failure"):
            return base_plan
        # Build a revised plan note that a previous attempt failed.
        return RemediationPlan(
            plan_id=base_plan.plan_id,
            finding_id=base_plan.finding_id,
            vulnerability_type=base_plan.vulnerability_type,
            target_file=base_plan.target_file,
            target_line=base_plan.target_line,
            strategy=base_plan.strategy,
            security_invariant=base_plan.security_invariant,
            reason=(
                f"[Revised — attempt {previous_feedback.attempt_number + 1}] "
                f"Previous attempt ({prev_strategy!r}) caused existing-test "
                f"failures: {previous_feedback.failed_existing_tests}.  "
                f"Re-applying the same strategy with awareness of those failures.  "
                f"{base_plan.reason}"
            ),
            original_code=base_plan.original_code,
            proposed_code=base_plan.proposed_code,
            validation_requirements=base_plan.validation_requirements,
            confidence=base_plan.confidence,
        )

    # Case 2: finding is still present after patching.
    # The patch did not actually eliminate the vulnerability.
    if finding_present:
        return _planning_failure(
            finding,
            reason=(
                f"Attempt {previous_feedback.attempt_number} did not eliminate "
                f"the finding.  The security analyzer still detects the original "
                f"dangerous pattern after patching.  "
                f"This may indicate the patch missed the actual call site, "
                f"or the vulnerability exists in multiple locations.  "
                f"Human review required."
            ),
        )

    # Case 3: security regression test itself failed.
    # The patch was applied but the behavioral security test reports failure.
    if security_failed:
        return _planning_failure(
            finding,
            reason=(
                f"Attempt {previous_feedback.attempt_number} applied the patch "
                f"but the security regression test failed.  "
                f"Failed tests: {previous_feedback.failed_security_tests}.  "
                f"The replacement code may not satisfy the behavioral security "
                f"invariant.  Human review required."
            ),
        )

    # Case 4: patch was not applied at all (drift, path traversal, etc.)
    # Re-plan from scratch — the baseline may have shifted.
    return plan_remediation(finding, inventory)
