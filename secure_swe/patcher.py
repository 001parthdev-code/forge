"""
Module 4 — Controlled Patcher

Applies an authorised RemediationPlan to the controlled target repository.

Architecture boundary
---------------------
This module MUST NOT:
  * decide what to change — that responsibility belongs to the Planner;
  * run security analysis;
  * modify any file not explicitly authorised by the RemediationPlan;
  * call external APIs, LLMs, or network services.

It MUST:
  * validate the target path stays inside the repository (containment);
  * verify the target file exists before touching it;
  * verify the expected original code is still present (drift protection);
  * perform only the minimal substitution authorised by the plan;
  * preserve full traceability: SecurityFinding → RemediationPlan → AppliedPatch;
  * be idempotent — re-applying an already-applied plan must not corrupt the file;
  * record SHA-256 hashes before and after the mutation;
  * write atomically to avoid partial-write corruption.

Public interface
----------------
  apply_remediation(repo_path, plan) -> AppliedPatch
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
from typing import Optional

from secure_swe.models import (
    AppliedPatch,
    PatchStatus,
    RemediationPlan,
)

# ---------------------------------------------------------------------------
# ID derivation
# ---------------------------------------------------------------------------


def _patch_id(plan_id: str) -> str:
    """
    Deterministic 16-char hex patch identifier derived from the plan ID.

    SHA-256 of "patch|<plan_id>", truncated to 16 hex characters.
    """
    raw = f"patch|{plan_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# SHA-256 helper
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest of *path*'s raw bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Failure constructors
# ---------------------------------------------------------------------------


def _fail(
    plan: RemediationPlan,
    status: PatchStatus,
    reason: str,
    before_sha256: Optional[str] = None,
) -> AppliedPatch:
    """Build a non-applied AppliedPatch for any failure condition."""
    return AppliedPatch(
        patch_id=_patch_id(plan.plan_id),
        plan_id=plan.plan_id,
        finding_id=plan.finding_id,
        target_file=plan.target_file,
        before_sha256=before_sha256,
        after_sha256=None,
        original_code=plan.original_code,
        replacement_code=plan.proposed_code,
        applied=False,
        status=status,
        failure_reason=reason,
    )


# ---------------------------------------------------------------------------
# Atomic file write
# ---------------------------------------------------------------------------


def _atomic_write(target: Path, new_content: str) -> None:
    """
    Write *new_content* to *target* atomically.

    Writes to a sibling temporary file in the same directory, then renames
    it over the target.  The rename is atomic on POSIX; on Windows it may
    briefly fail if the target is locked, but it avoids leaving a partial file
    in all other cases.
    """
    dir_ = target.parent
    fd, tmp_path = tempfile.mkstemp(dir=dir_, prefix=".patch_tmp_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(new_content)
        # os.replace is atomic on POSIX; on Windows it is best-effort.
        os.replace(tmp_path, target)
    except Exception:
        # Clean up the temp file if rename / write fails.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Core patch logic
# ---------------------------------------------------------------------------


def _apply_substitution(
    content: str,
    original: str,
    replacement: str,
) -> str:
    """
    Replace the first occurrence of *original* in *content* with *replacement*.

    Only the first occurrence is replaced to keep the mutation minimal and
    predictable.
    """
    return content.replace(original, replacement, 1)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def apply_remediation(
    repo_path: str | os.PathLike,
    plan: RemediationPlan,
) -> AppliedPatch:
    """
    Apply *plan* to the file it targets inside *repo_path*.

    Safety checks (in order):
    1. Path containment  — target_file must resolve inside repo_path.
    2. Target exists     — fail closed if the file is gone.
    3. Supported plan    — reject unsupported/planning_failure strategies.
    4. Drift detection   — original_code must still be present verbatim.
    5. Idempotency       — if proposed_code is already present, report already_applied.
    6. Minimal mutation  — replace only the first occurrence of original_code.
    7. Atomic write      — use rename-over-temp to avoid partial writes.
    8. Hash recording    — SHA-256 before and after.

    Parameters
    ----------
    repo_path:
        Absolute (or resolvable) path to the controlled repository root.
    plan:
        A RemediationPlan produced by plan_remediation().

    Returns
    -------
    AppliedPatch
        Always returns an AppliedPatch (never raises).
        Inspect ``patch.applied`` and ``patch.status`` to determine outcome.
    """
    root = Path(repo_path).resolve()

    # ------------------------------------------------------------------
    # 1. Path containment
    # ------------------------------------------------------------------
    try:
        # Construct the absolute path and verify it is inside the repo root.
        # Path(root / relative) already normalises ".." components, so we
        # resolve and check the prefix.
        candidate = (root / plan.target_file).resolve()
        # Ensure candidate is inside root — raises ValueError if not.
        candidate.relative_to(root)
    except (ValueError, RuntimeError):
        return _fail(
            plan,
            "path_traversal",
            f"Target path '{plan.target_file}' resolves outside the repository "
            f"root '{root}'.  Patch rejected.",
        )

    target = candidate

    # ------------------------------------------------------------------
    # 2. Target exists
    # ------------------------------------------------------------------
    if not target.exists():
        return _fail(
            plan,
            "target_missing",
            f"Target file '{plan.target_file}' does not exist in the repository.  "
            f"Cannot apply patch to a missing file.",
        )

    # Read current content and record the before-hash.
    current_content = target.read_text(encoding="utf-8")
    before_hash = _sha256_file(target)

    # ------------------------------------------------------------------
    # 3. Supported plan
    # ------------------------------------------------------------------
    if plan.strategy in ("unsupported", "planning_failure"):
        return _fail(
            plan,
            "unsupported_strategy",
            f"Plan strategy is '{plan.strategy}'.  "
            f"The patcher will not apply unsupported or failed plans.",
            before_sha256=before_hash,
        )

    if plan.proposed_code is None:
        return _fail(
            plan,
            "unsupported_strategy",
            "Plan carries no proposed_code; nothing to apply.",
            before_sha256=before_hash,
        )

    original = plan.original_code
    replacement = plan.proposed_code

    # ------------------------------------------------------------------
    # 4. Drift detection
    # ------------------------------------------------------------------
    if original not in current_content:
        # Check idempotency: if replacement is already present, report that.
        if replacement in current_content:
            return AppliedPatch(
                patch_id=_patch_id(plan.plan_id),
                plan_id=plan.plan_id,
                finding_id=plan.finding_id,
                target_file=plan.target_file,
                before_sha256=before_hash,
                after_sha256=before_hash,  # file was not changed
                original_code=original,
                replacement_code=replacement,
                applied=False,
                status="already_applied",
                failure_reason=(
                    "The proposed replacement is already present in the target "
                    "file; the patch appears to have been applied previously."
                ),
            )

        return _fail(
            plan,
            "drift_detected",
            f"Expected original code not found in '{plan.target_file}'.  "
            f"The file may have changed since the plan was created.  "
            f"Patch refused to prevent overwriting unexpected changes.",
            before_sha256=before_hash,
        )

    # ------------------------------------------------------------------
    # 5. Already applied (replacement already present alongside original)
    #    Handled above.  If original is still there, we proceed.
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # 6. Minimal mutation
    # ------------------------------------------------------------------
    new_content = _apply_substitution(current_content, original, replacement)

    # ------------------------------------------------------------------
    # 7. Atomic write
    # ------------------------------------------------------------------
    try:
        _atomic_write(target, new_content)
    except Exception as exc:  # noqa: BLE001
        return _fail(
            plan,
            "write_error",
            f"Failed to write patched file: {type(exc).__name__}: {exc}",
            before_sha256=before_hash,
        )

    # ------------------------------------------------------------------
    # 8. Hash recording
    # ------------------------------------------------------------------
    after_hash = _sha256_file(target)

    return AppliedPatch(
        patch_id=_patch_id(plan.plan_id),
        plan_id=plan.plan_id,
        finding_id=plan.finding_id,
        target_file=plan.target_file,
        before_sha256=before_hash,
        after_sha256=after_hash,
        original_code=original,
        replacement_code=replacement,
        applied=True,
        status="applied",
        failure_reason=None,
    )
