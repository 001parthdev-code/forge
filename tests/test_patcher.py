"""
Tests for Module 4 — Controlled Patcher.

Strategy
--------
Unit tests build minimal RemediationPlan objects in-memory and operate on
temporary repositories (tmp_path fixture).  No external services are used.

Test matrix
-----------
Case 1  Successful patch           → file modified, hashes differ, applied=True
Case 2  Repository drift           → patch refused, file untouched
Case 3  Path traversal             → rejected before any I/O
Case 4  Missing target             → controlled failure, no unexpected file creation
Case 5  Already applied            → explicit status, no duplication
Case 6  Minimal modification       → surrounding code byte-for-byte unchanged
Case 7  Unsupported strategy       → not applied
Case 8  AppliedPatch model         → JSON-serializable, traceability preserved
E2E     Full pipeline integration  → inspect → analyze → plan → patch
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import shutil
from pathlib import Path
from typing import Optional

import pytest

from secure_swe.analyzer import analyze_inventory
from secure_swe.inspector import inspect_repository
from secure_swe.models import (
    AppliedPatch,
    RemediationPlan,
    SecurityFinding,
)
from secure_swe.patcher import _patch_id, apply_remediation
from secure_swe.remediator import plan_remediation, plan_remediations


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding_id(vulnerability_type: str, file: str, line: int, sink: str) -> str:
    raw = f"{vulnerability_type}|{file}|{line}|{sink}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _plan_id(finding_id: str) -> str:
    raw = f"plan|{finding_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _make_plan(
    *,
    target_file: str = "vuln.py",
    original_code: str = 'os.system("ping -c 1 " + host)',
    proposed_code: Optional[str] = 'subprocess.run(["ping", "-c", "1", host], check=True)',
    strategy: str = "replace_os_system_with_subprocess_list",
    finding_id: Optional[str] = None,
    vulnerability_type: str = "command_injection",
) -> RemediationPlan:
    fid = finding_id or _finding_id(vulnerability_type, target_file, 5, "os.system")
    pid = _plan_id(fid)
    return RemediationPlan(
        plan_id=pid,
        finding_id=fid,
        vulnerability_type=vulnerability_type,
        target_file=target_file,
        target_line=5,
        strategy=strategy,  # type: ignore[arg-type]
        security_invariant="No shell expansion of dynamic values.",
        reason="Test plan",
        original_code=original_code,
        proposed_code=proposed_code,
        validation_requirements=["tests pass"],
        confidence="HIGH",
    )


# Minimal source that contains the vulnerable expression
_VULN_SOURCE = """\
import os

def ping_host(host: str) -> int:
    \"\"\"Ping host.\"\"\"
    return os.system("ping -c 1 " + host)

def other_func() -> None:
    pass
"""

_ORIGINAL = 'os.system("ping -c 1 " + host)'
_REPLACEMENT = 'subprocess.run(["ping", "-c", "1", host], check=True)'


# ---------------------------------------------------------------------------
# Case 1 — Successful patch
# ---------------------------------------------------------------------------

class TestSuccessfulPatch:
    """A valid plan against a matching file should be applied cleanly."""

    def _setup(self, tmp_path: Path) -> tuple[Path, RemediationPlan]:
        vuln = tmp_path / "vuln.py"
        vuln.write_text(_VULN_SOURCE, encoding="utf-8")
        plan = _make_plan(
            target_file="vuln.py",
            original_code=_ORIGINAL,
            proposed_code=_REPLACEMENT,
        )
        return vuln, plan

    def test_applied_is_true(self, tmp_path: Path) -> None:
        vuln, plan = self._setup(tmp_path)
        result = apply_remediation(tmp_path, plan)
        assert result.applied is True

    def test_status_is_applied(self, tmp_path: Path) -> None:
        vuln, plan = self._setup(tmp_path)
        result = apply_remediation(tmp_path, plan)
        assert result.status == "applied"

    def test_target_is_modified(self, tmp_path: Path) -> None:
        vuln, plan = self._setup(tmp_path)
        apply_remediation(tmp_path, plan)
        content = vuln.read_text(encoding="utf-8")
        assert _ORIGINAL not in content
        assert _REPLACEMENT in content

    def test_hashes_are_present(self, tmp_path: Path) -> None:
        vuln, plan = self._setup(tmp_path)
        result = apply_remediation(tmp_path, plan)
        assert result.before_sha256 is not None
        assert result.after_sha256 is not None

    def test_hashes_differ(self, tmp_path: Path) -> None:
        vuln, plan = self._setup(tmp_path)
        result = apply_remediation(tmp_path, plan)
        assert result.before_sha256 != result.after_sha256

    def test_before_hash_matches_original_file(self, tmp_path: Path) -> None:
        vuln, plan = self._setup(tmp_path)
        expected_before = hashlib.sha256(vuln.read_bytes()).hexdigest()
        result = apply_remediation(tmp_path, plan)
        assert result.before_sha256 == expected_before

    def test_after_hash_matches_new_file(self, tmp_path: Path) -> None:
        vuln, plan = self._setup(tmp_path)
        result = apply_remediation(tmp_path, plan)
        expected_after = hashlib.sha256((tmp_path / "vuln.py").read_bytes()).hexdigest()
        assert result.after_sha256 == expected_after

    def test_plan_id_preserved(self, tmp_path: Path) -> None:
        vuln, plan = self._setup(tmp_path)
        result = apply_remediation(tmp_path, plan)
        assert result.plan_id == plan.plan_id

    def test_finding_id_preserved(self, tmp_path: Path) -> None:
        vuln, plan = self._setup(tmp_path)
        result = apply_remediation(tmp_path, plan)
        assert result.finding_id == plan.finding_id

    def test_patch_id_is_deterministic(self, tmp_path: Path) -> None:
        """patch_id is always SHA-256('patch|<plan_id>')[:16]."""
        (tmp_path / "vuln.py").write_text(_VULN_SOURCE, encoding="utf-8")
        plan = _make_plan()
        result = apply_remediation(tmp_path, plan)
        expected = hashlib.sha256(f"patch|{plan.plan_id}".encode()).hexdigest()[:16]
        assert result.patch_id == expected

    def test_failure_reason_is_none(self, tmp_path: Path) -> None:
        vuln, plan = self._setup(tmp_path)
        result = apply_remediation(tmp_path, plan)
        assert result.failure_reason is None

    def test_original_code_recorded(self, tmp_path: Path) -> None:
        vuln, plan = self._setup(tmp_path)
        result = apply_remediation(tmp_path, plan)
        assert result.original_code == _ORIGINAL

    def test_replacement_code_recorded(self, tmp_path: Path) -> None:
        vuln, plan = self._setup(tmp_path)
        result = apply_remediation(tmp_path, plan)
        assert result.replacement_code == _REPLACEMENT


# ---------------------------------------------------------------------------
# Case 2 — Repository drift
# ---------------------------------------------------------------------------

class TestRepositoryDrift:
    """
    If the source file was changed after the plan was created, the patcher
    must refuse rather than blindly overwriting unknown content.
    """

    def test_drift_is_rejected(self, tmp_path: Path) -> None:
        vuln = tmp_path / "vuln.py"
        vuln.write_text(_VULN_SOURCE, encoding="utf-8")
        plan = _make_plan(original_code=_ORIGINAL, proposed_code=_REPLACEMENT)

        # Simulate drift: modify the file before patching
        drifted = _VULN_SOURCE.replace(_ORIGINAL, "os.system(cmd)")
        vuln.write_text(drifted, encoding="utf-8")

        result = apply_remediation(tmp_path, plan)
        assert result.applied is False
        assert result.status == "drift_detected"

    def test_drift_file_is_unchanged(self, tmp_path: Path) -> None:
        vuln = tmp_path / "vuln.py"
        drifted = _VULN_SOURCE.replace(_ORIGINAL, "os.system(cmd)")
        vuln.write_text(drifted, encoding="utf-8")
        plan = _make_plan(original_code=_ORIGINAL, proposed_code=_REPLACEMENT)

        apply_remediation(tmp_path, plan)
        assert vuln.read_text(encoding="utf-8") == drifted

    def test_drift_failure_reason_present(self, tmp_path: Path) -> None:
        vuln = tmp_path / "vuln.py"
        drifted = _VULN_SOURCE.replace(_ORIGINAL, "os.system(cmd)")
        vuln.write_text(drifted, encoding="utf-8")
        plan = _make_plan(original_code=_ORIGINAL, proposed_code=_REPLACEMENT)

        result = apply_remediation(tmp_path, plan)
        assert result.failure_reason is not None
        assert len(result.failure_reason) > 0

    def test_drift_before_hash_recorded(self, tmp_path: Path) -> None:
        vuln = tmp_path / "vuln.py"
        drifted = _VULN_SOURCE.replace(_ORIGINAL, "os.system(cmd)")
        vuln.write_text(drifted, encoding="utf-8")
        plan = _make_plan(original_code=_ORIGINAL, proposed_code=_REPLACEMENT)

        result = apply_remediation(tmp_path, plan)
        # Read actual file bytes to get the correct hash regardless of OS line endings
        expected = hashlib.sha256(vuln.read_bytes()).hexdigest()
        assert result.before_sha256 == expected

    def test_drift_after_hash_is_none(self, tmp_path: Path) -> None:
        vuln = tmp_path / "vuln.py"
        drifted = _VULN_SOURCE.replace(_ORIGINAL, "os.system(cmd)")
        vuln.write_text(drifted, encoding="utf-8")
        plan = _make_plan(original_code=_ORIGINAL, proposed_code=_REPLACEMENT)

        result = apply_remediation(tmp_path, plan)
        assert result.after_sha256 is None


# ---------------------------------------------------------------------------
# Case 3 — Path traversal
# ---------------------------------------------------------------------------

class TestPathTraversal:
    """Paths that escape the repository root must be rejected before any I/O."""

    @pytest.mark.parametrize("bad_path", [
        "../../outside.py",
        "../sibling.py",
        "/absolute/path/evil.py",
        "subdir/../../outside.py",
    ])
    def test_traversal_is_rejected(self, tmp_path: Path, bad_path: str) -> None:
        # Create a harmless file outside the repo to ensure we never touch it
        outside = tmp_path.parent / "outside.py"
        outside.write_text("# should never be touched\n", encoding="utf-8")

        plan = _make_plan(target_file=bad_path)
        result = apply_remediation(tmp_path, plan)
        assert result.applied is False
        assert result.status == "path_traversal"

    @pytest.mark.parametrize("bad_path", [
        "../../outside.py",
        "../sibling.py",
    ])
    def test_traversal_does_not_modify_external_file(
        self, tmp_path: Path, bad_path: str
    ) -> None:
        outside = tmp_path.parent / "outside.py"
        sentinel = "# never modified\n"
        outside.write_text(sentinel, encoding="utf-8")

        plan = _make_plan(target_file=bad_path)
        apply_remediation(tmp_path, plan)

        if outside.exists():
            assert outside.read_text(encoding="utf-8") == sentinel

    def test_traversal_before_hash_is_none(self, tmp_path: Path) -> None:
        plan = _make_plan(target_file="../../outside.py")
        result = apply_remediation(tmp_path, plan)
        assert result.before_sha256 is None


# ---------------------------------------------------------------------------
# Case 4 — Missing target
# ---------------------------------------------------------------------------

class TestMissingTarget:
    """When the target file does not exist the patcher must fail closed."""

    def test_missing_is_rejected(self, tmp_path: Path) -> None:
        plan = _make_plan(target_file="nonexistent.py")
        result = apply_remediation(tmp_path, plan)
        assert result.applied is False
        assert result.status == "target_missing"

    def test_missing_does_not_create_file(self, tmp_path: Path) -> None:
        plan = _make_plan(target_file="nonexistent.py")
        apply_remediation(tmp_path, plan)
        assert not (tmp_path / "nonexistent.py").exists()

    def test_missing_failure_reason_present(self, tmp_path: Path) -> None:
        plan = _make_plan(target_file="nonexistent.py")
        result = apply_remediation(tmp_path, plan)
        assert result.failure_reason is not None

    def test_missing_before_hash_is_none(self, tmp_path: Path) -> None:
        plan = _make_plan(target_file="nonexistent.py")
        result = apply_remediation(tmp_path, plan)
        assert result.before_sha256 is None

    def test_missing_does_not_create_unexpected_files(self, tmp_path: Path) -> None:
        before = set(tmp_path.iterdir())
        plan = _make_plan(target_file="ghost.py")
        apply_remediation(tmp_path, plan)
        after = set(tmp_path.iterdir())
        assert after == before


# ---------------------------------------------------------------------------
# Case 5 — Already applied (idempotency)
# ---------------------------------------------------------------------------

class TestAlreadyApplied:
    """Applying the same plan twice must not corrupt the file."""

    def _setup(self, tmp_path: Path) -> tuple[Path, RemediationPlan]:
        vuln = tmp_path / "vuln.py"
        vuln.write_text(_VULN_SOURCE, encoding="utf-8")
        plan = _make_plan(original_code=_ORIGINAL, proposed_code=_REPLACEMENT)
        return vuln, plan

    def test_second_application_is_already_applied(self, tmp_path: Path) -> None:
        vuln, plan = self._setup(tmp_path)
        apply_remediation(tmp_path, plan)
        result2 = apply_remediation(tmp_path, plan)
        assert result2.status == "already_applied"
        assert result2.applied is False

    def test_second_application_does_not_duplicate_replacement(
        self, tmp_path: Path
    ) -> None:
        vuln, plan = self._setup(tmp_path)
        apply_remediation(tmp_path, plan)
        apply_remediation(tmp_path, plan)
        content = vuln.read_text(encoding="utf-8")
        assert content.count(_REPLACEMENT) == 1

    def test_second_application_original_absent(self, tmp_path: Path) -> None:
        vuln, plan = self._setup(tmp_path)
        apply_remediation(tmp_path, plan)
        apply_remediation(tmp_path, plan)
        content = vuln.read_text(encoding="utf-8")
        assert _ORIGINAL not in content

    def test_second_application_failure_reason_present(self, tmp_path: Path) -> None:
        vuln, plan = self._setup(tmp_path)
        apply_remediation(tmp_path, plan)
        result2 = apply_remediation(tmp_path, plan)
        assert result2.failure_reason is not None

    def test_second_application_hashes_equal(self, tmp_path: Path) -> None:
        """before/after hashes should equal each other since no change was made."""
        vuln, plan = self._setup(tmp_path)
        apply_remediation(tmp_path, plan)
        result2 = apply_remediation(tmp_path, plan)
        assert result2.before_sha256 == result2.after_sha256


# ---------------------------------------------------------------------------
# Case 6 — Minimal modification
# ---------------------------------------------------------------------------

class TestMinimalModification:
    """Only the authorised code fragment must change; everything else is untouched."""

    _SOURCE = """\
import os
import sys

def helper() -> str:
    return "untouched"

def ping_host(host: str) -> int:
    return os.system("ping -c 1 " + host)

def another_helper() -> None:
    print("also untouched")
"""

    def test_unrelated_lines_unchanged(self, tmp_path: Path) -> None:
        vuln = tmp_path / "vuln.py"
        vuln.write_text(self._SOURCE, encoding="utf-8")
        plan = _make_plan(original_code=_ORIGINAL, proposed_code=_REPLACEMENT)

        apply_remediation(tmp_path, plan)
        patched = vuln.read_text(encoding="utf-8")

        assert "def helper" in patched
        assert '"untouched"' in patched
        assert "def another_helper" in patched
        assert '"also untouched"' in patched
        assert "import os" in patched
        assert "import sys" in patched

    def test_only_target_expression_replaced(self, tmp_path: Path) -> None:
        vuln = tmp_path / "vuln.py"
        vuln.write_text(self._SOURCE, encoding="utf-8")
        plan = _make_plan(original_code=_ORIGINAL, proposed_code=_REPLACEMENT)

        original_lines = self._SOURCE.splitlines()
        apply_remediation(tmp_path, plan)
        patched_lines = vuln.read_text(encoding="utf-8").splitlines()

        # Every line that does NOT contain the original code should be identical.
        for orig_line, patched_line in zip(original_lines, patched_lines):
            if _ORIGINAL not in orig_line:
                assert orig_line == patched_line, (
                    f"Unexpected change in line: {orig_line!r} → {patched_line!r}"
                )

    def test_first_occurrence_only_replaced(self, tmp_path: Path) -> None:
        """If the same expression appears twice, only the first is replaced."""
        doubled = self._SOURCE + f"\ndef second():\n    return {_ORIGINAL}\n"
        vuln = tmp_path / "vuln.py"
        vuln.write_text(doubled, encoding="utf-8")
        plan = _make_plan(original_code=_ORIGINAL, proposed_code=_REPLACEMENT)

        apply_remediation(tmp_path, plan)
        content = vuln.read_text(encoding="utf-8")

        # First occurrence replaced
        assert content.count(_REPLACEMENT) == 1
        # Second occurrence still present
        assert content.count(_ORIGINAL) == 1


# ---------------------------------------------------------------------------
# Case 7 — Unsupported / planning_failure strategy
# ---------------------------------------------------------------------------

class TestUnsupportedStrategy:
    """Plans with non-actionable strategies must not modify anything."""

    @pytest.mark.parametrize("strategy", ["unsupported", "planning_failure"])
    def test_not_applied(self, tmp_path: Path, strategy: str) -> None:
        vuln = tmp_path / "vuln.py"
        vuln.write_text(_VULN_SOURCE, encoding="utf-8")
        plan = _make_plan(
            strategy=strategy,
            proposed_code=None,
        )
        result = apply_remediation(tmp_path, plan)
        assert result.applied is False
        assert result.status == "unsupported_strategy"

    @pytest.mark.parametrize("strategy", ["unsupported", "planning_failure"])
    def test_file_unchanged(self, tmp_path: Path, strategy: str) -> None:
        vuln = tmp_path / "vuln.py"
        vuln.write_text(_VULN_SOURCE, encoding="utf-8")
        plan = _make_plan(strategy=strategy, proposed_code=None)
        apply_remediation(tmp_path, plan)
        assert vuln.read_text(encoding="utf-8") == _VULN_SOURCE


# ---------------------------------------------------------------------------
# Case 8 — AppliedPatch model contract
# ---------------------------------------------------------------------------

class TestAppliedPatchModel:
    """The AppliedPatch dataclass must be JSON-serializable and carry full traceability."""

    def _patch(self, tmp_path: Path) -> AppliedPatch:
        (tmp_path / "vuln.py").write_text(_VULN_SOURCE, encoding="utf-8")
        plan = _make_plan()
        return apply_remediation(tmp_path, plan)

    def test_is_dataclass(self, tmp_path: Path) -> None:
        result = self._patch(tmp_path)
        assert dataclasses.is_dataclass(result)

    def test_to_dict_returns_dict(self, tmp_path: Path) -> None:
        result = self._patch(tmp_path)
        assert isinstance(result.to_dict(), dict)

    def test_json_serializable(self, tmp_path: Path) -> None:
        result = self._patch(tmp_path)
        serialized = json.dumps(result.to_dict())
        assert len(serialized) > 0

    def test_round_trip(self, tmp_path: Path) -> None:
        result = self._patch(tmp_path)
        d = result.to_dict()
        # All original fields survive round-trip through dict
        for field in dataclasses.fields(result):
            assert field.name in d

    def test_patch_id_is_16_hex_chars(self, tmp_path: Path) -> None:
        result = self._patch(tmp_path)
        assert len(result.patch_id) == 16
        assert all(c in "0123456789abcdef" for c in result.patch_id)

    def test_traceability_finding_plan_patch(self, tmp_path: Path) -> None:
        (tmp_path / "vuln.py").write_text(_VULN_SOURCE, encoding="utf-8")
        fid = _finding_id("command_injection", "vuln.py", 5, "os.system")
        pid = _plan_id(fid)
        plan = _make_plan(finding_id=fid)
        result = apply_remediation(tmp_path, plan)

        assert result.finding_id == fid
        assert result.plan_id == pid
        expected_patch_id = hashlib.sha256(
            f"patch|{pid}".encode()
        ).hexdigest()[:16]
        assert result.patch_id == expected_patch_id

    def test_patch_id_differs_from_plan_id(self, tmp_path: Path) -> None:
        result = self._patch(tmp_path)
        assert result.patch_id != result.plan_id

    def test_patch_id_differs_from_finding_id(self, tmp_path: Path) -> None:
        result = self._patch(tmp_path)
        assert result.patch_id != result.finding_id


# ---------------------------------------------------------------------------
# End-to-end integration test
# ---------------------------------------------------------------------------

class TestEndToEndPipeline:
    """
    Full pipeline: inspect → analyze → plan → patch.

    Proves the entire SecurityFinding → RemediationPlan → AppliedPatch chain
    works against a real temporary repository.
    """

    # Use single-quoted string so ast.unparse output ('ping -c 1 ' + host)
    # matches the literal source text verbatim — enabling the patcher's
    # substring search to locate the vulnerable expression.
    _PING_SOURCE = """\
import os

def ping_host(host: str) -> int:
    return os.system('ping -c 1 ' + host)
"""

    def test_full_pipeline_os_system(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(self._PING_SOURCE, encoding="utf-8")

        inv = inspect_repository(str(tmp_path))
        findings = analyze_inventory(inv)
        assert findings, "analyzer must produce a finding"

        plans = plan_remediations(findings, inv)
        assert plans

        # Pick the first actionable plan
        actionable = [p for p in plans if p.proposed_code is not None]
        assert actionable, "at least one plan must be actionable"
        plan = actionable[0]

        result = apply_remediation(tmp_path, plan)

        assert result.applied is True
        assert result.status == "applied"
        assert result.before_sha256 is not None
        assert result.after_sha256 is not None
        assert result.before_sha256 != result.after_sha256

        # Traceability: finding → plan → patch
        matching_finding = next(f for f in findings if f.id == plan.finding_id)
        assert result.finding_id == matching_finding.id
        assert result.plan_id == plan.plan_id

        # The vulnerable code must no longer be present verbatim
        patched = (tmp_path / "app.py").read_text(encoding="utf-8")
        assert plan.original_code not in patched
        assert plan.proposed_code in patched

    def test_full_pipeline_traceability_ids(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(self._PING_SOURCE, encoding="utf-8")

        inv = inspect_repository(str(tmp_path))
        findings = analyze_inventory(inv)
        plans = plan_remediations(findings, inv)
        actionable = [p for p in plans if p.proposed_code is not None]
        plan = actionable[0]
        result = apply_remediation(tmp_path, plan)

        # Deterministic ID chain
        finding = next(f for f in findings if f.id == plan.finding_id)
        expected_plan_id = hashlib.sha256(
            f"plan|{finding.id}".encode()
        ).hexdigest()[:16]
        expected_patch_id = hashlib.sha256(
            f"patch|{expected_plan_id}".encode()
        ).hexdigest()[:16]

        assert plan.plan_id == expected_plan_id
        assert result.patch_id == expected_patch_id

    def test_controlled_sample_app(self, tmp_path: Path) -> None:
        """Run the full pipeline over the controlled command_injection_app sample."""
        sample_dir = Path("samples/command_injection_app")
        if not sample_dir.exists():
            pytest.skip("sample directory not found")

        dest = tmp_path / "sample"
        shutil.copytree(str(sample_dir), str(dest))

        inv = inspect_repository(str(dest))
        findings = analyze_inventory(inv)
        assert findings, "sample app must produce findings"

        plans = plan_remediations(findings, inv)
        actionable = [p for p in plans if p.proposed_code is not None]
        assert actionable, "at least one actionable plan required"

        patches = [apply_remediation(dest, p) for p in actionable]
        applied = [p for p in patches if p.applied]
        assert applied, "at least one patch must be applied"

        for patch in applied:
            assert patch.before_sha256 != patch.after_sha256
            assert patch.finding_id is not None
            assert patch.plan_id is not None

    def test_patch_applied_not_security_fix_verified(self, tmp_path: Path) -> None:
        """
        PATCH APPLIED ≠ SECURITY FIX VERIFIED.

        The result carries applied=True but no verification flag — the
        applied status only means the code was mutated, not that it is secure.
        """
        (tmp_path / "app.py").write_text(self._PING_SOURCE, encoding="utf-8")
        inv = inspect_repository(str(tmp_path))
        findings = analyze_inventory(inv)
        plans = plan_remediations(findings, inv)
        actionable = [p for p in plans if p.proposed_code is not None]
        plan = actionable[0]
        result = apply_remediation(tmp_path, plan)

        assert result.applied is True
        assert result.status == "applied"
        # No verification field exists on AppliedPatch — that comes later.
        assert not hasattr(result, "verified")
        assert not hasattr(result, "security_verified")
