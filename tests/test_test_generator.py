"""
Tests for Module 5 — Security Test Generator.

Test matrix
-----------
Case 1  Valid command-injection chain (os.system)
        → SecurityRegressionTest generated
        → DesiredOutcome generated
        → traceability preserved
        → behavioral security property represented

Case 2  Valid command-injection chain (subprocess.run shell=True)
        → same as Case 1 for subprocess sink

Case 3  Behavioral test quality
        → sentinel uses harmless shell-like input
        → test mocks actual process execution
        → test verifies input remains argument data
        → generated code does not actually execute the payload

Case 4  Mismatched chain (plan.finding_id ≠ finding.id)
        → generation rejected with TraceabilityError

Case 5  Mismatched chain (patch.plan_id ≠ plan.plan_id)
        → generation rejected with TraceabilityError

Case 6  Mismatched chain (patch.finding_id ≠ finding.id)
        → generation rejected with TraceabilityError

Case 7  Failed patch (applied=False)
        → generation rejected with TraceabilityError

Case 8  Unsupported vulnerability type
        → generation rejected with GenerationError

Case 9  Missing source evidence
        → generation rejected with GenerationError

Case 10 Determinism
        → same inputs produce equivalent SecurityRegressionTest

Case 11 DesiredOutcome content
        → security invariants, regression requirements, verification requirements present

Case 12 Model serialization
        → SecurityRegressionTest and DesiredOutcome are JSON-serializable
        → to_dict() round-trips

Case 13 persist_security_test — happy path
        → test file written inside repository
        → idempotent (no error on second write)

Case 14 persist_security_test — conflict rejection
        → existing unrelated file is not overwritten

Case 15 persist_security_test — path traversal rejected

Integration test
        → sample repository: inspect → analyze → plan → patch → test → outcome
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import shutil
from pathlib import Path
from typing import Optional

import pytest

from secure_swe.models import (
    AppliedPatch,
    DesiredOutcome,
    FileEntry,
    InventorySummary,
    RemediationPlan,
    RepoInventory,
    SecurityFinding,
    SecurityRegressionTest,
)
from secure_swe.test_generator import (
    GenerationError,
    TraceabilityError,
    _outcome_id,
    _test_id,
    generate_security_test,
    persist_security_test,
)

# ---------------------------------------------------------------------------
# Shared source fixtures
# ---------------------------------------------------------------------------

# Source that contains an os.system command-injection sink at line 5.
_OS_SYSTEM_SOURCE = """\
import os

def ping_host(host: str) -> int:
    \"\"\"Ping the host.\"\"\"
    return os.system("ping -c 1 " + host)

def other_func() -> None:
    pass
"""

# Source that contains a subprocess.run shell=True sink at line 5.
_SUBPROCESS_SOURCE = """\
import subprocess

def resolve_hostname(target: str) -> None:
    \"\"\"Perform DNS lookup.\"\"\"
    subprocess.run(f"nslookup {target}", shell=True)

def other_func() -> None:
    pass
"""

# ---------------------------------------------------------------------------
# Builder helpers (mirrors test_patcher.py conventions)
# ---------------------------------------------------------------------------


def _finding_id(vulnerability_type: str, file: str, line: int, sink: str) -> str:
    raw = f"{vulnerability_type}|{file}|{line}|{sink}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _plan_id(finding_id: str) -> str:
    raw = f"plan|{finding_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _patch_id(plan_id: str) -> str:
    raw = f"patch|{plan_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _make_entry(
    relative_path: str,
    content: Optional[str],
    *,
    is_text: bool = True,
    extension: Optional[str] = None,
) -> FileEntry:
    if extension is None:
        ext = "." + relative_path.rsplit(".", 1)[-1] if "." in relative_path else ""
    else:
        ext = extension
    raw = (content or "").encode()
    return FileEntry(
        relative_path=relative_path,
        extension=ext,
        size_bytes=len(raw),
        is_text=is_text,
        sha256=hashlib.sha256(raw).hexdigest(),
        content=content,
        content_omission_reason=None if content is not None else "binary",
        read_error=None,
    )


def _make_inventory(
    *entries: FileEntry,
    repo_root: str = "/fake/repo",
) -> RepoInventory:
    sorted_entries = sorted(entries, key=lambda e: e.relative_path)
    return RepoInventory(
        repo_root=repo_root,
        files=list(sorted_entries),
        summary=InventorySummary(
            total_files=len(sorted_entries),
            total_size_bytes=sum(e.size_bytes for e in sorted_entries),
            count_by_extension={},
            inspection_error_count=0,
        ),
    )


def _make_finding(
    *,
    vulnerability_type: str = "command_injection",
    file: str = "vuln.py",
    line: int = 5,
    sink: str = "os.system",
    evidence: str = '"ping -c 1 " + host',
) -> SecurityFinding:
    fid = _finding_id(vulnerability_type, file, line, sink)
    return SecurityFinding(
        id=fid,
        vulnerability_type=vulnerability_type,
        severity="HIGH",
        file=file,
        line=line,
        sink=sink,
        evidence=evidence,
        reason="Test finding",
        confidence="MEDIUM",
    )


def _make_plan(finding: SecurityFinding) -> RemediationPlan:
    pid = _plan_id(finding.id)
    return RemediationPlan(
        plan_id=pid,
        finding_id=finding.id,
        vulnerability_type=finding.vulnerability_type,
        target_file=finding.file,
        target_line=finding.line,
        strategy="replace_os_system_with_subprocess_list",
        security_invariant="Untrusted values must not be interpreted as shell syntax.",
        reason="Test plan",
        original_code=finding.evidence,
        proposed_code='subprocess.run(["ping", "-c", "1", host], check=True)',
        validation_requirements=["tests pass"],
        confidence="HIGH",
    )


def _make_patch(plan: RemediationPlan, *, applied: bool = True) -> AppliedPatch:
    pid = _patch_id(plan.plan_id)
    return AppliedPatch(
        patch_id=pid,
        plan_id=plan.plan_id,
        finding_id=plan.finding_id,
        target_file=plan.target_file,
        before_sha256="abc123",
        after_sha256="def456" if applied else None,
        original_code=plan.original_code,
        replacement_code=plan.proposed_code,
        applied=applied,
        status="applied" if applied else "drift_detected",
        failure_reason=None if applied else "drift detected",
    )


def _make_chain(
    *,
    source: str = _OS_SYSTEM_SOURCE,
    file: str = "vuln.py",
    line: int = 5,
    sink: str = "os.system",
    evidence: str = '"ping -c 1 " + host',
) -> tuple[SecurityFinding, RemediationPlan, AppliedPatch, RepoInventory]:
    finding = _make_finding(file=file, line=line, sink=sink, evidence=evidence)
    plan = _make_plan(finding)
    patch = _make_patch(plan)
    inventory = _make_inventory(_make_entry(file, source))
    return finding, plan, patch, inventory


# ---------------------------------------------------------------------------
# Case 1 — Valid command-injection chain (os.system)
# ---------------------------------------------------------------------------


class TestValidOsSystemChain:
    """generate_security_test succeeds for a well-formed os.system chain."""

    def _gen(self):
        finding, plan, patch, inventory = _make_chain()
        return generate_security_test(finding, plan, patch, inventory)

    def test_returns_tuple_of_two(self) -> None:
        result = self._gen()
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_first_element_is_security_regression_test(self) -> None:
        test, _ = self._gen()
        assert isinstance(test, SecurityRegressionTest)

    def test_second_element_is_desired_outcome(self) -> None:
        _, outcome = self._gen()
        assert isinstance(outcome, DesiredOutcome)

    def test_test_id_is_16_hex_chars(self) -> None:
        test, _ = self._gen()
        assert len(test.test_id) == 16
        int(test.test_id, 16)  # must be valid hex

    def test_outcome_id_is_16_hex_chars(self) -> None:
        _, outcome = self._gen()
        assert len(outcome.outcome_id) == 16
        int(outcome.outcome_id, 16)

    def test_traceability_finding_id_preserved(self) -> None:
        finding, plan, patch, inventory = _make_chain()
        test, outcome = generate_security_test(finding, plan, patch, inventory)
        assert test.finding_id == finding.id
        assert outcome.finding_id == finding.id

    def test_traceability_plan_id_preserved(self) -> None:
        finding, plan, patch, inventory = _make_chain()
        test, _ = generate_security_test(finding, plan, patch, inventory)
        assert test.plan_id == plan.plan_id

    def test_traceability_patch_id_preserved(self) -> None:
        finding, plan, patch, inventory = _make_chain()
        test, _ = generate_security_test(finding, plan, patch, inventory)
        assert test.patch_id == patch.patch_id

    def test_target_file_preserved(self) -> None:
        finding, plan, patch, inventory = _make_chain()
        test, _ = generate_security_test(finding, plan, patch, inventory)
        assert test.target_file == finding.file

    def test_security_property_nonempty(self) -> None:
        test, _ = self._gen()
        assert test.security_property

    def test_test_code_nonempty(self) -> None:
        test, _ = self._gen()
        assert test.test_code

    def test_expected_behavior_nonempty(self) -> None:
        test, _ = self._gen()
        assert test.expected_behavior

    def test_test_file_inside_tests_directory(self) -> None:
        test, _ = self._gen()
        assert test.test_file.startswith("tests/")

    def test_test_name_starts_with_test_prefix(self) -> None:
        test, _ = self._gen()
        assert test.test_name.startswith("test_")


# ---------------------------------------------------------------------------
# Case 2 — Valid command-injection chain (subprocess.run shell=True)
# ---------------------------------------------------------------------------


class TestValidSubprocessChain:
    """generate_security_test succeeds for a subprocess.run chain."""

    def _gen(self):
        finding, plan, patch, inventory = _make_chain(
            source=_SUBPROCESS_SOURCE,
            file="app.py",
            line=5,
            sink="subprocess.run",
            evidence='f"nslookup {target}"',
        )
        # Adjust plan strategy for subprocess sink
        plan = dataclasses.replace(
            plan,
            strategy="replace_shell_string_with_arg_list",
        )
        return generate_security_test(finding, plan, patch, inventory)

    def test_returns_two_elements(self) -> None:
        result = self._gen()
        assert len(result) == 2

    def test_test_code_contains_subprocess_mock(self) -> None:
        test, _ = self._gen()
        assert "subprocess.run" in test.test_code

    def test_test_code_no_shell_true_passed(self) -> None:
        test, _ = self._gen()
        # The generated test must NOT instruct the mock to verify shell=True —
        # it must assert shell=True is ABSENT.
        assert "shell=True must not be present" in test.test_code


# ---------------------------------------------------------------------------
# Case 3 — Behavioral test quality
# ---------------------------------------------------------------------------


class TestBehavioralTestQuality:
    """Verify the generated test has the required behavioral properties."""

    def _test_code(self, *, sink: str = "os.system") -> str:
        evidence = '"ping -c 1 " + host' if sink == "os.system" else 'f"nslookup {target}"'
        source = _OS_SYSTEM_SOURCE if sink == "os.system" else _SUBPROCESS_SOURCE
        finding, plan, patch, inventory = _make_chain(
            source=source,
            sink=sink,
            evidence=evidence,
        )
        test, _ = generate_security_test(finding, plan, patch, inventory)
        return test.test_code

    def test_uses_harmless_sentinel_input(self) -> None:
        code = self._test_code()
        # Sentinel must appear in the generated test code.
        assert "example.invalid; SENTINEL" in code

    def test_mocks_process_execution(self) -> None:
        code = self._test_code()
        # Test must use unittest.mock.patch.
        assert "from unittest.mock import" in code
        assert "patch(" in code

    def test_asserts_list_not_string(self) -> None:
        code = self._test_code()
        # Must check that the argument is a list (not an interpolated string).
        assert "isinstance(first_arg, list)" in code

    def test_asserts_sentinel_in_list(self) -> None:
        code = self._test_code()
        # Must verify the sentinel ends up inside the argument list.
        assert "example.invalid; SENTINEL" in code
        assert "in first_arg" in code

    def test_does_not_actually_execute_payload(self) -> None:
        code = self._test_code()
        # The code must not contain a bare os.system call or shell invocation
        # outside a mock context.  Specifically, check that there is no
        # un-mocked call to os.system(sentinel) in the test body.
        # (A simple proxy: the test wraps the function call inside `with patch(...)`)
        assert 'with patch(' in code

    def test_no_destructive_commands(self) -> None:
        code = self._test_code()
        for danger in ("rm -rf", "rmdir", "shutil.rmtree", "os.remove", "format c:"):
            assert danger not in code, f"Dangerous pattern found: {danger!r}"

    def test_no_network_access(self) -> None:
        code = self._test_code()
        for net in ("urllib", "requests.get", "httpx", "socket.connect"):
            assert net not in code, f"Network access pattern found: {net!r}"

    def test_subprocess_sink_asserts_no_shell_true(self) -> None:
        code = self._test_code(sink="subprocess.run")
        assert "shell=True must not be present" in code

    def test_generated_code_is_syntactically_valid_python(self) -> None:
        import ast as ast_module
        code = self._test_code()
        # Will raise SyntaxError if the generated code is not valid Python.
        ast_module.parse(code)

    def test_generated_code_subprocess_is_syntactically_valid_python(self) -> None:
        import ast as ast_module
        code = self._test_code(sink="subprocess.run")
        ast_module.parse(code)


# ---------------------------------------------------------------------------
# Case 4–6 — Mismatched chain
# ---------------------------------------------------------------------------


class TestMismatchedChain:
    """Mismatched IDs cause TraceabilityError to be raised."""

    def test_plan_finding_id_mismatch(self) -> None:
        finding, plan, patch, inventory = _make_chain()
        # Tamper: give the plan a different finding_id.
        bad_plan = dataclasses.replace(plan, finding_id="0000000000000000")
        with pytest.raises(TraceabilityError, match="finding_id"):
            generate_security_test(finding, bad_plan, patch, inventory)

    def test_patch_plan_id_mismatch(self) -> None:
        finding, plan, patch, inventory = _make_chain()
        bad_patch = dataclasses.replace(patch, plan_id="0000000000000000")
        with pytest.raises(TraceabilityError, match="plan_id"):
            generate_security_test(finding, plan, bad_patch, inventory)

    def test_patch_finding_id_mismatch(self) -> None:
        finding, plan, patch, inventory = _make_chain()
        bad_patch = dataclasses.replace(patch, finding_id="0000000000000000")
        with pytest.raises(TraceabilityError, match="finding_id"):
            generate_security_test(finding, plan, bad_patch, inventory)


# ---------------------------------------------------------------------------
# Case 7 — Failed patch
# ---------------------------------------------------------------------------


class TestFailedPatch:
    """A patch with applied=False must cause TraceabilityError."""

    def test_unapplied_patch_rejected(self) -> None:
        finding, plan, patch, inventory = _make_chain()
        unapplied = _make_patch(plan, applied=False)
        with pytest.raises(TraceabilityError, match="applied=False"):
            generate_security_test(finding, plan, unapplied, inventory)

    def test_error_mentions_patch_id(self) -> None:
        finding, plan, patch, inventory = _make_chain()
        unapplied = _make_patch(plan, applied=False)
        with pytest.raises(TraceabilityError) as exc_info:
            generate_security_test(finding, plan, unapplied, inventory)
        assert unapplied.patch_id in str(exc_info.value)


# ---------------------------------------------------------------------------
# Case 8 — Unsupported vulnerability type
# ---------------------------------------------------------------------------


class TestUnsupportedVulnerabilityType:
    """Non-command_injection findings must raise GenerationError."""

    def test_sqli_is_unsupported(self) -> None:
        finding = _make_finding(vulnerability_type="sql_injection")
        plan = _make_plan(finding)
        # Adjust plan's vulnerability_type to match
        plan = dataclasses.replace(plan, vulnerability_type="sql_injection")
        patch = _make_patch(plan)
        inventory = _make_inventory(_make_entry(finding.file, _OS_SYSTEM_SOURCE))
        with pytest.raises(GenerationError, match="not supported"):
            generate_security_test(finding, plan, patch, inventory)

    def test_error_mentions_vulnerability_type(self) -> None:
        finding = _make_finding(vulnerability_type="path_traversal")
        plan = dataclasses.replace(_make_plan(finding), vulnerability_type="path_traversal")
        patch = _make_patch(plan)
        inventory = _make_inventory(_make_entry(finding.file, _OS_SYSTEM_SOURCE))
        with pytest.raises(GenerationError) as exc_info:
            generate_security_test(finding, plan, patch, inventory)
        assert "path_traversal" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Case 9 — Missing source evidence
# ---------------------------------------------------------------------------


class TestMissingSourceEvidence:
    """Absent inventory source must raise GenerationError."""

    def test_empty_inventory_rejected(self) -> None:
        finding, plan, patch, _ = _make_chain()
        empty_inventory = _make_inventory()  # no files
        with pytest.raises(GenerationError, match="not available"):
            generate_security_test(finding, plan, patch, empty_inventory)

    def test_binary_entry_rejected(self) -> None:
        finding, plan, patch, _ = _make_chain()
        binary_entry = _make_entry(finding.file, None, is_text=False)
        inventory = _make_inventory(binary_entry)
        with pytest.raises(GenerationError, match="not available"):
            generate_security_test(finding, plan, patch, inventory)


# ---------------------------------------------------------------------------
# Case 10 — Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    """Same inputs must produce identical SecurityRegressionTest."""

    def test_test_id_is_deterministic(self) -> None:
        finding, plan, patch, inventory = _make_chain()
        test1, _ = generate_security_test(finding, plan, patch, inventory)
        test2, _ = generate_security_test(finding, plan, patch, inventory)
        assert test1.test_id == test2.test_id

    def test_test_code_is_deterministic(self) -> None:
        finding, plan, patch, inventory = _make_chain()
        test1, _ = generate_security_test(finding, plan, patch, inventory)
        test2, _ = generate_security_test(finding, plan, patch, inventory)
        assert test1.test_code == test2.test_code

    def test_outcome_id_is_deterministic(self) -> None:
        finding, plan, patch, inventory = _make_chain()
        _, outcome1 = generate_security_test(finding, plan, patch, inventory)
        _, outcome2 = generate_security_test(finding, plan, patch, inventory)
        assert outcome1.outcome_id == outcome2.outcome_id

    def test_test_id_derivation(self) -> None:
        finding, plan, patch, inventory = _make_chain()
        test, _ = generate_security_test(finding, plan, patch, inventory)
        expected = _test_id(patch.patch_id)
        assert test.test_id == expected

    def test_outcome_id_derivation(self) -> None:
        finding, plan, patch, inventory = _make_chain()
        _, outcome = generate_security_test(finding, plan, patch, inventory)
        expected = _outcome_id(finding.id)
        assert outcome.outcome_id == expected


# ---------------------------------------------------------------------------
# Case 11 — DesiredOutcome content
# ---------------------------------------------------------------------------


class TestDesiredOutcomeContent:
    """DesiredOutcome must carry all required requirement categories."""

    def _outcome(self) -> DesiredOutcome:
        finding, plan, patch, inventory = _make_chain()
        _, outcome = generate_security_test(finding, plan, patch, inventory)
        return outcome

    def test_security_invariants_nonempty(self) -> None:
        outcome = self._outcome()
        assert len(outcome.security_invariants) >= 1

    def test_regression_requirements_nonempty(self) -> None:
        outcome = self._outcome()
        assert len(outcome.regression_requirements) >= 1

    def test_verification_requirements_nonempty(self) -> None:
        outcome = self._outcome()
        assert len(outcome.verification_requirements) >= 1

    def test_security_invariant_mentions_shell(self) -> None:
        outcome = self._outcome()
        combined = " ".join(outcome.security_invariants).lower()
        assert "shell" in combined

    def test_security_invariant_mentions_data(self) -> None:
        outcome = self._outcome()
        combined = " ".join(outcome.security_invariants).lower()
        assert "data" in combined or "argument" in combined or "interpreted" in combined

    def test_regression_requirements_mention_existing_tests(self) -> None:
        outcome = self._outcome()
        combined = " ".join(outcome.regression_requirements).lower()
        assert "test" in combined

    def test_regression_requirements_mention_security_regression_test(self) -> None:
        outcome = self._outcome()
        combined = " ".join(outcome.regression_requirements).lower()
        assert "security" in combined

    def test_verification_requirements_mention_finding(self) -> None:
        outcome = self._outcome()
        combined = " ".join(outcome.verification_requirements).lower()
        assert "finding" in combined

    def test_verification_requirements_mention_independent_verification(self) -> None:
        outcome = self._outcome()
        combined = " ".join(outcome.verification_requirements).lower()
        assert "verif" in combined

    def test_outcome_not_marked_satisfied(self) -> None:
        """The DesiredOutcome model must not carry a 'satisfied' flag."""
        outcome = self._outcome()
        d = dataclasses.asdict(outcome)
        for key in d:
            assert "satisfied" not in key.lower(), (
                f"Field {key!r} implies premature satisfaction"
            )


# ---------------------------------------------------------------------------
# Case 12 — Model serialization
# ---------------------------------------------------------------------------


class TestModelSerialization:
    """SecurityRegressionTest and DesiredOutcome must be JSON-serializable."""

    def _gen(self):
        finding, plan, patch, inventory = _make_chain()
        return generate_security_test(finding, plan, patch, inventory)

    def test_regression_test_to_dict_returns_dict(self) -> None:
        test, _ = self._gen()
        assert isinstance(test.to_dict(), dict)

    def test_desired_outcome_to_dict_returns_dict(self) -> None:
        _, outcome = self._gen()
        assert isinstance(outcome.to_dict(), dict)

    def test_regression_test_json_serializable(self) -> None:
        test, _ = self._gen()
        # json.dumps must not raise
        raw = json.dumps(test.to_dict())
        assert raw

    def test_desired_outcome_json_serializable(self) -> None:
        _, outcome = self._gen()
        raw = json.dumps(outcome.to_dict())
        assert raw

    def test_regression_test_round_trip(self) -> None:
        test, _ = self._gen()
        d = test.to_dict()
        restored = SecurityRegressionTest(**d)
        assert restored == test

    def test_desired_outcome_round_trip(self) -> None:
        _, outcome = self._gen()
        d = outcome.to_dict()
        restored = DesiredOutcome(**d)
        assert restored == outcome

    def test_regression_test_is_dataclass(self) -> None:
        test, _ = self._gen()
        assert dataclasses.is_dataclass(test)

    def test_desired_outcome_is_dataclass(self) -> None:
        _, outcome = self._gen()
        assert dataclasses.is_dataclass(outcome)


# ---------------------------------------------------------------------------
# Case 13 — persist_security_test happy path
# ---------------------------------------------------------------------------


class TestPersistSecurityTest:
    """persist_security_test writes the test file correctly."""

    def _gen(self):
        finding, plan, patch, inventory = _make_chain()
        return generate_security_test(finding, plan, patch, inventory)

    def test_writes_file_inside_repo(self, tmp_path: Path) -> None:
        test, _ = self._gen()
        written = persist_security_test(test, tmp_path)
        assert written.exists()
        assert written.is_relative_to(tmp_path)

    def test_written_content_matches_test_code(self, tmp_path: Path) -> None:
        test, _ = self._gen()
        written = persist_security_test(test, tmp_path)
        assert written.read_text(encoding="utf-8") == test.test_code

    def test_idempotent_second_write(self, tmp_path: Path) -> None:
        test, _ = self._gen()
        written1 = persist_security_test(test, tmp_path)
        # Second call must not raise and must return the same path.
        written2 = persist_security_test(test, tmp_path)
        assert written1 == written2

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        test, _ = self._gen()
        written = persist_security_test(test, tmp_path)
        assert written.parent.is_dir()

    def test_written_file_path_corresponds_to_test_file(self, tmp_path: Path) -> None:
        test, _ = self._gen()
        written = persist_security_test(test, tmp_path)
        expected = (tmp_path / test.test_file).resolve()
        assert written.resolve() == expected


# ---------------------------------------------------------------------------
# Case 14 — persist_security_test conflict rejection
# ---------------------------------------------------------------------------


class TestPersistConflict:
    """An existing unrelated test file must not be overwritten."""

    def test_unrelated_existing_file_rejected(self, tmp_path: Path) -> None:
        finding, plan, patch, inventory = _make_chain()
        test, _ = generate_security_test(finding, plan, patch, inventory)

        # Pre-create an unrelated file at the same path.
        target = tmp_path / test.test_file
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("# existing unrelated test\nassert True\n", encoding="utf-8")

        with pytest.raises(GenerationError, match="Refusing to overwrite"):
            persist_security_test(test, tmp_path)


# ---------------------------------------------------------------------------
# Case 15 — persist_security_test path traversal
# ---------------------------------------------------------------------------


class TestPersistPathTraversal:
    """Path traversal in test_file must be rejected."""

    def test_traversal_outside_repo_rejected(self, tmp_path: Path) -> None:
        finding, plan, patch, inventory = _make_chain()
        test, _ = generate_security_test(finding, plan, patch, inventory)

        # Manually override test_file to attempt traversal.
        evil_test = dataclasses.replace(test, test_file="../../evil_test.py")
        with pytest.raises(GenerationError, match="outside the repository root"):
            persist_security_test(evil_test, tmp_path)


# ---------------------------------------------------------------------------
# Integration test — full vertical slice through all modules
# ---------------------------------------------------------------------------


class TestIntegrationFullSlice:
    """
    Full pipeline integration test:
        sample repository
            → inspect
            → analyze
            → find
            → plan
            → patch
            → generate_security_test
            → SecurityRegressionTest + DesiredOutcome

    The sample app contains some findings where ast.unparse() produces a
    single-quoted f-string that does not match the double-quoted source
    verbatim (routes.py), causing drift_detected in the patcher.  The
    integration tests therefore scan all findings and select the first one
    that results in an applied patch — mirroring the strategy used in
    test_patcher.py::TestEndToEndPipeline::test_controlled_sample_app.
    """

    _SAMPLES_DIR = Path(__file__).parent.parent / "samples" / "command_injection_app"

    def _build_tmp_repo(self, tmp_path: Path) -> Path:
        """Copy the sample repository into a clean temporary directory."""
        repo = tmp_path / "repo"
        shutil.copytree(str(self._SAMPLES_DIR), str(repo))
        return repo

    def _find_applied_chain(self, repo: Path):
        """
        Run the full pipeline over *repo* and return the first
        (finding, plan, patch, inventory) tuple where patch.applied is True.

        Raises AssertionError if no applied patch is found.
        """
        from secure_swe.analyzer import analyze_inventory
        from secure_swe.inspector import inspect_repository
        from secure_swe.patcher import apply_remediation
        from secure_swe.remediator import plan_remediation

        inventory = inspect_repository(str(repo))
        findings = analyze_inventory(inventory)
        assert findings, "Sample repository must yield at least one finding."

        for finding in findings:
            plan = plan_remediation(finding, inventory)
            if plan.strategy in ("unsupported", "planning_failure"):
                continue
            patch = apply_remediation(str(repo), plan)
            if patch.applied:
                return finding, plan, patch, inventory

        pytest.fail("No finding produced an applied patch in the sample repository.")

    def test_full_pipeline_produces_regression_test(self, tmp_path: Path) -> None:
        repo = self._build_tmp_repo(tmp_path)
        finding, plan, patch, inventory = self._find_applied_chain(repo)

        test, outcome = generate_security_test(finding, plan, patch, inventory)

        assert isinstance(test, SecurityRegressionTest)
        assert isinstance(outcome, DesiredOutcome)

    def test_full_pipeline_traceability(self, tmp_path: Path) -> None:
        repo = self._build_tmp_repo(tmp_path)
        finding, plan, patch, inventory = self._find_applied_chain(repo)

        test, outcome = generate_security_test(finding, plan, patch, inventory)

        # Full chain: finding → plan → patch → test → outcome
        assert plan.finding_id == finding.id
        assert patch.plan_id == plan.plan_id
        assert patch.finding_id == finding.id
        assert test.finding_id == finding.id
        assert test.plan_id == plan.plan_id
        assert test.patch_id == patch.patch_id
        assert outcome.finding_id == finding.id

    def test_full_pipeline_behavioral_test_code(self, tmp_path: Path) -> None:
        """Generated test code must contain behavioral mock-based assertions."""
        repo = self._build_tmp_repo(tmp_path)
        finding, plan, patch, inventory = self._find_applied_chain(repo)

        test, _ = generate_security_test(finding, plan, patch, inventory)

        code = test.test_code
        assert "example.invalid; SENTINEL" in code, "Must use harmless sentinel input"
        assert "patch(" in code, "Must mock process execution"
        assert "isinstance(first_arg, list)" in code, "Must verify list argument"

    def test_full_pipeline_desired_outcome_requirements(self, tmp_path: Path) -> None:
        """DesiredOutcome must specify all required requirement categories."""
        repo = self._build_tmp_repo(tmp_path)
        finding, plan, patch, inventory = self._find_applied_chain(repo)

        _, outcome = generate_security_test(finding, plan, patch, inventory)

        assert outcome.security_invariants
        assert outcome.regression_requirements
        assert outcome.verification_requirements

    def test_full_pipeline_persist_test_file(self, tmp_path: Path) -> None:
        """persist_security_test writes the file inside the repository."""
        repo = self._build_tmp_repo(tmp_path)
        finding, plan, patch, inventory = self._find_applied_chain(repo)

        test, _ = generate_security_test(finding, plan, patch, inventory)

        written = persist_security_test(test, repo)
        assert written.exists()
        assert written.is_relative_to(repo)
        content = written.read_text(encoding="utf-8")
        assert "Generated by secure_swe.test_generator." in content
