"""
Tests for Module 3 — Security Remediation Planner.

Strategy
--------
All tests build synthetic RepoInventory / SecurityFinding objects in-memory
without touching the filesystem.  The end-to-end test uses a real temp
directory to exercise the full pipeline:

    inspect_repository → analyze_inventory → plan_remediation

Test matrix
-----------
Case 1  subprocess + shell=True (fstring)   → actionable plan
Case 2  os.system with dynamic argument     → actionable plan
Case 3  unsupported vulnerability type      → unsupported plan, no fabrication
Case 4  missing repository evidence         → planning_failure, no fabrication
Case 5  determinism                         → same inputs produce same output
E2E     full pipeline via sample repository
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
from typing import Optional

import pytest

from secure_swe.analyzer import analyze_inventory
from secure_swe.inspector import inspect_repository
from secure_swe.models import (
    FileEntry,
    InventorySummary,
    RemediationPlan,
    RepoInventory,
    SecurityFinding,
)
from secure_swe.remediator import plan_remediation, plan_remediations


# ---------------------------------------------------------------------------
# Helpers (mirrors test_analyzer.py conventions)
# ---------------------------------------------------------------------------

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


def _make_inventory(*entries: FileEntry, repo_root: str = "/fake/repo") -> RepoInventory:
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


def _finding_id(vulnerability_type: str, file: str, line: int, sink: str) -> str:
    raw = f"{vulnerability_type}|{file}|{line}|{sink}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _make_finding(
    *,
    vulnerability_type: str = "command_injection",
    file: str = "app.py",
    line: int = 5,
    sink: str = "subprocess.run",
    evidence: str = "f'ping {host}'",
    severity: str = "HIGH",
    confidence: str = "MEDIUM",
) -> SecurityFinding:
    fid = _finding_id(vulnerability_type, file, line, sink)
    return SecurityFinding(
        id=fid,
        vulnerability_type=vulnerability_type,
        severity=severity,  # type: ignore[arg-type]
        file=file,
        line=line,
        sink=sink,
        evidence=evidence,
        reason="Test finding",
        confidence=confidence,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# Case 1 — subprocess.run with shell=True and f-string
# ---------------------------------------------------------------------------

class TestSubprocessShellTrue:
    """subprocess.run(f'ping {host}', shell=True) → replace_shell_string_with_arg_list"""

    SOURCE = """\
import subprocess

def ping(host):
    command = f"ping {host}"
    subprocess.run(command, shell=True)
"""

    def _inventory(self) -> RepoInventory:
        return _make_inventory(_make_entry("net/ping.py", self.SOURCE))

    def _finding(self) -> SecurityFinding:
        # line 5 is the subprocess.run call
        inv = self._inventory()
        findings = analyze_inventory(inv)
        assert findings, "pre-condition: analyzer must detect finding in SOURCE"
        return findings[0]

    def test_plan_references_original_finding(self) -> None:
        finding = self._finding()
        plan = plan_remediation(finding, self._inventory())
        assert plan.finding_id == finding.id

    def test_plan_targets_correct_file_and_line(self) -> None:
        finding = self._finding()
        plan = plan_remediation(finding, self._inventory())
        assert plan.target_file == finding.file
        assert plan.target_line == finding.line

    def test_strategy_removes_shell_interpretation(self) -> None:
        finding = self._finding()
        plan = plan_remediation(finding, self._inventory())
        assert plan.strategy == "replace_shell_string_with_arg_list"

    def test_proposed_code_uses_argument_list(self) -> None:
        finding = self._finding()
        plan = plan_remediation(finding, self._inventory())
        assert plan.proposed_code is not None
        # Must not use shell=True
        assert "shell=True" not in plan.proposed_code
        # Must use list syntax
        assert "[" in plan.proposed_code

    def test_proposed_code_resolves_simple_indirect_variable(self) -> None:
        # The v0 planner resolves a simple straight-line local assignment feeding
        # the dangerous sink so it can construct a concrete argv remediation.
        finding = self._finding()
        plan = plan_remediation(finding, self._inventory())
        assert plan.proposed_code is not None
        assert "<dynamic_value>" not in plan.proposed_code
        assert '"ping"' in plan.proposed_code
        assert "host" in plan.proposed_code

    def test_security_invariant_present(self) -> None:
        finding = self._finding()
        plan = plan_remediation(finding, self._inventory())
        assert plan.security_invariant
        assert "shell" in plan.security_invariant.lower()

    def test_validation_requirements_present(self) -> None:
        finding = self._finding()
        plan = plan_remediation(finding, self._inventory())
        assert len(plan.validation_requirements) >= 3

    def test_validation_requires_no_shell(self) -> None:
        finding = self._finding()
        plan = plan_remediation(finding, self._inventory())
        combined = " ".join(plan.validation_requirements).lower()
        assert "shell" in combined

    def test_validation_requires_existing_tests_pass(self) -> None:
        finding = self._finding()
        plan = plan_remediation(finding, self._inventory())
        combined = " ".join(plan.validation_requirements).lower()
        assert "test" in combined

    def test_validation_requires_security_regression_test(self) -> None:
        finding = self._finding()
        plan = plan_remediation(finding, self._inventory())
        combined = " ".join(plan.validation_requirements).lower()
        assert "regression" in combined or "security" in combined

    def test_plan_is_json_serialisable(self) -> None:
        finding = self._finding()
        plan = plan_remediation(finding, self._inventory())
        d = plan.to_dict()
        json.dumps(d)  # must not raise

    def test_plan_has_plan_id(self) -> None:
        finding = self._finding()
        plan = plan_remediation(finding, self._inventory())
        assert plan.plan_id
        assert len(plan.plan_id) == 16

    def test_subprocess_call_shell_true(self) -> None:
        source = "import subprocess\ndef fn(cmd): subprocess.call(cmd, shell=True)\n"
        inv = _make_inventory(_make_entry("mod.py", source))
        findings = analyze_inventory(inv)
        assert findings
        plan = plan_remediation(findings[0], inv)
        assert plan.strategy == "replace_shell_string_with_arg_list"
        assert plan.proposed_code is not None

    def test_subprocess_popen_shell_true(self) -> None:
        source = "import subprocess\ndef fn(dst): subprocess.Popen(f'traceroute {dst}', shell=True)\n"
        inv = _make_inventory(_make_entry("mod.py", source))
        findings = analyze_inventory(inv)
        assert findings
        plan = plan_remediation(findings[0], inv)
        assert plan.strategy == "replace_shell_string_with_arg_list"
        assert plan.proposed_code is not None
        assert "Popen" in plan.proposed_code


# ---------------------------------------------------------------------------
# Case 2 — os.system with dynamic argument
# ---------------------------------------------------------------------------

class TestOsSystem:
    """os.system("ping -c 1 " + host) → replace_os_system_with_subprocess_list"""

    SOURCE = """\
import os

def ping_host(host):
    return os.system("ping -c 1 " + host)
"""

    def _inventory(self) -> RepoInventory:
        return _make_inventory(_make_entry("utils/net.py", self.SOURCE))

    def _finding(self) -> SecurityFinding:
        inv = self._inventory()
        findings = analyze_inventory(inv)
        assert findings, "pre-condition: analyzer must detect os.system finding"
        return findings[0]

    def test_strategy_migrates_away_from_os_system(self) -> None:
        finding = self._finding()
        plan = plan_remediation(finding, self._inventory())
        assert plan.strategy == "replace_os_system_with_subprocess_list"

    def test_proposed_code_uses_subprocess(self) -> None:
        finding = self._finding()
        plan = plan_remediation(finding, self._inventory())
        assert plan.proposed_code is not None
        assert "subprocess.run" in plan.proposed_code

    def test_proposed_code_uses_list_not_shell_string(self) -> None:
        finding = self._finding()
        plan = plan_remediation(finding, self._inventory())
        assert plan.proposed_code is not None
        assert "[" in plan.proposed_code
        assert "shell=True" not in plan.proposed_code

    def test_proposed_code_preserves_program_name(self) -> None:
        finding = self._finding()
        plan = plan_remediation(finding, self._inventory())
        assert plan.proposed_code is not None
        assert '"ping"' in plan.proposed_code

    def test_finding_to_plan_traceability(self) -> None:
        finding = self._finding()
        plan = plan_remediation(finding, self._inventory())
        assert plan.finding_id == finding.id
        assert plan.target_file == finding.file
        assert plan.target_line == finding.line
        assert plan.vulnerability_type == finding.vulnerability_type

    def test_plan_has_security_invariant(self) -> None:
        finding = self._finding()
        plan = plan_remediation(finding, self._inventory())
        assert plan.security_invariant
        assert len(plan.security_invariant) > 20

    def test_original_code_is_complete_dangerous_call(self) -> None:
        finding = self._finding()
        plan = plan_remediation(finding, self._inventory())
        assert plan.original_code.startswith("os.system(")
        assert finding.evidence in plan.original_code or "ping -c 1" in plan.original_code

    def test_os_system_variable_arg(self) -> None:
        source = "import os\ndef run(cmd): os.system(cmd)\n"
        inv = _make_inventory(_make_entry("script.py", source))
        findings = analyze_inventory(inv)
        assert findings
        plan = plan_remediation(findings[0], inv)
        assert plan.strategy == "replace_os_system_with_subprocess_list"
        # No static args known → placeholder list
        assert plan.proposed_code is not None
        assert "[" in plan.proposed_code


# ---------------------------------------------------------------------------
# Case 3 — unsupported vulnerability type
# ---------------------------------------------------------------------------

class TestUnsupportedVulnerabilityType:
    """A finding with a type other than command_injection must not be fabricated."""

    def _sqli_finding(self) -> SecurityFinding:
        return SecurityFinding(
            id="aabbccdd11223344",
            vulnerability_type="sql_injection",
            severity="HIGH",
            file="db/query.py",
            line=10,
            sink="cursor.execute",
            evidence='f"SELECT * FROM users WHERE id={user_id}"',
            reason="Dynamic SQL construction",
            confidence="MEDIUM",
        )

    def _inventory(self) -> RepoInventory:
        source = 'def q(uid): cursor.execute(f"SELECT * FROM users WHERE id={uid}")\n'
        return _make_inventory(_make_entry("db/query.py", source))

    def test_returns_unsupported_strategy(self) -> None:
        plan = plan_remediation(self._sqli_finding(), self._inventory())
        assert plan.strategy == "unsupported"

    def test_no_proposed_code(self) -> None:
        plan = plan_remediation(self._sqli_finding(), self._inventory())
        assert plan.proposed_code is None

    def test_no_empty_validation_requirements(self) -> None:
        """Unsupported plans carry no validation requirements (nothing to verify)."""
        plan = plan_remediation(self._sqli_finding(), self._inventory())
        assert plan.validation_requirements == []

    def test_finding_traceability_preserved(self) -> None:
        finding = self._sqli_finding()
        plan = plan_remediation(finding, self._inventory())
        assert plan.finding_id == finding.id
        assert plan.vulnerability_type == finding.vulnerability_type

    def test_reason_mentions_unsupported_type(self) -> None:
        plan = plan_remediation(self._sqli_finding(), self._inventory())
        assert "sql_injection" in plan.reason

    def test_plan_id_is_deterministic(self) -> None:
        finding = self._sqli_finding()
        inv = self._inventory()
        plan1 = plan_remediation(finding, inv)
        plan2 = plan_remediation(finding, inv)
        assert plan1.plan_id == plan2.plan_id

    def test_xss_finding_also_unsupported(self) -> None:
        finding = SecurityFinding(
            id="deadbeef12345678",
            vulnerability_type="xss",
            severity="MEDIUM",
            file="web/template.py",
            line=3,
            sink="render",
            evidence="user_input",
            reason="Reflected user data",
            confidence="LOW",
        )
        source = "def render(user_input): return user_input\n"
        inv = _make_inventory(_make_entry("web/template.py", source))
        plan = plan_remediation(finding, inv)
        assert plan.strategy == "unsupported"
        assert plan.proposed_code is None


# ---------------------------------------------------------------------------
# Case 4 — missing repository evidence
# ---------------------------------------------------------------------------

class TestMissingRepositoryEvidence:
    """Finding references source that cannot be reconciled with the inventory."""

    def _finding_missing_file(self) -> SecurityFinding:
        return _make_finding(file="ghost/missing.py", line=3)

    def _finding_binary_file(self) -> SecurityFinding:
        return _make_finding(file="binary.py", line=1)

    def _finding_bad_line(self) -> SecurityFinding:
        return _make_finding(file="small.py", line=9999)

    def test_missing_file_returns_planning_failure(self) -> None:
        # Inventory has no entry for "ghost/missing.py"
        inv = _make_inventory(_make_entry("other.py", "x = 1\n"))
        plan = plan_remediation(self._finding_missing_file(), inv)
        assert plan.strategy == "planning_failure"

    def test_missing_file_no_proposed_code(self) -> None:
        inv = _make_inventory(_make_entry("other.py", "x = 1\n"))
        plan = plan_remediation(self._finding_missing_file(), inv)
        assert plan.proposed_code is None

    def test_binary_content_none_returns_planning_failure(self) -> None:
        # Entry exists but content is None (binary file)
        entry = _make_entry("binary.py", None, is_text=False)
        inv = _make_inventory(entry)
        plan = plan_remediation(self._finding_binary_file(), inv)
        assert plan.strategy == "planning_failure"

    def test_binary_content_none_no_proposed_code(self) -> None:
        entry = _make_entry("binary.py", None, is_text=False)
        inv = _make_inventory(entry)
        plan = plan_remediation(self._finding_binary_file(), inv)
        assert plan.proposed_code is None

    def test_out_of_range_line_returns_planning_failure(self) -> None:
        # File has 2 lines, finding claims line 9999
        source = "import os\nos.system(cmd)\n"
        inv = _make_inventory(_make_entry("small.py", source))
        plan = plan_remediation(self._finding_bad_line(), inv)
        assert plan.strategy == "planning_failure"

    def test_planning_failure_preserves_traceability(self) -> None:
        finding = self._finding_missing_file()
        inv = _make_inventory(_make_entry("other.py", "x = 1\n"))
        plan = plan_remediation(finding, inv)
        assert plan.finding_id == finding.id
        assert plan.target_file == finding.file

    def test_empty_inventory_returns_planning_failure(self) -> None:
        finding = _make_finding(file="app.py", line=1)
        inv = _make_inventory()
        plan = plan_remediation(finding, inv)
        assert plan.strategy == "planning_failure"


# ---------------------------------------------------------------------------
# Case 5 — determinism
# ---------------------------------------------------------------------------

class TestDeterminism:
    """Same finding + same inventory must always produce equivalent plans."""

    SOURCE = """\
import subprocess

def traceroute(dest):
    subprocess.Popen(f"traceroute {dest}", shell=True)
"""

    def _setup(self):
        inv = _make_inventory(_make_entry("net/trace.py", self.SOURCE))
        findings = analyze_inventory(inv)
        assert findings
        return findings[0], inv

    def test_repeated_calls_produce_same_plan(self) -> None:
        finding, inv = self._setup()
        plan1 = plan_remediation(finding, inv)
        plan2 = plan_remediation(finding, inv)
        assert dataclasses.asdict(plan1) == dataclasses.asdict(plan2)

    def test_plan_ids_are_identical_on_repeat(self) -> None:
        finding, inv = self._setup()
        plan1 = plan_remediation(finding, inv)
        plan2 = plan_remediation(finding, inv)
        assert plan1.plan_id == plan2.plan_id

    def test_plan_id_differs_from_finding_id(self) -> None:
        finding, inv = self._setup()
        plan = plan_remediation(finding, inv)
        assert plan.plan_id != plan.finding_id

    def test_proposed_code_identical_on_repeat(self) -> None:
        finding, inv = self._setup()
        plan1 = plan_remediation(finding, inv)
        plan2 = plan_remediation(finding, inv)
        assert plan1.proposed_code == plan2.proposed_code

    def test_different_findings_produce_different_plan_ids(self) -> None:
        source_a = "import os\ndef a(x): os.system(x)\n"
        source_b = "import subprocess\ndef b(x): subprocess.run(x, shell=True)\n"
        inv_a = _make_inventory(_make_entry("a.py", source_a))
        inv_b = _make_inventory(_make_entry("b.py", source_b))
        findings_a = analyze_inventory(inv_a)
        findings_b = analyze_inventory(inv_b)
        assert findings_a and findings_b
        plan_a = plan_remediation(findings_a[0], inv_a)
        plan_b = plan_remediation(findings_b[0], inv_b)
        assert plan_a.plan_id != plan_b.plan_id

    def test_plan_id_is_16_hex_chars(self) -> None:
        finding, inv = self._setup()
        plan = plan_remediation(finding, inv)
        assert len(plan.plan_id) == 16
        assert all(c in "0123456789abcdef" for c in plan.plan_id)


# ---------------------------------------------------------------------------
# RemediationPlan model contract
# ---------------------------------------------------------------------------

class TestRemediationPlanModel:
    """Unit tests for the RemediationPlan dataclass itself."""

    SOURCE = "import os\ndef run(cmd): return os.system(cmd)\n"

    def _plan(self) -> RemediationPlan:
        inv = _make_inventory(_make_entry("script.py", self.SOURCE))
        findings = analyze_inventory(inv)
        assert findings
        return plan_remediation(findings[0], inv)

    def test_plan_is_dataclass(self) -> None:
        plan = self._plan()
        assert dataclasses.is_dataclass(plan)

    def test_to_dict_returns_dict(self) -> None:
        plan = self._plan()
        d = plan.to_dict()
        assert isinstance(d, dict)

    def test_to_dict_round_trip(self) -> None:
        plan = self._plan()
        d = plan.to_dict()
        assert d["plan_id"] == plan.plan_id
        assert d["finding_id"] == plan.finding_id
        assert d["vulnerability_type"] == plan.vulnerability_type
        assert d["target_file"] == plan.target_file
        assert d["target_line"] == plan.target_line
        assert d["strategy"] == plan.strategy
        assert d["security_invariant"] == plan.security_invariant
        assert d["proposed_code"] == plan.proposed_code
        assert d["original_code"] == plan.original_code

    def test_full_json_serialisable(self) -> None:
        plan = self._plan()
        json.dumps(plan.to_dict())  # must not raise

    def test_validation_requirements_is_list(self) -> None:
        plan = self._plan()
        assert isinstance(plan.validation_requirements, list)
        for req in plan.validation_requirements:
            assert isinstance(req, str)


# ---------------------------------------------------------------------------
# plan_remediations collection helper
# ---------------------------------------------------------------------------

class TestPlanRemediations:
    """plan_remediations returns one plan per finding in order."""

    SOURCE = """\
import os
import subprocess

def a(x): os.system(x)
def b(x): subprocess.run(x, shell=True)
"""

    def test_returns_one_plan_per_finding(self) -> None:
        inv = _make_inventory(_make_entry("multi.py", self.SOURCE))
        findings = analyze_inventory(inv)
        assert len(findings) == 2
        plans = plan_remediations(findings, inv)
        assert len(plans) == 2

    def test_order_preserved(self) -> None:
        inv = _make_inventory(_make_entry("multi.py", self.SOURCE))
        findings = analyze_inventory(inv)
        plans = plan_remediations(findings, inv)
        for finding, plan in zip(findings, plans):
            assert plan.finding_id == finding.id

    def test_empty_findings_returns_empty(self) -> None:
        inv = _make_inventory(_make_entry("clean.py", "x = 1\n"))
        plans = plan_remediations([], inv)
        assert plans == []


# ---------------------------------------------------------------------------
# End-to-end integration: inspect → analyze → plan
# ---------------------------------------------------------------------------

class TestEndToEndPipeline:
    """
    Full vertical slice from on-disk source to RemediationPlan.

    Uses a temporary repository with vulnerable Python files.
    """

    PING_SOURCE = """\
import subprocess

def ping(host):
    command = f"ping {host}"
    subprocess.run(command, shell=True)
"""

    SYSTEM_SOURCE = """\
import os

def check(host):
    return os.system("ping -c 1 " + host)
"""

    def test_pipeline_subprocess_fstring(self, tmp_path: Path) -> None:
        (tmp_path / "ping.py").write_text(self.PING_SOURCE, encoding="utf-8")
        inv = inspect_repository(str(tmp_path))
        findings = analyze_inventory(inv)
        assert findings, "analyzer must detect finding in PING_SOURCE"
        plans = plan_remediations(findings, inv)
        assert len(plans) == len(findings)

        plan = plans[0]
        assert plan.finding_id == findings[0].id
        assert plan.strategy == "replace_shell_string_with_arg_list"
        assert plan.proposed_code is not None
        assert "shell=True" not in plan.proposed_code
        assert "[" in plan.proposed_code
        assert plan.security_invariant
        assert plan.validation_requirements

    def test_pipeline_os_system(self, tmp_path: Path) -> None:
        (tmp_path / "sys.py").write_text(self.SYSTEM_SOURCE, encoding="utf-8")
        inv = inspect_repository(str(tmp_path))
        findings = analyze_inventory(inv)
        assert findings, "analyzer must detect finding in SYSTEM_SOURCE"
        plans = plan_remediations(findings, inv)
        plan = plans[0]
        assert plan.finding_id == findings[0].id
        assert plan.strategy == "replace_os_system_with_subprocess_list"
        assert plan.proposed_code is not None
        assert "subprocess.run" in plan.proposed_code

    def test_pipeline_traceability_chain(self, tmp_path: Path) -> None:
        """Finding id links back from plan_id via deterministic derivation."""
        (tmp_path / "vuln.py").write_text(self.PING_SOURCE, encoding="utf-8")
        inv = inspect_repository(str(tmp_path))
        findings = analyze_inventory(inv)
        plans = plan_remediations(findings, inv)

        finding = findings[0]
        plan = plans[0]

        # Traceability: plan → finding
        assert plan.finding_id == finding.id

        # plan_id is derived deterministically from finding_id
        import hashlib
        expected_plan_id = hashlib.sha256(
            f"plan|{finding.id}".encode()
        ).hexdigest()[:16]
        assert plan.plan_id == expected_plan_id

    def test_controlled_sample_app(self, tmp_path: Path) -> None:
        """Run the full pipeline over the controlled sample repository."""
        import shutil
        sample_dir = Path("samples/command_injection_app")
        if not sample_dir.exists():
            pytest.skip("sample directory not found")

        dest = tmp_path / "sample"
        shutil.copytree(str(sample_dir), str(dest))

        inv = inspect_repository(str(dest))
        findings = analyze_inventory(inv)
        assert findings, "sample app must produce at least one finding"

        plans = plan_remediations(findings, inv)
        assert len(plans) == len(findings)

        for finding, plan in zip(findings, plans):
            assert plan.finding_id == finding.id
            assert plan.strategy in (
                "replace_shell_string_with_arg_list",
                "replace_os_system_with_subprocess_list",
                "unsupported",
                "planning_failure",
            )
            # All actionable plans must have a security invariant
            assert plan.security_invariant

    def test_no_files_modified(self, tmp_path: Path) -> None:
        """The planner must not write to the repository."""
        source = "import subprocess\ndef f(x): subprocess.run(x, shell=True)\n"
        vuln_file = tmp_path / "vuln.py"
        vuln_file.write_text(source, encoding="utf-8")
        original_content = vuln_file.read_text(encoding="utf-8")
        original_mtime = vuln_file.stat().st_mtime

        inv = inspect_repository(str(tmp_path))
        findings = analyze_inventory(inv)
        plan_remediations(findings, inv)

        assert vuln_file.read_text(encoding="utf-8") == original_content
        assert vuln_file.stat().st_mtime == original_mtime
