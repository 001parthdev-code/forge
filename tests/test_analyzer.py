"""
Tests for Module 2 — Security Analyzer.

Strategy
--------
All tests build a synthetic RepoInventory directly from in-memory source
strings via a small helper, without touching the filesystem.  This keeps the
tests fast, hermetic, and independent of Module 1 implementation details.

The full end-to-end pipeline test (inspect → analyze) uses a real temp
directory to confirm the two modules integrate correctly.
"""

from __future__ import annotations

import dataclasses
import hashlib
from pathlib import Path
from typing import Optional

import pytest

from secure_swe.analyzer import analyze_inventory
from secure_swe.inspector import inspect_repository
from secure_swe.models import (
    FileEntry,
    InventorySummary,
    RepoInventory,
    SecurityFinding,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_entry(
    relative_path: str,
    content: Optional[str],
    *,
    is_text: bool = True,
    extension: Optional[str] = None,
) -> FileEntry:
    """Build a synthetic FileEntry for a given source string."""
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


def _make_inventory(*entries: FileEntry) -> RepoInventory:
    """Build a minimal RepoInventory from the given FileEntry objects."""
    sorted_entries = sorted(entries, key=lambda e: e.relative_path)
    return RepoInventory(
        repo_root="/fake/repo",
        files=list(sorted_entries),
        summary=InventorySummary(
            total_files=len(sorted_entries),
            total_size_bytes=sum(e.size_bytes for e in sorted_entries),
            count_by_extension={},
            inspection_error_count=0,
        ),
    )


def _findings_for(source: str, path: str = "test_file.py") -> list[SecurityFinding]:
    """Convenience: analyze a single source string and return findings."""
    inv = _make_inventory(_make_entry(path, source))
    return analyze_inventory(inv)


# ---------------------------------------------------------------------------
# Positive: os.system with dynamic argument
# ---------------------------------------------------------------------------

class TestOsSystemDynamic:
    """os.system() with a dynamic argument should produce a finding."""

    def test_string_concatenation_flagged(self) -> None:
        source = """
import os

def ping(host):
    os.system("ping " + host)
"""
        findings = _findings_for(source)
        assert len(findings) == 1
        f = findings[0]
        assert f.vulnerability_type == "command_injection"
        assert f.sink == "os.system"
        assert f.severity == "HIGH"

    def test_variable_argument_flagged(self) -> None:
        source = """
import os

def run_cmd(cmd):
    os.system(cmd)
"""
        findings = _findings_for(source)
        assert len(findings) == 1
        assert findings[0].sink == "os.system"

    def test_fstring_argument_flagged(self) -> None:
        source = """
import os

def lookup(host):
    os.system(f"nslookup {host}")
"""
        findings = _findings_for(source)
        assert len(findings) == 1
        assert findings[0].sink == "os.system"

    def test_finding_contains_file_and_line(self) -> None:
        source = """
import os

def ping(host):
    os.system("ping " + host)
"""
        findings = _findings_for(source, path="app/network.py")
        assert len(findings) == 1
        f = findings[0]
        assert f.file == "app/network.py"
        assert f.line > 0

    def test_finding_contains_evidence(self) -> None:
        source = """
import os

def ping(host):
    os.system("ping " + host)
"""
        findings = _findings_for(source)
        # Evidence must describe the dynamic expression, not just "found".
        assert findings[0].evidence != ""
        assert len(findings[0].evidence) > 0

    def test_finding_contains_reason(self) -> None:
        source = """
import os

def ping(host):
    os.system("ping " + host)
"""
        findings = _findings_for(source)
        reason = findings[0].reason
        assert "os.system" in reason
        assert len(reason) > 20


# ---------------------------------------------------------------------------
# Positive: subprocess.run with shell=True and dynamic argument
# ---------------------------------------------------------------------------

class TestSubprocessRunShellTrue:
    """subprocess.run(..., shell=True) with a dynamic argument should flag."""

    def test_fstring_flagged(self) -> None:
        source = """
import subprocess

def lookup(target):
    command = f"nslookup {target}"
    subprocess.run(command, shell=True)
"""
        findings = _findings_for(source)
        assert len(findings) == 1
        f = findings[0]
        assert f.sink == "subprocess.run"
        assert f.vulnerability_type == "command_injection"

    def test_concatenation_flagged(self) -> None:
        source = """
import subprocess

def run(cmd):
    subprocess.run("sh " + cmd, shell=True)
"""
        findings = _findings_for(source)
        assert len(findings) == 1
        assert findings[0].sink == "subprocess.run"

    def test_variable_arg_flagged(self) -> None:
        source = """
import subprocess

def run(cmd):
    subprocess.run(cmd, shell=True)
"""
        findings = _findings_for(source)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# Positive: subprocess.call / subprocess.Popen with shell=True
# ---------------------------------------------------------------------------

class TestOtherSubprocessSinks:
    def test_subprocess_call_shell_true_dynamic(self) -> None:
        source = """
import subprocess

def exec_cmd(user_cmd):
    subprocess.call(user_cmd, shell=True)
"""
        findings = _findings_for(source)
        assert len(findings) == 1
        assert findings[0].sink == "subprocess.call"

    def test_subprocess_popen_shell_true_dynamic(self) -> None:
        source = """
import subprocess

def trace(dest):
    subprocess.Popen(f"traceroute {dest}", shell=True)
"""
        findings = _findings_for(source)
        assert len(findings) == 1
        assert findings[0].sink == "subprocess.Popen"


# ---------------------------------------------------------------------------
# Negative: safe subprocess argument list (no shell=True)
# ---------------------------------------------------------------------------

class TestSafeSubprocessList:
    """subprocess.run(["cmd", arg]) without shell=True must NOT be flagged."""

    def test_list_arg_no_shell_not_flagged(self) -> None:
        source = """
import subprocess

def safe_ping(host):
    subprocess.run(["ping", "-c", "1", host])
"""
        findings = _findings_for(source)
        assert findings == []

    def test_list_arg_shell_false_not_flagged(self) -> None:
        source = """
import subprocess

def safe_ping(host):
    subprocess.run(["ping", "-c", "1", host], shell=False)
"""
        findings = _findings_for(source)
        assert findings == []

    def test_subprocess_run_no_shell_kwarg_not_flagged(self) -> None:
        source = """
import subprocess

def run(cmd):
    subprocess.run(cmd)
"""
        findings = _findings_for(source)
        assert findings == []


# ---------------------------------------------------------------------------
# Negative: static (constant) command
# ---------------------------------------------------------------------------

class TestStaticCommand:
    """A constant command string must NOT produce a command-injection finding."""

    def test_os_system_static_not_flagged(self) -> None:
        source = """
import os

def check():
    os.system("ls -la")
"""
        findings = _findings_for(source)
        assert findings == []

    def test_subprocess_run_static_with_shell_not_flagged(self) -> None:
        source = """
import subprocess

def status():
    subprocess.run("uptime", shell=True)
"""
        findings = _findings_for(source)
        assert findings == []

    def test_subprocess_run_static_list_not_flagged(self) -> None:
        source = """
import subprocess

def status():
    subprocess.run(["uptime"])
"""
        findings = _findings_for(source)
        assert findings == []


# ---------------------------------------------------------------------------
# Negative: non-Python files skipped
# ---------------------------------------------------------------------------

class TestNonPythonFilesSkipped:
    def test_markdown_file_skipped(self) -> None:
        entry = _make_entry("README.md", "os.system(user_input)", extension=".md")
        inv = _make_inventory(entry)
        assert analyze_inventory(inv) == []

    def test_text_file_skipped(self) -> None:
        entry = _make_entry("notes.txt", "os.system(user_input)", extension=".txt")
        inv = _make_inventory(entry)
        assert analyze_inventory(inv) == []


# ---------------------------------------------------------------------------
# Negative: binary files and missing content skipped
# ---------------------------------------------------------------------------

class TestSkippedEntries:
    def test_binary_file_skipped(self) -> None:
        entry = _make_entry("lib.so", None, is_text=False, extension=".so")
        inv = _make_inventory(entry)
        assert analyze_inventory(inv) == []

    def test_content_none_skipped(self) -> None:
        """A .py entry with content=None (e.g. oversized) must be silently skipped."""
        entry = FileEntry(
            relative_path="big.py",
            extension=".py",
            size_bytes=999999,
            is_text=True,
            sha256="abc",
            content=None,
            content_omission_reason="exceeds size limit",
            read_error=None,
        )
        inv = _make_inventory(entry)
        assert analyze_inventory(inv) == []


# ---------------------------------------------------------------------------
# Robustness: malformed Python must not crash analysis
# ---------------------------------------------------------------------------

class TestRobustness:
    def test_malformed_python_does_not_abort_analysis(self) -> None:
        """
        A SyntaxError in one file must not prevent findings from other files.
        """
        bad_source = "def broken( this is not valid python @@@@"
        good_source = """
import os

def run(cmd):
    os.system(cmd)
"""
        inv = _make_inventory(
            _make_entry("broken.py", bad_source),
            _make_entry("good.py", good_source),
        )
        findings = analyze_inventory(inv)
        # The good file must still yield a finding.
        assert any(f.file == "good.py" for f in findings)

    def test_malformed_file_produces_no_finding(self) -> None:
        """A file that cannot be parsed should produce zero findings for itself."""
        bad_source = "def broken( @@@@"
        inv = _make_inventory(_make_entry("broken.py", bad_source))
        findings = analyze_inventory(inv)
        assert findings == []

    def test_empty_file_no_crash(self) -> None:
        inv = _make_inventory(_make_entry("empty.py", ""))
        assert analyze_inventory(inv) == []

    def test_empty_inventory_no_crash(self) -> None:
        inv = _make_inventory()
        assert analyze_inventory(inv) == []


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

class TestDeterminism:
    def test_two_analyses_produce_same_findings(self) -> None:
        source = """
import os
import subprocess

def run(host, cmd):
    os.system("ping " + host)
    subprocess.run(cmd, shell=True)
"""
        inv = _make_inventory(_make_entry("multi.py", source))
        findings1 = analyze_inventory(inv)
        findings2 = analyze_inventory(inv)
        assert [dataclasses.asdict(f) for f in findings1] == [
            dataclasses.asdict(f) for f in findings2
        ]

    def test_finding_ids_are_deterministic(self) -> None:
        source = """
import os

def ping(host):
    os.system("ping " + host)
"""
        inv = _make_inventory(_make_entry("app.py", source))
        ids1 = [f.id for f in analyze_inventory(inv)]
        ids2 = [f.id for f in analyze_inventory(inv)]
        assert ids1 == ids2

    def test_sorted_by_file_then_line(self) -> None:
        source_a = """
import os

def a(x):
    os.system(x)
"""
        source_b = """
import os

def b(y):
    os.system(y)
"""
        inv = _make_inventory(
            _make_entry("b_file.py", source_b),
            _make_entry("a_file.py", source_a),
        )
        findings = analyze_inventory(inv)
        files = [f.file for f in findings]
        assert files == sorted(files)


# ---------------------------------------------------------------------------
# SecurityFinding model contract
# ---------------------------------------------------------------------------

class TestFindingModel:
    def test_finding_is_json_serialisable(self) -> None:
        import json

        source = """
import os

def run(cmd):
    os.system(cmd)
"""
        inv = _make_inventory(_make_entry("app.py", source))
        findings = analyze_inventory(inv)
        assert len(findings) == 1
        serialised = json.dumps(findings[0].to_dict())
        assert isinstance(serialised, str)

    def test_finding_to_dict_round_trip(self) -> None:
        import json

        source = """
import os

def run(cmd):
    os.system(cmd)
"""
        inv = _make_inventory(_make_entry("app.py", source))
        finding = analyze_inventory(inv)[0]
        d = finding.to_dict()
        parsed = json.loads(json.dumps(d))
        assert parsed["vulnerability_type"] == "command_injection"
        assert parsed["sink"] == "os.system"
        assert isinstance(parsed["line"], int)
        assert parsed["file"] == "app.py"
        assert parsed["severity"] == "HIGH"
        assert parsed["confidence"] in ("HIGH", "MEDIUM", "LOW")
        assert len(parsed["id"]) == 16
        assert len(parsed["evidence"]) > 0
        assert len(parsed["reason"]) > 0


# ---------------------------------------------------------------------------
# End-to-end: real filesystem → inspect → analyze
# ---------------------------------------------------------------------------

class TestEndToEnd:
    """
    Full pipeline: write files to a temp dir → inspect_repository →
    analyze_inventory.  Confirms Module 1 and Module 2 integrate cleanly.
    """

    def test_vulnerable_sample_produces_findings(self, tmp_path: Path) -> None:
        (tmp_path / "system.py").write_text(
            "import os\n\ndef ping(host):\n    os.system('ping ' + host)\n"
        )
        inv = inspect_repository(tmp_path)
        findings = analyze_inventory(inv)
        assert len(findings) >= 1
        assert all(f.vulnerability_type == "command_injection" for f in findings)

    def test_safe_sample_produces_no_findings(self, tmp_path: Path) -> None:
        (tmp_path / "safe.py").write_text(
            "import subprocess\n\ndef ping(host):\n    subprocess.run(['ping', host])\n"
        )
        inv = inspect_repository(tmp_path)
        findings = analyze_inventory(inv)
        assert findings == []

    def test_controlled_sample_app(self, tmp_path: Path) -> None:
        """
        Analyze the controlled sample directory; expect the known three
        command-injection sinks: os.system, subprocess.run, subprocess.Popen.
        """
        import shutil
        from pathlib import Path as P

        sample_dir = P("samples/command_injection_app")
        if not sample_dir.exists():
            pytest.skip("Controlled sample not present")

        # Copy the sample into tmp_path so inspect_repository sees a clean tree.
        dest = tmp_path / "sample"
        shutil.copytree(sample_dir, dest)

        inv = inspect_repository(dest)
        findings = analyze_inventory(inv)

        sinks_found = {f.sink for f in findings}
        assert "os.system" in sinks_found
        assert "subprocess.run" in sinks_found
        assert "subprocess.Popen" in sinks_found

        # Static command in routes.py must NOT appear as a finding.
        static_findings = [
            f for f in findings
            if f.sink == "subprocess.run" and "uptime" in f.evidence
        ]
        assert static_findings == []
