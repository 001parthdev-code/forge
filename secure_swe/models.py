"""
Data models for Secure SWE Agent.

All models are plain dataclasses and are JSON-serializable via dataclasses.asdict().
"""

from __future__ import annotations

import dataclasses
from typing import Dict, List, Literal, Optional


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
