"""
Data models for Secure SWE Agent.

All models are plain dataclasses and are JSON-serializable via dataclasses.asdict().
"""

from __future__ import annotations

import dataclasses
from typing import Dict, List, Optional


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
