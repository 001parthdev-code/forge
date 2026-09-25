"""
Repository Inspector — Module 1 of Secure SWE Agent.

Produces a deterministic, read-only RepoInventory from a filesystem path.
This module performs NO vulnerability analysis.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import List

from secure_swe.models import FileEntry, InventorySummary, RepoInventory

# Files whose raw byte size exceeds this threshold are inventoried but their
# text content is not inlined into the RepoInventory artifact (~200 KB).
CONTENT_SIZE_LIMIT = 200 * 1024  # 200 KB

# Directory names that are always excluded from enumeration.
_EXCLUDED_DIRS = {".git"}


def inspect_repository(repo_path: str | os.PathLike) -> RepoInventory:
    """
    Inspect *repo_path* and return a :class:`~secure_swe.models.RepoInventory`.

    Parameters
    ----------
    repo_path:
        Filesystem path to the repository root.

    Raises
    ------
    FileNotFoundError
        When *repo_path* does not exist.
    NotADirectoryError
        When *repo_path* exists but is not a directory.
    """
    root = Path(repo_path).resolve()

    if not root.exists():
        raise FileNotFoundError(f"Repository path does not exist: {repo_path}")
    if not root.is_dir():
        raise NotADirectoryError(f"Repository path is not a directory: {repo_path}")

    raw_paths: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune excluded directories in-place so os.walk does not descend into them.
        dirnames[:] = sorted(
            d for d in dirnames if d not in _EXCLUDED_DIRS
        )
        for filename in filenames:
            raw_paths.append(Path(dirpath) / filename)

    # Deterministic lexicographic order by relative path (forward-slash normalised).
    raw_paths.sort(key=lambda p: _relative_posix(root, p))

    entries: List[FileEntry] = [_inspect_file(root, p) for p in raw_paths]

    summary = _build_summary(entries)

    return RepoInventory(
        repo_root=str(root),
        files=entries,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _relative_posix(root: Path, file_path: Path) -> str:
    """Return the POSIX-style relative path string from *root* to *file_path*."""
    return file_path.relative_to(root).as_posix()


def _inspect_file(root: Path, file_path: Path) -> FileEntry:
    """Read *file_path* and return a :class:`~secure_swe.models.FileEntry`."""
    rel = _relative_posix(root, file_path)
    ext = file_path.suffix  # includes leading "." or "" for no extension

    # --- Attempt to read raw bytes ---
    try:
        raw_bytes = file_path.read_bytes()
    except Exception as exc:  # noqa: BLE001
        # File exists in the tree but cannot be read.
        return FileEntry(
            relative_path=rel,
            extension=ext,
            size_bytes=_safe_stat(file_path),
            is_text=False,
            sha256=None,
            content=None,
            content_omission_reason=None,
            read_error=f"{type(exc).__name__}: {exc}",
        )

    size_bytes = len(raw_bytes)
    sha256 = hashlib.sha256(raw_bytes).hexdigest()

    # --- Determine whether to inline content ---
    if size_bytes > CONTENT_SIZE_LIMIT:
        return FileEntry(
            relative_path=rel,
            extension=ext,
            size_bytes=size_bytes,
            is_text=False,  # not assessed — content not decoded
            sha256=sha256,
            content=None,
            content_omission_reason=f"file exceeds inline-content limit ({CONTENT_SIZE_LIMIT} bytes)",
            read_error=None,
        )

    # --- Attempt UTF-8 decode ---
    try:
        text = raw_bytes.decode("utf-8")
        return FileEntry(
            relative_path=rel,
            extension=ext,
            size_bytes=size_bytes,
            is_text=True,
            sha256=sha256,
            content=text,
            content_omission_reason=None,
            read_error=None,
        )
    except UnicodeDecodeError:
        return FileEntry(
            relative_path=rel,
            extension=ext,
            size_bytes=size_bytes,
            is_text=False,
            sha256=sha256,
            content=None,
            content_omission_reason="binary file: not valid UTF-8",
            read_error=None,
        )


def _safe_stat(file_path: Path) -> int:
    """Return file size from stat, or 0 if stat itself fails."""
    try:
        return file_path.stat().st_size
    except Exception:  # noqa: BLE001
        return 0


def _build_summary(entries: List[FileEntry]) -> InventorySummary:
    count_by_ext: dict[str, int] = {}
    total_size = 0
    error_count = 0

    for entry in entries:
        count_by_ext[entry.extension] = count_by_ext.get(entry.extension, 0) + 1
        total_size += entry.size_bytes
        if entry.read_error is not None:
            error_count += 1

    return InventorySummary(
        total_files=len(entries),
        total_size_bytes=total_size,
        count_by_extension=count_by_ext,
        inspection_error_count=error_count,
    )
