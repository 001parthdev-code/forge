"""
Tests for Module 1 — Repository Inspector.

All fixtures are created in temporary directories; no test touches the
working tree or the samples/ directory.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
from pathlib import Path

import pytest

from secure_swe.inspector import CONTENT_SIZE_LIMIT, inspect_repository
from secure_swe.models import RepoInventory


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_repo(tmp_path: Path, files: dict[str, bytes]) -> Path:
    """Write *files* (relative path → bytes) into *tmp_path* and return it."""
    for rel, content in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return tmp_path


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Normal repository
# ---------------------------------------------------------------------------

class TestNormalRepository:
    """A small but representative repository with nested structure."""

    APP_PY = b"print('hello')\n"
    README = b"# My App\n"
    CONFIG = b'{"debug": false}\n'
    UTIL_PY = b"def helper(): pass\n"

    @pytest.fixture()
    def repo(self, tmp_path: Path) -> Path:
        return _make_repo(tmp_path, {
            "app.py": self.APP_PY,
            "README.md": self.README,
            "config.json": self.CONFIG,
            "nested/util.py": self.UTIL_PY,
        })

    def test_all_files_discovered(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        paths = [f.relative_path for f in inv.files]
        assert "app.py" in paths
        assert "README.md" in paths
        assert "config.json" in paths
        assert "nested/util.py" in paths

    def test_nested_file_discovered(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        assert any(f.relative_path == "nested/util.py" for f in inv.files)

    def test_relative_paths_no_absolute(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        for f in inv.files:
            assert not os.path.isabs(f.relative_path), (
                f"Expected relative path, got absolute: {f.relative_path}"
            )

    def test_relative_paths_forward_slash(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        for f in inv.files:
            assert "\\" not in f.relative_path, (
                f"Backslash found in path: {f.relative_path}"
            )

    def test_ordering_is_lexicographic(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        paths = [f.relative_path for f in inv.files]
        assert paths == sorted(paths)

    def test_text_content_captured(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        app = next(f for f in inv.files if f.relative_path == "app.py")
        assert app.is_text is True
        assert app.content == self.APP_PY.decode()

    def test_hashes_populated(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        for f in inv.files:
            assert f.sha256 is not None, f"Missing hash for {f.relative_path}"
            assert len(f.sha256) == 64  # SHA-256 hex is 64 chars

    def test_hash_values_correct(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        app = next(f for f in inv.files if f.relative_path == "app.py")
        assert app.sha256 == _sha256(self.APP_PY)

    def test_summary_total_file_count(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        assert inv.summary.total_files == 4

    def test_summary_total_size(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        expected = sum(len(b) for b in [
            self.APP_PY, self.README, self.CONFIG, self.UTIL_PY,
        ])
        assert inv.summary.total_size_bytes == expected

    def test_summary_count_by_extension(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        ext = inv.summary.count_by_extension
        assert ext.get(".py") == 2
        assert ext.get(".md") == 1
        assert ext.get(".json") == 1

    def test_summary_no_errors(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        assert inv.summary.inspection_error_count == 0

    def test_repo_root_is_absolute(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        assert os.path.isabs(inv.repo_root)

    def test_no_read_errors(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        for f in inv.files:
            assert f.read_error is None


# ---------------------------------------------------------------------------
# .git exclusion
# ---------------------------------------------------------------------------

class TestGitExclusion:
    def test_git_directory_excluded(self, tmp_path: Path) -> None:
        _make_repo(tmp_path, {
            "app.py": b"x = 1\n",
            ".git/HEAD": b"ref: refs/heads/main\n",
            ".git/config": b"[core]\n",
        })
        inv = inspect_repository(tmp_path)
        for f in inv.files:
            assert not f.relative_path.startswith(".git/"), (
                f".git file leaked into inventory: {f.relative_path}"
            )

    def test_normal_files_still_present_after_git_exclusion(
        self, tmp_path: Path
    ) -> None:
        _make_repo(tmp_path, {
            "app.py": b"x = 1\n",
            ".git/HEAD": b"ref: refs/heads/main\n",
        })
        inv = inspect_repository(tmp_path)
        assert any(f.relative_path == "app.py" for f in inv.files)

    def test_git_files_not_counted_in_summary(self, tmp_path: Path) -> None:
        _make_repo(tmp_path, {
            "app.py": b"x = 1\n",
            ".git/HEAD": b"ref: refs/heads/main\n",
        })
        inv = inspect_repository(tmp_path)
        assert inv.summary.total_files == 1


# ---------------------------------------------------------------------------
# Binary file
# ---------------------------------------------------------------------------

class TestBinaryFile:
    # Bytes that cannot be decoded as UTF-8.
    BINARY_DATA = bytes(range(256))

    @pytest.fixture()
    def repo(self, tmp_path: Path) -> Path:
        return _make_repo(tmp_path, {
            "data.bin": self.BINARY_DATA,
            "app.py": b"pass\n",
        })

    def test_binary_file_appears_in_inventory(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        assert any(f.relative_path == "data.bin" for f in inv.files)

    def test_binary_file_classified_as_non_text(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        entry = next(f for f in inv.files if f.relative_path == "data.bin")
        assert entry.is_text is False

    def test_binary_file_content_omitted(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        entry = next(f for f in inv.files if f.relative_path == "data.bin")
        assert entry.content is None

    def test_binary_file_has_hash(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        entry = next(f for f in inv.files if f.relative_path == "data.bin")
        assert entry.sha256 == _sha256(self.BINARY_DATA)

    def test_binary_file_has_omission_reason(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        entry = next(f for f in inv.files if f.relative_path == "data.bin")
        assert entry.content_omission_reason is not None
        assert len(entry.content_omission_reason) > 0

    def test_binary_file_no_read_error(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        entry = next(f for f in inv.files if f.relative_path == "data.bin")
        assert entry.read_error is None


# ---------------------------------------------------------------------------
# Large file
# ---------------------------------------------------------------------------

class TestLargeFile:
    @pytest.fixture()
    def large_content(self) -> bytes:
        # Slightly above the 200 KB limit, valid UTF-8 to confirm content is
        # still omitted based on size alone, not encoding failure.
        return b"A" * (CONTENT_SIZE_LIMIT + 1)

    @pytest.fixture()
    def repo(self, tmp_path: Path, large_content: bytes) -> Path:
        return _make_repo(tmp_path, {
            "large.txt": large_content,
            "small.py": b"pass\n",
        })

    def test_large_file_in_inventory(self, repo: Path, large_content: bytes) -> None:
        inv = inspect_repository(repo)
        assert any(f.relative_path == "large.txt" for f in inv.files)

    def test_large_file_size_correct(self, repo: Path, large_content: bytes) -> None:
        inv = inspect_repository(repo)
        entry = next(f for f in inv.files if f.relative_path == "large.txt")
        assert entry.size_bytes == len(large_content)

    def test_large_file_hash_available(self, repo: Path, large_content: bytes) -> None:
        inv = inspect_repository(repo)
        entry = next(f for f in inv.files if f.relative_path == "large.txt")
        assert entry.sha256 == _sha256(large_content)

    def test_large_file_content_omitted(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        entry = next(f for f in inv.files if f.relative_path == "large.txt")
        assert entry.content is None

    def test_large_file_omission_reason(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        entry = next(f for f in inv.files if f.relative_path == "large.txt")
        assert entry.content_omission_reason is not None

    def test_small_file_unaffected(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        small = next(f for f in inv.files if f.relative_path == "small.py")
        assert small.content == "pass\n"

    def test_summary_includes_large_file(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        assert inv.summary.total_files == 2


# ---------------------------------------------------------------------------
# Invalid paths
# ---------------------------------------------------------------------------

class TestInvalidPaths:
    def test_nonexistent_path_raises_file_not_found(self, tmp_path: Path) -> None:
        missing = tmp_path / "does_not_exist"
        with pytest.raises(FileNotFoundError):
            inspect_repository(missing)

    def test_regular_file_raises_not_a_directory(self, tmp_path: Path) -> None:
        f = tmp_path / "regular.txt"
        f.write_bytes(b"content")
        with pytest.raises(NotADirectoryError):
            inspect_repository(f)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

class TestDeterminism:
    @pytest.fixture()
    def repo(self, tmp_path: Path) -> Path:
        return _make_repo(tmp_path, {
            "z_last.py": b"z = 1\n",
            "a_first.py": b"a = 1\n",
            "middle/m.py": b"m = 1\n",
        })

    def test_two_inspections_produce_same_paths(self, repo: Path) -> None:
        inv1 = inspect_repository(repo)
        inv2 = inspect_repository(repo)
        assert [f.relative_path for f in inv1.files] == [
            f.relative_path for f in inv2.files
        ]

    def test_two_inspections_produce_same_hashes(self, repo: Path) -> None:
        inv1 = inspect_repository(repo)
        inv2 = inspect_repository(repo)
        assert [f.sha256 for f in inv1.files] == [f.sha256 for f in inv2.files]

    def test_two_inspections_are_structurally_equal(self, repo: Path) -> None:
        inv1 = inspect_repository(repo)
        inv2 = inspect_repository(repo)
        # Compare via dict (repo_root may differ only if tmp_path resolution
        # differs across calls — it won't for the same fixture instance).
        d1 = dataclasses.asdict(inv1)
        d2 = dataclasses.asdict(inv2)
        assert d1 == d2

    def test_paths_are_sorted_lexicographically(self, repo: Path) -> None:
        inv = inspect_repository(repo)
        paths = [f.relative_path for f in inv.files]
        assert paths == sorted(paths)


# ---------------------------------------------------------------------------
# JSON serialisability
# ---------------------------------------------------------------------------

class TestJsonSerialisation:
    def test_to_dict_is_json_serialisable(self, tmp_path: Path) -> None:
        import json
        _make_repo(tmp_path, {
            "app.py": b"x = 1\n",
            "data.bin": bytes(range(256)),
        })
        inv = inspect_repository(tmp_path)
        # Should not raise.
        serialised = json.dumps(inv.to_dict())
        assert isinstance(serialised, str)
        assert len(serialised) > 0

    def test_to_dict_round_trip(self, tmp_path: Path) -> None:
        import json
        _make_repo(tmp_path, {"app.py": b"pass\n"})
        inv = inspect_repository(tmp_path)
        d = inv.to_dict()
        # Re-parse and spot-check key fields survive round-trip.
        parsed = json.loads(json.dumps(d))
        assert parsed["repo_root"] == inv.repo_root
        assert len(parsed["files"]) == 1
        assert parsed["files"][0]["relative_path"] == "app.py"
