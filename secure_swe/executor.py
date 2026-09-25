"""
Module 6 — Controlled Test Executor

Runs test suites inside a controlled workspace and returns structured
ExecutionResult / TestSuiteResult evidence.

Architecture boundary
---------------------
This module MUST NOT:
  * interpret test output to infer pass/fail beyond exit code;
  * use shell=True for any subprocess invocation;
  * modify repository files;
  * make network calls.

It MUST:
  * use explicit argument arrays (no shell expansion);
  * enforce a configurable timeout per suite;
  * capture stdout, stderr, and exit code;
  * distinguish timeout from ordinary failure;
  * return deterministic, JSON-serializable structured results.

SECURITY NOTE — EXECUTION ISOLATION
-------------------------------------
This executor uses subprocess.run() with a controlled working directory,
explicit argument arrays, and timeout enforcement.  It is a *controlled*
execution mechanism, NOT an OS-level sandbox.

Protections in place:
  * shell=True is never used — commands are passed as argument arrays.
  * Working directory is explicitly set to the workspace path.
  * Timeout prevents runaway processes.
  * No environment secrets are forwarded unnecessarily.

Protections NOT in place:
  * No container or VM isolation.
  * A malicious test could still read/write host filesystem.
  * No network egress filtering.

A future Rust enforcement boundary / stronger isolation layer may be
introduced after the core MVP is validated.  Do not rely on this executor
as a security sandbox.
"""

from __future__ import annotations

import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

from secure_swe.models import ExecutionResult, TestSuiteResult

logger = logging.getLogger(__name__)

# Default per-suite timeout in seconds.
DEFAULT_TIMEOUT_SECONDS: int = 60

# Exit code used when the process is killed by timeout.
_TIMEOUT_EXIT_CODE: int = -1


# ---------------------------------------------------------------------------
# Low-level execution primitive
# ---------------------------------------------------------------------------


def _run_command(
    command: List[str],
    working_dir: Path,
    timeout_seconds: int,
    test_category: str,
) -> ExecutionResult:
    """
    Execute *command* in *working_dir* and return a structured ExecutionResult.

    The process is never started via a shell.  stdout and stderr are fully
    captured.  The exit code is the sole determinant of ``passed``.

    Parameters
    ----------
    command:
        Explicit argument array.  Must NOT rely on shell expansion.
    working_dir:
        The directory in which to run the process.  Must exist.
    timeout_seconds:
        Maximum wall-clock time in seconds before the process is killed.
    test_category:
        One of "existing" or "security"; preserved in the result.
    """
    start = time.monotonic()
    timed_out = False
    exit_code = _TIMEOUT_EXIT_CODE
    stdout_text = ""
    stderr_text = ""

    try:
        result = subprocess.run(  # noqa: S603 — shell=False is explicit
            command,
            cwd=str(working_dir),
            timeout=timeout_seconds,
            capture_output=True,
            # Decode with errors="replace" — never crash on non-UTF-8 output.
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        exit_code = result.returncode
        stdout_text = result.stdout or ""
        stderr_text = result.stderr or ""

    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = _TIMEOUT_EXIT_CODE
        stdout_text = (exc.stdout or b"").decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr_text = (exc.stderr or b"").decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        logger.warning(
            "Test suite '%s' timed out after %ds.", test_category, timeout_seconds
        )

    except FileNotFoundError as exc:
        # pytest or python not found in the workspace.
        exit_code = 127
        stderr_text = f"Executable not found: {exc}"
        logger.error("Executor: command not found: %s", command[0])

    except Exception as exc:  # noqa: BLE001
        exit_code = 1
        stderr_text = f"Executor internal error: {type(exc).__name__}: {exc}"
        logger.exception("Executor: unexpected error running %s", command)

    duration = time.monotonic() - start

    # Pass only when exit_code is 0 AND the process was not killed by timeout.
    passed = (exit_code == 0) and (not timed_out)

    return ExecutionResult(
        command=list(command),
        exit_code=exit_code,
        stdout=stdout_text,
        stderr=stderr_text,
        duration_seconds=round(duration, 3),
        timed_out=timed_out,
        passed=passed,
        test_category=test_category,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# Suite-level runners
# ---------------------------------------------------------------------------


def run_existing_tests(
    workspace: Path,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    extra_args: Optional[List[str]] = None,
) -> ExecutionResult:
    """
    Run the existing test suite found inside *workspace*.

    Uses pytest via ``sys.executable -m pytest`` so the correct Python
    environment is always used.

    Parameters
    ----------
    workspace:
        Path to the workspace directory that contains the test suite.
    timeout_seconds:
        Maximum wall-clock time before the process is killed.
    extra_args:
        Optional additional pytest arguments (e.g. ["-x"]).
    """
    command = [
        sys.executable,
        "-m",
        "pytest",
        "--tb=short",
        "-q",
        "--no-header",
    ]
    if extra_args:
        command.extend(extra_args)

    logger.info("Running existing tests in '%s'.", workspace)
    return _run_command(command, workspace, timeout_seconds, "existing")


def run_security_test(
    workspace: Path,
    test_file: str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> ExecutionResult:
    """
    Run the generated security regression test at *test_file* inside *workspace*.

    The test file path is validated to be inside *workspace* before execution.

    Parameters
    ----------
    workspace:
        Path to the workspace directory.
    test_file:
        Repository-relative path to the security regression test file.
    timeout_seconds:
        Maximum wall-clock time before the process is killed.
    """
    # Path containment check — never execute a file outside the workspace.
    ws_resolved = workspace.resolve()
    test_resolved = (workspace / test_file).resolve()
    try:
        test_resolved.relative_to(ws_resolved)
    except ValueError:
        return ExecutionResult(
            command=[],
            exit_code=1,
            stdout="",
            stderr=(
                f"Security test path '{test_file}' resolves outside workspace "
                f"'{workspace}'.  Execution rejected."
            ),
            duration_seconds=0.0,
            timed_out=False,
            passed=False,
            test_category="security",
        )

    command = [
        sys.executable,
        "-m",
        "pytest",
        str(test_resolved),
        "--tb=short",
        "-q",
        "--no-header",
    ]

    logger.info("Running security test '%s' in '%s'.", test_file, workspace)
    return _run_command(command, workspace, timeout_seconds, "security")


# ---------------------------------------------------------------------------
# Composite runner
# ---------------------------------------------------------------------------


def run_test_suites(
    workspace: Path,
    security_test_file: str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> TestSuiteResult:
    """
    Run both the existing test suite and the security regression test.

    Returns a TestSuiteResult whose ``overall_passed`` is True only when
    BOTH suites pass.

    Parameters
    ----------
    workspace:
        Path to the workspace directory containing both test suites.
    security_test_file:
        Repository-relative path to the generated security regression test.
    timeout_seconds:
        Timeout applied to each suite independently.
    """
    existing = run_existing_tests(workspace, timeout_seconds=timeout_seconds)
    security = run_security_test(
        workspace, security_test_file, timeout_seconds=timeout_seconds
    )

    return TestSuiteResult(
        existing_tests=existing,
        security_tests=security,
        overall_passed=existing.passed and security.passed,
    )
