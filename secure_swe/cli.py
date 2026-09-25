"""
Secure SWE CLI — entry point for the closed-loop security remediation agent.

Usage
-----
    python -m secure_swe.cli --help
    python -m secure_swe.cli <repo_path>
    python -m secure_swe.cli <repo_path> --json
    python -m secure_swe.cli <repo_path> --output artifacts/run.json
    python -m secure_swe.cli <repo_path> --max-attempts 3 --timeout 60

Exit codes
----------
    0  — VERIFIED
    1  — HUMAN_REVIEW_REQUIRED
    2  — ERROR (workflow-level failure)
    3  — CLI usage / argument error
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Optional

from secure_swe.orchestrator import MAX_ATTEMPTS, run_secure_remediation
from secure_swe.models import RemediationWorkflowResult
from secure_swe.report import render_workflow_report
from secure_swe.display import WorkflowDisplay
from secure_swe.evaluation import compute_metrics


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

EXIT_VERIFIED = 0
EXIT_HUMAN_REVIEW = 1
EXIT_ERROR = 2
EXIT_USAGE = 3


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _resolve_output_path(output: str) -> Path:
    """Resolve and create parent directories for the output path."""
    p = Path(output)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _write_json(result: RemediationWorkflowResult, output: Optional[str]) -> None:
    """Serialize result to JSON and write to output path or stdout."""
    data = result.to_dict()
    serialized = json.dumps(data, indent=2, default=str)
    if output:
        path = _resolve_output_path(output)
        path.write_text(serialized, encoding="utf-8")
    else:
        print(serialized)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secure-swe",
        description=(
            "Secure SWE Agent — closed-loop security remediation engine.\n\n"
            "Inspects a Python repository for command-injection vulnerabilities,\n"
            "engineers a verified remediation, and produces a structured evidence report."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes:
  0  VERIFIED           — remediation succeeded and was independently verified
  1  HUMAN_REVIEW       — remediation could not be verified within attempt budget
  2  ERROR              — an unexpected workflow-level failure occurred
  3  USAGE              — invalid arguments

Examples:
  python -m secure_swe.cli ./samples/command_injection_app
  python -m secure_swe.cli ./samples/command_injection_app --json
  python -m secure_swe.cli ./samples/command_injection_app --output artifacts/run.json
  python -m secure_swe.cli ./samples/scenario_b_feedback_loop --max-attempts 3
  python -m secure_swe.cli ./samples/scenario_c_escalation
""",
    )

    parser.add_argument(
        "repo_path",
        help="Path to the repository to remediate.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="emit_json",
        help="Emit the full structured JSON report to stdout instead of human-readable output.",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write the JSON report to FILE (may be combined with or without --json).",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=MAX_ATTEMPTS,
        metavar="N",
        help=f"Maximum remediation attempts (default: {MAX_ATTEMPTS}, max: 5).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        metavar="SECONDS",
        help="Per-test-suite execution timeout in seconds (default: 60).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress workflow progress output (useful with --json).",
    )

    return parser


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    """
    Run the CLI.  Returns an exit code.

    Does NOT call sys.exit() — that responsibility is deferred to the caller
    (``__main__.py``) so that the function remains testable.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    # ------------------------------------------------------------------
    # Validate repo path
    # ------------------------------------------------------------------
    repo_path = Path(args.repo_path).resolve()
    if not repo_path.exists():
        print(
            f"secure-swe: error: path does not exist: {args.repo_path}",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if not repo_path.is_dir():
        print(
            f"secure-swe: error: path is not a directory: {args.repo_path}",
            file=sys.stderr,
        )
        return EXIT_USAGE

    # ------------------------------------------------------------------
    # Display setup
    # ------------------------------------------------------------------
    display = WorkflowDisplay(quiet=args.quiet or args.emit_json)

    display.header(str(args.repo_path))

    # ------------------------------------------------------------------
    # Run workflow
    # ------------------------------------------------------------------
    wall_start = time.monotonic()

    result = run_secure_remediation(
        repo_path=str(repo_path),
        max_attempts=args.max_attempts,
        timeout_seconds=args.timeout,
    )

    wall_duration = time.monotonic() - wall_start

    # ------------------------------------------------------------------
    # Display result
    # ------------------------------------------------------------------
    if not args.emit_json:
        display.render_result(result)

    # ------------------------------------------------------------------
    # Write JSON output (includes metrics in the serialized dict)
    # ------------------------------------------------------------------
    if args.emit_json or args.output:
        # Attach evaluation metrics to the JSON output
        metrics = compute_metrics(result)
        data = result.to_dict()
        data["_metrics"] = metrics.to_dict()
        serialized = json.dumps(data, indent=2, default=str)
        if args.output:
            path = _resolve_output_path(args.output)
            path.write_text(serialized, encoding="utf-8")
        if args.emit_json:
            print(serialized)

    # ------------------------------------------------------------------
    # Exit code
    # ------------------------------------------------------------------
    if result.status == "VERIFIED":
        return EXIT_VERIFIED
    elif result.status == "HUMAN_REVIEW_REQUIRED":
        return EXIT_HUMAN_REVIEW
    else:
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
