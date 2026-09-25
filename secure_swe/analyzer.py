"""
Module 2 — Security Analyzer

Analyzes a RepoInventory and produces structured, evidence-backed
SecurityFinding records for Python command-injection vulnerabilities.

Detection strategy
------------------
Uses Python's built-in ``ast`` module to parse each Python source file from
the inventory and look for calls to dangerous execution sinks:

    * os.system(expr)
    * subprocess.run(expr,   shell=True)
    * subprocess.call(expr,  shell=True)
    * subprocess.Popen(expr, shell=True)

A finding is only emitted when the *first argument* to the sink is a
**dynamically constructed** expression — i.e., not a bare string literal or
bytes literal.  Patterns treated as dynamic:

    - Name / Attribute references (variables)
    - f-strings (JoinedStr)
    - Binary concatenation (+) involving at least one non-constant operand
    - Any other non-Constant node (call result, subscript, …)

This is an *intra-file*, *intra-function* analysis only.  It does not perform
interprocedural taint tracking.  A function parameter that is never called
with external input will still be flagged as "potentially untrusted" because
the analyzer cannot prove provenance beyond the file boundary.

Known limitations
-----------------
* No interprocedural / cross-file taint analysis.
* Parameters treated as potentially untrusted by convention; the analyzer
  cannot distinguish internal-only helpers from externally-facing entrypoints.
* Aliases (``import subprocess as sp``) are not resolved.
* Dynamic attribute access on ``os`` / ``subprocess`` is not tracked.
* The analyzer operates on inventory content only — it never touches the
  filesystem directly.
"""

from __future__ import annotations

import ast
import hashlib
import logging
from typing import List, Optional

from secure_swe.models import RepoInventory, SecurityFinding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sink registry
# ---------------------------------------------------------------------------

# Each entry is (module_attr_chain, requires_shell_true).
# module_attr_chain examples: ("os", "system"), ("subprocess", "run")
_SINKS: list[tuple[tuple[str, ...], bool]] = [
    (("os", "system"),         False),
    (("subprocess", "run"),    True),
    (("subprocess", "call"),   True),
    (("subprocess", "Popen"),  True),
]


def _sink_label(chain: tuple[str, ...]) -> str:
    return ".".join(chain)


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _attr_chain(node: ast.expr) -> Optional[tuple[str, ...]]:
    """
    Return the dotted attribute chain for a Name or Attribute node, or None.

    Examples:
        Name("os")              → ("os",)
        Attribute(Name("os"), "system") → ("os", "system")
    """
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, ast.Attribute):
        parent = _attr_chain(node.value)
        if parent is not None:
            return parent + (node.attr,)
    return None


def _is_dynamic(node: ast.expr) -> bool:
    """
    Return True when *node* is not a compile-time constant.

    Conservative: f-strings, variable references, concatenations that include
    at least one non-constant operand, and any other non-Constant node are
    all considered dynamic.
    """
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, ast.JoinedStr):
        # f-string — always dynamic when it contains any interpolation
        return bool(node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_dynamic(node.left) or _is_dynamic(node.right)
    # Name, Attribute, Call, Subscript, etc. — all treated as dynamic
    return True


def _unparse_safe(node: ast.expr) -> str:
    """Return a compact source representation of *node*, never raising."""
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover
        return repr(node)


def _has_shell_true(call: ast.Call) -> bool:
    """
    Return True when the call contains ``shell=True`` as a keyword argument.
    """
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
            if kw.value.value is True:
                return True
    return False


# ---------------------------------------------------------------------------
# Finding ID
# ---------------------------------------------------------------------------

def _finding_id(
    vulnerability_type: str,
    file: str,
    line: int,
    sink: str,
) -> str:
    """
    Return a deterministic 16-character hex prefix of SHA-256.

    Using the full 64-char digest is verbose; 16 hex chars (64 bits) provides
    ample collision resistance for a single repository's findings list.
    """
    raw = f"{vulnerability_type}|{file}|{line}|{sink}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Per-file analysis
# ---------------------------------------------------------------------------

def _analyze_source(
    relative_path: str,
    source: str,
) -> list[SecurityFinding]:
    """
    Parse *source* and return all command-injection findings.

    Returns an empty list when the file cannot be parsed; never raises.
    """
    try:
        tree = ast.parse(source, filename=relative_path)
    except SyntaxError as exc:
        logger.warning("Skipping %s — parse error: %s", relative_path, exc)
        return []

    findings: list[SecurityFinding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        chain = _attr_chain(node.func)
        if chain is None:
            continue

        for (sink_chain, needs_shell), in (
            ((s, ns),) for s, ns in _SINKS  # unpack one at a time
        ):
            # The call chain must end with the sink chain.
            # e.g. chain ("os", "system") matches sink_chain ("os", "system")
            # e.g. chain ("subprocess", "run") matches ("subprocess", "run")
            if len(chain) < len(sink_chain):
                continue
            if chain[-len(sink_chain):] != sink_chain:
                continue

            # For subprocess sinks, shell=True is required.
            if needs_shell and not _has_shell_true(node):
                break  # correct sink, but shell=False/absent — not flagged

            # Must have at least one positional argument.
            if not node.args:
                break

            cmd_arg = node.args[0]

            if not _is_dynamic(cmd_arg):
                break  # static command — not flagged

            sink_label = _sink_label(sink_chain)
            evidence_expr = _unparse_safe(cmd_arg)
            line = node.lineno

            reason = (
                f"The first argument to `{sink_label}` is a dynamically "
                f"constructed expression (`{evidence_expr}`).  "
                f"If any contributing variable carries externally-supplied "
                f"input, an attacker may inject arbitrary shell commands.  "
                f"Note: this analyzer does not perform cross-file taint "
                f"analysis; the input provenance cannot be confirmed."
            )

            findings.append(
                SecurityFinding(
                    id=_finding_id("command_injection", relative_path, line, sink_label),
                    vulnerability_type="command_injection",
                    severity="HIGH",
                    file=relative_path,
                    line=line,
                    sink=sink_label,
                    evidence=evidence_expr,
                    reason=reason,
                    confidence="MEDIUM",
                )
            )
            break  # a call can only match one sink entry

    return findings


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def analyze_inventory(inventory: RepoInventory) -> list[SecurityFinding]:
    """
    Analyze *inventory* for Python command-injection vulnerabilities.

    Only Python files (extension ``.py``) whose content is available are
    analyzed.  Binary files, oversized files, and files that failed during
    inspection are silently skipped.  A file that cannot be parsed does not
    abort analysis of the remaining files.

    Returns a stable, deterministic list of SecurityFinding records sorted
    by (file, line).

    Filesystem boundary
    -------------------
    This function reads only from *inventory*.  It never touches the
    filesystem.  All file enumeration and content loading is the
    responsibility of ``inspect_repository()`` (Module 1).
    """
    all_findings: list[SecurityFinding] = []

    for entry in inventory.files:
        if entry.extension != ".py":
            continue
        if not entry.is_text:
            continue
        if entry.content is None:
            continue

        file_findings = _analyze_source(entry.relative_path, entry.content)
        all_findings.extend(file_findings)

    # Deterministic order: primary sort by file path, secondary by line number.
    all_findings.sort(key=lambda f: (f.file, f.line))
    return all_findings
