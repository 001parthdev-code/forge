# Security Policy

## Prototype status

Secure SWE v1.0 is a research and hackathon prototype for evidence-driven security remediation in controlled Python repositories.

The current execution layer provides bounded subprocess execution and isolated remediation workspaces. It is **not** a hardened OS-level sandbox and must not be treated as a safe environment for arbitrary hostile repositories.

## Trust model

Secure SWE treats the following as potentially untrusted:

- target repository source code;
- repository documentation and instructions;
- generated remediation plans and patches;
- generated security regression tests;
- test and process output.

Autonomous remediation is performed against disposable workspace copies. The canonical repository is not modified by `run_secure_remediation()`. A successful workflow retains a verified workspace and patch artifact; applying that candidate to canonical source is a separate authority decision.

## Current controls

The v1.0 prototype includes:

- a clean workspace copy for each remediation attempt;
- discard-on-failure semantics for rejected attempts;
- path-containment checks before controlled source mutation;
- repository-drift checks before applying a planned change;
- atomic patch writes and before/after SHA-256 evidence;
- explicit subprocess argument arrays rather than `shell=True` in the executor;
- explicit working directories and per-suite execution timeouts;
- behavioral security regression tests;
- post-patch re-analysis before verification;
- bounded remediation attempts and explicit `HUMAN_REVIEW_REQUIRED` escalation.

## Known limitations

Secure SWE v1.0 does **not** provide:

- container, VM, or kernel-enforced process isolation;
- network egress isolation;
- host filesystem or host-secret isolation from malicious executed code;
- a separate deterministic capability-enforcement service;
- generalized protection against repository prompt injection;
- comprehensive analysis of arbitrary Python security vulnerabilities;
- production-grade protection against intentionally malicious repositories.

**Attempt isolation is not security sandboxing.** Workspace copies protect remediation state and the canonical repository from failed attempts; they do not confine hostile code at the operating-system boundary.

## Supported use

Use v1.0 with the provided controlled/synthetic scenarios or repositories you trust enough to execute locally. Do not expose arbitrary repository execution as a public service.

## Reporting a vulnerability

Please report security issues privately to the project maintainer rather than opening a public issue containing exploit details. Include the affected version, reproduction steps, expected impact, and any proposed mitigation if available.
