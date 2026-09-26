# Secure SWE Threat Model

## Scope

This threat model describes Secure SWE v1.0, a prototype that performs bounded security-remediation attempts against controlled Python repositories.

The model distinguishes **remediation-state isolation** from **execution security isolation**. v1.0 provides the former, not the latter.

## Security objectives

Secure SWE aims to:

1. prevent failed autonomous remediation attempts from corrupting the canonical repository;
2. prevent path-based patch operations from escaping the intended workspace;
3. reject stale remediation plans when source has drifted;
4. avoid shell-mediated test execution in the executor;
5. bound execution time and remediation attempts;
6. require independent evidence before declaring a remediation verified;
7. preserve an auditable finding → plan → patch → test → verification chain;
8. stop and request human review when the supported planner cannot justify a safe next action.

## Assets

Assets of interest include:

- canonical repository source and history;
- correctness of application behavior;
- security properties being remediated;
- integrity of verification evidence;
- host filesystem, credentials, and environment;
- availability of the execution environment.

## Trust assumptions

### Controlled / trusted enough for v1.0

- the Secure SWE deterministic implementation and its configured policies;
- the Python runtime and host OS;
- the controlled synthetic repositories used for the public demo and evaluation;
- the test framework itself.

### Potentially untrusted

- target repository contents;
- repository documentation and embedded instructions;
- remediation output;
- generated tests;
- subprocess/test output;
- future model/LLM output.

## Threats and current mitigations

### Failed or incorrect generated patch

**Threat:** a remediation removes the visible pattern but leaves the vulnerability, or introduces a regression.

**Mitigations:** behavioral security regression testing, existing test-suite execution, post-patch re-analysis, explicit security-invariant verification, rejection of failed attempts.

### Repository drift / stale plan

**Threat:** source changes after analysis and before patching.

**Mitigation:** the patcher verifies that the expected original source still exists before mutation and fails closed on drift.

### Path traversal during patching

**Threat:** a plan attempts to modify a path outside the repository/workspace.

**Mitigation:** paths are resolved and required to remain relative to the resolved workspace root before mutation.

### Partial write / corrupted target

**Threat:** a failed write leaves a source file partially modified.

**Mitigation:** controlled patching uses an atomic write/rename strategy and records before/after hashes.

### Runaway tests

**Threat:** tests never terminate.

**Mitigation:** configurable per-suite timeouts and structured timeout evidence.

### Shell-mediated execution

**Threat:** executor commands are interpreted by a shell.

**Mitigation:** executor commands are explicit argument arrays and do not use `shell=True`.

### Infinite autonomous remediation

**Threat:** the agent loops indefinitely or repeatedly applies the same failed idea.

**Mitigations:** hard attempt ceiling, structured failure feedback, feedback-aware replanning, early human escalation when no supported alternative exists.

### Canonical repository corruption

**Threat:** autonomous experimentation directly changes the developer's source of truth.

**Mitigation:** every attempt operates on a clean workspace copy. Failed workspaces are discarded; verified workspaces are retained as candidates. The orchestrator does not automatically apply the candidate back to canonical source.

### Malicious repository code or tests

**Threat:** executed repository code reads host files/secrets, writes outside the workspace, uses the network, spawns additional processes, or otherwise abuses host authority.

**Current status:** **not contained by v1.0**. The executor has a controlled working directory and timeout, but it is not an OS security boundary.

### Repository prompt injection

**Threat:** repository text attempts to manipulate a future LLM/agent into bypassing policy or verification.

**Current status:** v1.0's core analysis/remediation path is deterministic, but generalized prompt-injection defenses are not implemented for future model-driven capabilities.

### Verifier manipulation / correlated failure

**Threat:** planner, generated tests, and verifier share the same incorrect assumption and collectively accept a bad remediation.

**Mitigations:** separation of planning, execution evidence, and post-patch analysis reduces direct self-approval, but v1.0 does not eliminate correlated logic errors. Adversarial verifier testing is future work.

## Explicit non-goals in v1.0

v1.0 does not claim:

- safe execution of arbitrary hostile repositories;
- container/VM/kernel-level isolation;
- network isolation;
- host-secret isolation;
- a separate capability-enforcement service;
- comprehensive Python vulnerability detection;
- production-grade autonomous code modification.

## Future enforcement boundary

A hardened design should move dangerous capabilities behind a deterministic enforcement layer and an OS-enforced isolated runtime:

```text
Agent / reasoning plane
       |
       | capability request
       v
Deterministic Enforcer
       |
       | approved operation
       v
Isolated Runtime
       |
       v
Execution Evidence
       |
       v
Verifier
```

Potential controls include workspace-scoped filesystem capabilities, command allowlists, sanitized environments, network policy, process/resource limits, audit logging, and container/VM or equivalent OS isolation.

## Central security principle

> The model is allowed to be wrong. Being wrong must not automatically make its output accepted state.
