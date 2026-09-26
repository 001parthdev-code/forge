# Secure SWE Architecture

## Objective

Secure SWE is a bounded, evidence-driven security-remediation agent. Its objective is not to generate a plausible patch; it is to produce a **verified remediation candidate** or stop with `HUMAN_REVIEW_REQUIRED`.

The v1.0 scope is intentionally narrow:

- Python repositories;
- command-injection findings;
- deterministic AST-based analysis and supported remediation strategies;
- controlled/synthetic repositories.

## System flow

```text
Target Repository
      |
      v
Repository Inspector
      | RepoInventory
      v
Security Analyzer
      | SecurityFinding
      v
Remediation Planner
      | RemediationPlan
      v
Clean Attempt Workspace
      |
      v
Controlled Patcher
      | AppliedPatch
      v
Security Test Generator
      | SecurityRegressionTest + DesiredOutcome
      v
Executor
      | TestSuiteResult
      v
Verifier
      | VerificationResult
   +--+--+
   |     |
 PASS   FAIL
   |     |
   v     v
VERIFIED FailureFeedback
          |
          v
     discard workspace
          |
          v
        Replan
          |
          v
      next attempt

attempt budget exhausted / unsupported
          |
          v
HUMAN_REVIEW_REQUIRED
```

## Component contracts

### Inspector

`Repository path -> RepoInventory`

Produces a deterministic, read-only snapshot of repository files, content metadata, hashes, and inspection errors. Git internals are excluded.

### Analyzer

`RepoInventory -> list[SecurityFinding]`

Analyzes readable Python source using deterministic AST logic. v1.0 focuses on supported command-injection patterns and records evidence rather than making unsupported exploitability claims.

### Remediation planner

`SecurityFinding + RepoInventory (+ FailureFeedback) -> RemediationPlan`

Chooses a supported deterministic remediation strategy and records the security invariant and validation requirements. Feedback-aware planning must produce a meaningful alternative or stop; it must not disguise identical retries as engineering progress.

### Patcher

`Repository workspace + RemediationPlan -> AppliedPatch`

Applies only the authorized transformation after path containment, target existence, plan support, and drift checks. It records before/after SHA-256 hashes and uses an atomic write strategy.

### Security test generator

`Finding + Plan + Patch + Inventory -> SecurityRegressionTest + DesiredOutcome`

Creates a behavioral regression test for the security property and an explicit outcome specification. For command injection, shell-like sentinel input should remain data rather than becoming shell syntax.

### Executor

`Workspace + test paths -> TestSuiteResult`

Runs existing and security tests with explicit argument arrays, a controlled working directory, captured output, and timeouts. The executor is controlled but is **not** an OS sandbox.

### Verifier

`Finding + Plan + Patch + DesiredOutcome + TestSuiteResult + Workspace -> VerificationResult`

Returns `verified=True` only when the required evidence agrees: the patch was applied, existing tests pass, the security regression passes, re-analysis eliminates the original finding, and the security invariant is satisfied.

### Orchestrator

Coordinates the bounded engineering loop. It does not duplicate component business logic. Each attempt begins from a clean copy of the canonical baseline. Failed workspaces are discarded; a verified workspace is retained for inspection.

## Evidence model

```text
SecurityFinding
      |
      v
RemediationPlan
      |
      v
AppliedPatch
      |
      v
SecurityRegressionTest
      |
      v
AttemptResult
      |
      v
VerificationResult
      |
      v
RemediationWorkflowResult
```

This provenance allows a reviewer to determine what was found, why a change was authorized, what changed, what was executed, why an attempt was rejected, and why a final candidate was accepted.

## Core invariants

1. **Patch generation is not success.**
2. **Verification requires security and regression evidence.**
3. **Canonical source is not the experimentation surface.** Autonomous attempts occur in workspace copies.
4. **Failed attempts do not contaminate later attempts.** Each attempt starts from the same baseline.
5. **Retries are bounded.** The default maximum is 3; the public API clamps the configured value to 1-5.
6. **Failure must become evidence.** Replanning consumes structured `FailureFeedback`.
7. **Unsupported cases escalate.** The system may stop before exhausting the attempt budget when no supported alternative exists.
8. **Traceability is preserved.** Findings, plans, patches, tests, attempts, and verification results remain linked.
9. **Canonical mutation is a separate authority decision.** A verified candidate is retained; it is not automatically applied to the caller's repository.

## Canonical repository safety

```text
Canonical Repository
       |
       | copy
       v
Attempt Workspace
       |
       +-- patch
       +-- generate test
       +-- execute
       +-- re-analyze
       +-- verify
              |
          +---+---+
          |       |
        FAIL     PASS
          |       |
       discard  retain
                  |
                  v
          VERIFIED CANDIDATE
```

This provides state isolation for autonomous engineering. It does not provide hostile-code containment; see `THREAT_MODEL.md`.
