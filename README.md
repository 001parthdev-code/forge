# Secure SWE

[![CI](https://github.com/YOUR_USERNAME/YOUR_REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/YOUR_REPO/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/YOUR_USERNAME/YOUR_REPO)](https://github.com/YOUR_USERNAME/YOUR_REPO/releases)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-316%20passing-brightgreen)](#controlled-evaluation)
[![Live Demo](https://img.shields.io/badge/demo-Hugging%20Face-yellow)](https://huggingface.co/spaces/Devparthox01/secure-swe)

> **Don't trust the patch. Verify the outcome.**

Secure SWE is an evidence-driven, bounded autonomous security-remediation agent.

Instead of stopping when a vulnerability is detected or a patch is generated, Secure SWE engineers toward a **verified security outcome**:

```text
Detect
  ↓
Plan
  ↓
Patch
  ↓
Security Regression Test
  ↓
Execute
  ↓
Verify
  │
  ├── PASS → VERIFIED
  │
  └── FAIL
       ↓
   Failure Evidence
       ↓
   Clean Workspace
       ↓
      Replan
       ↓
   Next Attempt

Unable to safely converge
       ↓
HUMAN_REVIEW_REQUIRED
```

Secure SWE v1.0 currently focuses on **command-injection remediation in controlled Python repositories**.

---

## Why Secure SWE?

Generating a patch is not the same as fixing a vulnerability.

A remediation can:

- remove an obvious vulnerable pattern while leaving the underlying issue exploitable;
- fix the security problem while breaking existing application behavior;
- pass existing tests while failing the relevant security property;
- be based on insufficient evidence;
- or address a case the autonomous system does not understand well enough to modify safely.

Secure SWE therefore treats every remediation as a **hypothesis that must earn verification**.

A patch is accepted only after the system collects evidence that:

1. the patch was successfully applied;
2. the existing application tests still pass;
3. a behavioral security regression test passes;
4. the original dangerous condition is no longer detected;
5. the required security invariant is satisfied.

Otherwise, the remediation is rejected.

---

## The Engineering Loop

Secure SWE is designed around bounded iterative engineering rather than one-shot patch generation.

```text
                         ┌──────────────────────┐
                         │                      │
                         ▼                      │
Finding → Plan → Patch → Test → Verify          │
                         │       │              │
                         │       ├── FAIL ──────┘
                         │       │
                         │       ▼
                         │   FailureFeedback
                         │       │
                         │   clean baseline
                         │       │
                         └──── Replan
                                 │
                                 ▼
                             next attempt
```

Every failed attempt produces structured evidence for the next decision.

Attempts are bounded. Secure SWE does not retry indefinitely.

If it cannot construct or verify a supported remediation, the workflow terminates with:

```text
HUMAN_REVIEW_REQUIRED
```

rather than fabricating a fix.

---

## Architecture

```text
Target Repository
       │
       ▼
┌──────────────────┐
│ Repository       │
│ Inspector        │
└────────┬─────────┘
         │
         ▼
   RepoInventory
         │
         ▼
┌──────────────────┐
│ Security         │
│ Analyzer         │
└────────┬─────────┘
         │
         ▼
  SecurityFinding
         │
         ▼
┌──────────────────┐
│ Remediation      │
│ Planner          │
└────────┬─────────┘
         │
         ▼
  RemediationPlan
         │
         ▼
┌──────────────────────────┐
│ Isolated Attempt         │
│ Workspace                │
└────────────┬─────────────┘
             │
             ▼
      Controlled Patcher
             │
             ▼
        AppliedPatch
             │
             ▼
   Security Test Generator
             │
             ├── SecurityRegressionTest
             └── DesiredOutcome
             │
             ▼
          Executor
             │
             ├── Existing Tests
             └── Security Tests
             │
             ▼
          Verifier
          /      \
     VERIFIED   REJECTED
                   │
                   ▼
            FailureFeedback
                   │
             clean workspace
                   │
                 Replan
```

The orchestrator coordinates these components without duplicating their internal responsibilities.

---

## Evidence and Traceability

Secure SWE preserves provenance throughout the remediation lifecycle.

```text
SecurityFinding
      ↓
RemediationPlan
      ↓
AppliedPatch
      ↓
SecurityRegressionTest
      ↓
AttemptResult
      ↓
VerificationResult
      ↓
RemediationWorkflowResult
```

This makes it possible to answer:

- What vulnerability caused this modification?
- What evidence supported the finding?
- What remediation strategy was selected?
- What code actually changed?
- Which tests were executed?
- Why was an attempt rejected?
- Why was the final remediation accepted?
- When did the system decide human review was required?

---

## Canonical Repository Safety

Secure SWE does **not** autonomously experiment directly against the canonical repository.

Each remediation attempt starts from a clean workspace copy:

```text
Canonical Repository
       │
       │ copy
       ▼
Attempt Workspace
       │
       ├── modify source
       ├── generate security test
       ├── execute tests
       ├── re-analyze
       └── verify
              │
          ┌───┴────┐
          │        │
        FAIL      PASS
          │        │
       discard   retain
                   │
                   ▼
           VERIFIED CANDIDATE
```

Failed attempts are discarded.

A successful workspace is retained as a **verified candidate**.

Applying that candidate to canonical source is a separate authority decision.

---

## Demo Scenarios

Secure SWE ships with three controlled synthetic scenarios.

### Scenario A — Direct Remediation

A supported command-injection vulnerability can be remediated immediately.

```text
Detect
→ Plan
→ Patch
→ Security Test PASS
→ Existing Tests PASS
→ Finding Eliminated
→ VERIFIED
```

Expected result:

```text
VERIFIED
Attempts: 1
```

### Scenario B — Failure-Driven Re-engineering

The first remediation addresses the security issue but causes an application regression.

Secure SWE rejects its own patch.

```text
Attempt 1
  Security regression   PASS
  Existing tests        FAIL
  Verification          REJECTED

        ↓

Failure evidence captured

        ↓

Attempt 2
  Revised strategy
  Security regression   PASS
  Existing tests        PASS
  Finding eliminated    PASS
  Verification          VERIFIED
```

This demonstrates the distinction between a retry loop and an engineering loop:

```text
Retry:
same decision → same failure

Secure SWE:
failure evidence → revised decision → new attempt
```

### Scenario C — Safe Escalation

The system encounters a case for which the supported deterministic planner cannot justify a safe remediation.

Expected result:

```text
HUMAN_REVIEW_REQUIRED
```

No remediation is fabricated.

---

## Controlled Evaluation

Secure SWE v1.0 was evaluated across **15 controlled synthetic runs**.

| Scenario | Runs | Expected behavior | Observed |
|---|---:|---|---:|
| Direct remediation | 5 | VERIFIED | **5/5** |
| Feedback-loop remediation | 5 | Reject → revise → VERIFIED | **5/5** |
| Unsupported remediation | 5 | HUMAN_REVIEW_REQUIRED | **5/5** |

Additional observations:

```text
Expected terminal decisions                 15/15

Bad first remediations rejected
and successfully revised                     5/5

Unsupported cases escalated safely           5/5

Unsupported cases receiving
an unjustified remediation                    0/5
```

Observed median workflow duration on the development machine:

```text
Direct remediation          ~0.70 s
Feedback-loop remediation   ~1.42 s
```

These measurements come from small controlled synthetic repositories. They demonstrate prototype reproducibility and workflow behavior; they are **not claims of production-scale security performance**.

Evaluation artifacts are retained in the repository for reproducibility.

---

## Quick Start

### Requirements

- Python 3.12
- Git

Clone the repository:

```bash
git clone https://github.com/001parthdev-code/forge.git
cd forge
```

Create a virtual environment.

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Run the test suite:

```bash
python -m pytest -q
```

---

## CLI

Show available options:

```bash
python -m secure_swe.cli --help
```

Run direct remediation:

```bash
python -m secure_swe.cli ./samples/command_injection_app
```

Run the feedback-loop scenario:

```bash
python -m secure_swe.cli ./samples/scenario_b_feedback_loop
```

Run the escalation scenario:

```bash
python -m secure_swe.cli ./samples/scenario_c_escalation
```

Generate machine-readable evidence:

```bash
python -m secure_swe.cli ./samples/command_injection_app --json
```

Write the report to disk:

```bash
python -m secure_swe.cli ./samples/command_injection_app \
  --output artifacts/run.json
```

---

## Example Result

```text
SECURE SWE
────────────────────────────────────────────

[DETECT]

Finding:  Command Injection
Severity: HIGH
File:     app/system.py

[ENGINEER]

Attempt 1

  Patch                  APPLIED
  Security Regression    PASS
  Existing Tests         PASS
  Verification           PASS

────────────────────────────────────────────
FINAL RESULT

✓ VERIFIED

Attempts: 1
```

A failed remediation is never converted into `VERIFIED` merely because a patch was generated.

---

## Trust Model

Secure SWE treats several inputs and outputs as potentially untrusted:

- target repository contents;
- generated remediations;
- generated regression tests;
- repository documentation;
- execution output.

The model/agent is therefore allowed to propose changes, but its output must pass deterministic checks before being accepted as a verified candidate.

### Current protections

- clean workspace per remediation attempt;
- canonical repository preserved during autonomous experimentation;
- path-containment checks around controlled mutation;
- repository-drift detection;
- no `shell=True` in the test executor;
- bounded test execution;
- bounded remediation attempts;
- behavioral security regression tests;
- independent post-patch security analysis;
- explicit human escalation.

### Important limitation

**Attempt isolation is not the same as security sandboxing.**

The current executor is bounded, but Secure SWE v1.0 does not provide a hardened OS-level execution boundary for arbitrary hostile repositories.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for details.

---

## Current Scope

Secure SWE v1.0 deliberately prioritizes depth over breadth.

Currently supported:

```text
Language:             Python
Vulnerability family: Command injection
Repository type:      Controlled/synthetic
Analysis:             Deterministic AST-based
Remediation:          Deterministic supported strategies
Execution:            Controlled local subprocess execution
```

The current version should be treated as an engineering/research prototype.

---

## IBM Bob 2.0

Secure SWE v1.0 was developed during the IBM Bob 2.0 Hackathon.

IBM Bob IDE was used extensively through task-oriented development to implement and integrate major components including:

- repository inspection;
- structured evidence models;
- security analysis;
- remediation planning;
- controlled patching;
- security regression-test generation;
- execution and verification;
- bounded remediation orchestration;
- CLI/reporting and productization work.

The project was decomposed into bounded engineering tasks with explicit contracts, invariants, acceptance criteria, and tests rather than using Bob solely as an autocomplete system.

Required IBM Bob task-session evidence is preserved under:

```text
bob_sessions/
```

The Secure SWE concept predates the hackathon; IBM Bob substantially accelerated implementation and integration of this version.

---

## Repository Structure

```text
forge/
├── secure_swe/           # Secure SWE engine
├── samples/              # Controlled demo repositories
├── tests/                # Automated test suite
├── evaluation/           # Controlled evaluation artifacts
├── bob_sessions/         # IBM Bob task-session evidence
├── docs/                 # Architecture / threat-model documentation
├── .github/workflows/    # CI
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── LICENSE
├── pyproject.toml
└── requirements.txt
```

---

## Security

Secure SWE is a security-oriented prototype, but the current version is **not a hardened sandbox for executing arbitrary hostile repositories**.

Please review [`SECURITY.md`](SECURITY.md) before using Secure SWE outside the provided controlled scenarios.

Security vulnerabilities should be reported privately rather than disclosed through a public issue containing exploit details.

---

## Roadmap

Potential directions beyond v1 include:

- deterministic capability enforcement;
- hardened runtime isolation;
- network and host-secret isolation;
- adversarial repository evaluation;
- repository prompt-injection defenses;
- interprocedural data-flow analysis;
- LLM-assisted investigation and failure-driven replanning;
- additional vulnerability families;
- Git branch / pull-request workflows;
- CI security-remediation integration;
- real-world repository benchmarks;
- verifier-adversarial testing.

The long-term research question is broader than vulnerability detection:

> **How much authority can an autonomous software-engineering agent receive while maintaining deterministic control over what it may modify, execute, trust, and declare successful?**

---

## License

Licensed under the **Apache License 2.0**.

See [`LICENSE`](LICENSE) for details.