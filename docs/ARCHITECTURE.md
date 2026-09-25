# Secure SWE Agent Architecture

## Objective

Secure SWE Agent improves the developer security-remediation workflow by
taking a security issue through investigation, remediation, regression
testing, and independent verification.

Initial scope:

- Python repositories
- Command injection
- Controlled synthetic target repository

## Pipeline

Target Repository
    |
    v
Inspector
    |
    | RepoInventory
    v
Analyzer
    |
    | SecurityFinding
    v
Remediator
    |
    | RemediationPlan
    v
Patcher
    |
    | AppliedPatch
    v
Test Generator
    |
    | SecurityRegressionTest
    v
Executor
    |
    | TestResult
    v
Verifier
    |
    | VerificationResult
    v
Evidence Report

## Components

### Inspector

Produces a deterministic, read-only snapshot of the target repository.

### Analyzer

Examines repository evidence for the currently supported vulnerability
class.

### Remediator

Produces a remediation plan grounded in the identified finding.

### Patcher

Applies explicitly approved modifications to the controlled repository.

### Test Generator

Creates a regression test that reproduces the security property being
protected.

### Executor

Runs the relevant test suite and captures execution evidence.

### Verifier

Determines whether the vulnerability has actually been remediated using
test and repository evidence.

### Orchestrator

Coordinates workflow stages.

The orchestrator must not contain the implementation logic belonging to
individual stages.

## Core Design Principle

Every important conclusion should be backed by inspectable evidence.

The system must distinguish between:

- vulnerability detected
- remediation proposed
- patch applied
- tests executed
- tests passed
- security regression passed
- remediation verified

A generated patch is not equivalent to a verified remediation.

## Hackathon Scope

The first vertical slice intentionally supports one vulnerability class
and one language.

Generality comes after the complete workflow works reliably.
