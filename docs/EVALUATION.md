# Secure SWE v1.0 Evaluation

## Purpose

The v1.0 evaluation checks whether the prototype behaves reproducibly across three deliberately different remediation outcomes. It is a controlled functional evaluation, not a production security benchmark.

## Environment and scope

- controlled synthetic Python repositories;
- command-injection remediation only;
- five runs per scenario;
- 15 total workflow runs;
- measurements collected from the local development environment;
- terminal status, attempt behavior, verification behavior, and workflow duration recorded from structured workflow results.

## Scenarios

### Scenario A — Direct remediation

A supported command-injection finding has a remediation that should succeed on the first attempt.

Expected:

```text
Finding -> Plan -> Patch -> Tests PASS -> Verification PASS -> VERIFIED
```

### Scenario B — Failure-driven re-engineering

The first supported remediation is intentionally insufficient for the application's behavioral requirements. Secure SWE should reject it, convert failure into structured feedback, start again from the clean baseline, choose a genuinely different supported strategy, and verify the second attempt.

Expected:

```text
Attempt 1 -> REJECTED
           -> FailureFeedback
Attempt 2 -> revised strategy -> VERIFIED
```

Observed strategy transition in the controlled fixture:

```text
replace_shell_string_with_arg_list
        -> rejected
replace_shell_string_preserve_safe_kwargs
        -> verified
```

### Scenario C — Safe escalation

The finding cannot be safely remediated by the deterministic strategies supported by v1.0.

Expected:

```text
No justified supported remediation -> HUMAN_REVIEW_REQUIRED
```

The system should not fabricate a patch merely to continue autonomously.

## Results

| Scenario | Runs | Expected behavior | Observed |
|---|---:|---|---:|
| A — Direct remediation | 5 | `VERIFIED` | **5/5** |
| B — Feedback-loop remediation | 5 | Reject → revise → `VERIFIED` | **5/5** |
| C — Unsupported remediation | 5 | `HUMAN_REVIEW_REQUIRED` | **5/5** |

Summary:

```text
Expected terminal decisions                         15/15
Direct remediations verified                         5/5
Bad first remediations rejected and revised          5/5
Unsupported cases escalated safely                    5/5
Unsupported cases receiving an unjustified patch      0/5
```

## Runtime observations

On the development machine used for the controlled evaluation:

| Scenario | Mean | Median | Observed range |
|---|---:|---:|---:|
| A — Direct remediation | ~0.750 s | ~0.703 s | ~0.687–0.953 s |
| B — Feedback loop | ~1.459 s | ~1.422 s | ~1.406–1.625 s |

Scenario C terminates during planning/support evaluation and completes too quickly for its current coarse timing presentation to be a useful performance measurement; its runtime is therefore not used as a performance claim.

## Interpretation

The strongest result is not raw speed. The controlled runs demonstrate three decision properties of the prototype:

1. supported direct remediations can reach a verified outcome;
2. a security-oriented patch that causes a regression is not accepted merely because it changed the vulnerable code;
3. unsupported cases can terminate safely without an unjustified autonomous modification.

Scenario B also demonstrates that the bounded loop is not simply retrying the same transformation: the second attempt uses failure evidence to select a different supported remediation strategy.

## Limitations

These results must not be generalized beyond the evaluation scope.

The evaluation does **not** establish:

- production vulnerability-detection precision or recall;
- effectiveness across arbitrary real-world repositories;
- performance across multiple languages or vulnerability families;
- security against malicious repositories;
- superiority to human engineers or other remediation tools;
- production-scale latency or throughput.

Future evaluation should include larger licensed vulnerable-code corpora, real repositories, precision/recall measurement, remediation success and regression rates, adversarial repositories, and independent verifier-focused testing.
