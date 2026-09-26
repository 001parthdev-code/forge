# Contributing to Secure SWE

Secure SWE is an experimental security-engineering project. Contributions should preserve its central rule: **a generated patch is not a verified remediation**.

## Development environment

Python 3.12 is the reference development environment.

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install dependencies and run the suite:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m pip install pytest
python -m pytest -q
```

## Pull requests

Changes should:

- preserve finding → plan → patch → test → verification traceability;
- add tests for behavioral changes and failure paths;
- never weaken verification merely to make a remediation pass;
- preserve clean-baseline semantics between attempts;
- preserve explicit human escalation for unsupported cases;
- avoid unrelated refactors in security-sensitive changes;
- update architecture or threat-model documentation when trust boundaries change;
- keep credentials, local virtual environments, caches, generated archives, and secrets out of version control.

## Security-sensitive changes

Changes affecting execution, filesystem access, canonical repository mutation, verification, agent capabilities, or external integrations require corresponding threat-model review.

Do not describe workspace isolation as an OS sandbox unless a real OS-enforced isolation boundary is introduced and tested.
