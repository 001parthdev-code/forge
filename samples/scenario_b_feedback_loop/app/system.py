"""Synthetic feedback-loop demo for Secure SWE."""
import subprocess


def resolve_hostname(target: str) -> None:
    # Vulnerable: dynamic input is interpreted by a shell.  check=True is part
    # of the application's observable contract and must survive remediation.
    command = f"nslookup {target}"
    subprocess.run(command, shell=True, check=True)
