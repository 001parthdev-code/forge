"""Synthetic escalation demo for Secure SWE."""
import subprocess


def run_tool(target: str) -> None:
    # Vulnerable, but the command prefix is itself computed dynamically.  The
    # v0 deterministic planner intentionally cannot reconstruct a safe argv.
    prefix = choose_program()
    command = prefix + " " + target
    subprocess.run(command, shell=True)


def choose_program() -> str:
    return "echo"
