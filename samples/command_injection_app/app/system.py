"""
Low-level system helpers for the network-utility application.

This module is part of the controlled command-injection sample.
It intentionally contains vulnerable patterns for security testing.
Do NOT deploy this code; it is for analysis only.
"""

from __future__ import annotations

import os
import subprocess


def ping_host(host: str) -> int:
    """
    Ping *host* and return the exit code.

    VULNERABLE: ``host`` is concatenated directly into a shell command.
    An attacker-controlled ``host`` value can inject arbitrary shell commands.
    Example exploit: host = "8.8.8.8; rm -rf /"
    """
    return os.system("ping -c 1 " + host)


def resolve_hostname(target: str) -> None:
    """
    Perform a DNS lookup for *target*.

    VULNERABLE: *target* is interpolated into an f-string passed to
    subprocess.run with shell=True.
    Example exploit: target = "example.com; cat /etc/passwd"
    """
    command = f"nslookup {target}"
    subprocess.run(command, shell=True)


def safe_ping(host: str) -> None:
    """
    Ping *host* safely using an argument list (no shell expansion).

    NOT VULNERABLE: the command is passed as a list; shell=True is absent.
    The host value is passed as a discrete argument and cannot escape into
    the shell command string.
    """
    subprocess.run(["ping", "-c", "1", host])
