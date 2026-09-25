"""
HTTP route handlers for the network-utility application.

This module is part of the controlled command-injection sample.
It intentionally contains a vulnerable pattern for security testing.
Do NOT deploy this code; it is for analysis only.
"""

from __future__ import annotations

import subprocess


def handle_traceroute(request_params: dict) -> str:
    """
    Handle a traceroute request from user-supplied parameters.

    VULNERABLE: the destination is taken from an untrusted dict and
    interpolated into a shell command via subprocess.Popen with shell=True.
    Example exploit: request_params["destination"] = "8.8.8.8 && id"
    """
    destination = request_params.get("destination", "")
    proc = subprocess.Popen(f"traceroute {destination}", shell=True)
    proc.wait()
    return f"Traceroute to {destination} complete."


def handle_static_check() -> str:
    """
    Run a fixed internal diagnostic.

    NOT VULNERABLE: the command is a compile-time constant; no dynamic input.
    """
    result = subprocess.run("uptime", shell=True, capture_output=True, text=True)
    return result.stdout
