# Scenario B — Feedback Loop

Synthetic command-injection case designed to demonstrate real failure-driven replanning.
The vulnerable call uses `shell=True` and also relies on `check=True` as existing behavior.
Attempt 1 removes shell interpretation but drops `check=True`, so existing tests reject it.
Attempt 2 uses that failure evidence to preserve safe subprocess kwargs while keeping the shell removed.
