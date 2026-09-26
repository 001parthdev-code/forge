from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from secure_swe.orchestrator import run_secure_remediation

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent.parent
STATIC_DIR = PACKAGE_DIR / "static"

SCENARIOS = {
    "a": {
        "name": "Direct Remediation",
        "subtitle": "Detect → Patch → Verify",
        "description": "A supported command-injection flaw is remediated and independently verified in one attempt.",
        "path": PROJECT_ROOT / "samples" / "command_injection_app",
        "expected": "VERIFIED",
    },
    "b": {
        "name": "Engineering Feedback Loop",
        "subtitle": "Reject → Learn → Re-engineer → Verify",
        "description": "The first security fix causes a regression. Secure SWE rejects it, uses failure evidence, and produces a revised verified remediation.",
        "path": PROJECT_ROOT / "samples" / "scenario_b_feedback_loop",
        "expected": "VERIFIED",
    },
    "c": {
        "name": "Safe Escalation",
        "subtitle": "Know when not to patch",
        "description": "The deterministic planner cannot justify a safe transformation, so Secure SWE escalates instead of fabricating a fix.",
        "path": PROJECT_ROOT / "samples" / "scenario_c_escalation",
        "expected": "HUMAN_REVIEW_REQUIRED",
    },
}

app = FastAPI(title="Secure SWE Demo", version="0.1.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/scenarios")
def scenarios() -> dict[str, Any]:
    return {
        key: {k: v for k, v in value.items() if k != "path"}
        for key, value in SCENARIOS.items()
    }


@app.post("/api/run/{scenario_id}")
def run_scenario(scenario_id: str) -> dict[str, Any]:
    scenario = SCENARIOS.get(scenario_id.lower())
    if scenario is None:
        raise HTTPException(status_code=404, detail="Unknown demo scenario")

    repo = scenario["path"]
    if not repo.exists():
        raise HTTPException(status_code=500, detail=f"Demo fixture is missing: {repo.name}")

    result = run_secure_remediation(str(repo), max_attempts=3, timeout_seconds=30)
    payload = result.to_dict()
    payload["scenario"] = {
        "id": scenario_id.lower(),
        "name": scenario["name"],
        "subtitle": scenario["subtitle"],
        "expected": scenario["expected"],
    }
    return payload


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
