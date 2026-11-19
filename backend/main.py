"""
FastAPI application for RedLoop.

Exposes REST APIs for:
- Scenario inspection
- Live interactive playground attacks
- Batch baseline evaluations
- Evaluation run progress and aggregated metrics
- Health check and static file serving for presentation UI
"""

import asyncio
import logging
import uuid
from pathlib import Path
from typing import Any, Optional
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend import db
from backend.baseline import evaluate_baseline
from backend.config import PROJECT_ROOT, settings
from backend.defender import run_defender
from backend.judge import judge
from backend.scenarios import (
    SCENARIOS,
    get_all_scenarios,
    get_scenario,
    get_scenario_families,
)
from backend.attacker.strategy_memory import strategy_memory
from backend.eval_auto import (
    run_auto_campaign,
    compute_comparison_metrics,
    export_campaign_data,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("redloop.api")

FRONTEND_DIR = PROJECT_ROOT / "frontend"


# ---------------------------------------------------------------------
# Pydantic Request & Response Schemas
# ---------------------------------------------------------------------

class AttackRequest(BaseModel):
    scenario_id: str
    model: Optional[str] = None
    defense: str = "none"
    attack_text: str
    enable_llm_judge: bool = False


class BaselineRunRequest(BaseModel):
    models: Optional[list[str]] = None
    defense: str = "none"
    scenario_ids: Optional[list[str]] = None
    max_templates_per_category: Optional[int] = None


class AutoCampaignRequest(BaseModel):
    models: Optional[list[str]] = None
    defense: str = "none"
    scenario_ids: Optional[list[str]] = None
    budget_per_scenario: int = 8
    mode: str = "first_success"  # "first_success" or "exhaustive"



# ---------------------------------------------------------------------
# Lifespan & Initialization
# ---------------------------------------------------------------------

# Ensure database tables exist at module load time
db.init_db()
db.save_scenario_metadata([s.to_dict() for s in get_all_scenarios()])


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database and sync scenario records
    db.init_db()
    scenarios_dicts = [s.to_dict() for s in get_all_scenarios()]
    db.save_scenario_metadata(scenarios_dicts)
    logger.info(f"RedLoop initialized with {len(scenarios_dicts)} scenarios. Mock mode: {settings.is_mock}")
    yield


app = FastAPI(
    title="RedLoop API",
    description="Automated Red-Teaming & Prompt Injection Testbed",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------

@app.get("/api/health")
async def health_check():
    return {
        "status": "ok",
        "mock_mode": settings.is_mock,
        "groq_configured": bool(settings.groq_api_key.strip()),
        "models": {
            "weak_defender": settings.weak_defender_model,
            "strong_defender": settings.strong_defender_model,
            "judge_model": settings.judge_model,
        },
        "available_models": settings.available_models,
        "rate_limit_rpm": settings.rate_limit_rpm,
    }


@app.get("/api/scenarios")
async def list_scenarios():
    scenarios = get_all_scenarios()
    return {
        "total": len(scenarios),
        "families": get_scenario_families(),
        "scenarios": [s.to_dict() for s in scenarios],
    }


@app.get("/api/scenarios/{scenario_id}")
async def get_single_scenario(scenario_id: str):
    scenario = get_scenario(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")
    data = scenario.to_dict()
    data["benign_document_preview"] = scenario.render_untrusted_document(scenario.benign_injection_text)
    return data


@app.post("/api/attack")
async def run_single_attack(req: AttackRequest):
    scenario = get_scenario(req.scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario '{req.scenario_id}' not found.")

    chosen_model = req.model or settings.weak_defender_model

    # Run Defender
    try:
        defender_res = await run_defender(
            scenario=scenario,
            injection_text=req.attack_text,
            model=chosen_model,
            defense_config=req.defense,
            bypass_cache=False,
        )
    except Exception as e:
        logger.error(f"Defender execution failed: {e}")
        raise HTTPException(status_code=500, detail=f"Defender execution error: {str(e)}")

    # Run Judge
    try:
        judge_res = await judge(
            scenario=scenario,
            run_result=defender_res,
            injection_text=req.attack_text,
            enable_llm_judge=req.enable_llm_judge,
        )
    except Exception as e:
        logger.error(f"Judge evaluation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Judge evaluation error: {str(e)}")

    attempt_id = f"manual_{uuid.uuid4().hex[:12]}"
    db.record_attack_attempt(
        attempt_id=attempt_id,
        run_id=None,
        scenario_id=scenario.id,
        model=chosen_model,
        defense=req.defense,
        attack_text=req.attack_text,
        attack_category="manual_playground",
        attack_source="manual",
        response=defender_res["response"],
        tool_calls=defender_res["tool_calls"],
        success=judge_res["success"],
        reason=judge_res["reason"],
        latency_ms=defender_res["latency_ms"],
        cached=defender_res["cached"],
    )

    return {
        "attempt_id": attempt_id,
        "scenario_id": scenario.id,
        "model": chosen_model,
        "defense": req.defense,
        "response": defender_res["response"],
        "tool_calls": defender_res["tool_calls"],
        "latency_ms": defender_res["latency_ms"],
        "cached": defender_res["cached"],
        "success": judge_res["success"],
        "reason": judge_res["reason"],
        "method": judge_res["method"],
        "llm_judge": judge_res.get("llm_judge"),
        "effective_system_prompt": defender_res.get("effective_system_prompt"),
        "effective_user_prompt": defender_res.get("effective_user_prompt"),
    }


@app.post("/api/baseline/run")
async def start_baseline_run(req: BaselineRunRequest, background_tasks: BackgroundTasks):
    run_id = f"run_{uuid.uuid4().hex[:10]}"
    models = req.models or [settings.weak_defender_model]

    # Validate models
    for m in models:
        if m not in settings.available_models and m != settings.weak_defender_model and m != settings.strong_defender_model:
            logger.info(f"Custom model requested: {m}")

    background_tasks.add_task(
        evaluate_baseline,
        models=models,
        defense=req.defense,
        scenario_ids=req.scenario_ids,
        run_id=run_id,
        max_templates_per_category=req.max_templates_per_category,
    )

    return {
        "run_id": run_id,
        "status": "started",
        "models": models,
        "defense": req.defense,
        "message": "Baseline evaluation launched in background.",
    }


@app.get("/api/runs/{run_id}")
async def get_run_status(run_id: str):
    run_data = db.get_run(run_id)
    if not run_data:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")
    return {
        "id": run_data["id"],
        "type": run_data["type"],
        "status": run_data["status"],
        "progress": run_data["progress"],
        "created_at": run_data["created_at"],
        "completed_at": run_data.get("completed_at"),
        "config": run_data.get("config", {}),
    }


@app.get("/api/runs/{run_id}/results")
async def get_run_results(run_id: str, limit: int = 500):
    run_data = db.get_run(run_id)
    if not run_data:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")

    summary = run_data.get("summary") or db.get_stats_summary(run_id)
    attempts = db.get_run_attempts(run_id, limit=limit)

    return {
        "run": run_data,
        "summary": summary,
        "attempts": attempts,
    }


@app.get("/api/stats/summary")
async def get_latest_stats_summary():
    latest_run = db.get_latest_baseline_run()
    if latest_run:
        summary = latest_run.get("summary") or db.get_stats_summary(latest_run["id"])
        summary["latest_run_id"] = latest_run["id"]
        summary["latest_run_created_at"] = latest_run["created_at"]
        return summary

    # Fallback to all recorded attempts if no formal baseline run completed yet
    fallback_summary = db.get_stats_summary(None)
    fallback_summary["latest_run_id"] = None
    return fallback_summary


# ---------------------------------------------------------------------
# Part 2: Automated Red-Teamer Endpoints
# ---------------------------------------------------------------------

@app.post("/api/auto/run")
async def start_auto_campaign(req: AutoCampaignRequest, background_tasks: BackgroundTasks):
    run_id = f"auto_{uuid.uuid4().hex[:10]}"
    models = req.models or [settings.weak_defender_model]
    scenarios_count = len(req.scenario_ids) if req.scenario_ids else len(SCENARIOS)

    # Estimate API call volume
    # Worst case: (initial candidates + reflection rounds) * scenarios * models
    estimated_calls = models_count = len(models) * scenarios_count * req.budget_per_scenario
    warning_exceeded = estimated_calls > settings.api_call_warning_threshold

    background_tasks.add_task(
        run_auto_campaign,
        models=models,
        defense=req.defense,
        scenario_ids=req.scenario_ids,
        budget_per_scenario=req.budget_per_scenario,
        mode=req.mode,
        run_id=run_id,
    )

    return {
        "run_id": run_id,
        "status": "started",
        "models": models,
        "defense": req.defense,
        "budget_per_scenario": req.budget_per_scenario,
        "mode": req.mode,
        "estimated_api_calls": estimated_calls,
        "warning_exceeded": warning_exceeded,
        "message": "Automated red-team campaign launched.",
    }


@app.get("/api/auto/runs/{run_id}/events")
async def get_auto_run_events(run_id: str, since_id: int = 0):
    events = db.get_run_events(run_id=run_id, since_id=since_id)
    run_data = db.get_run(run_id)
    return {
        "run_id": run_id,
        "status": run_data["status"] if run_data else "unknown",
        "progress": run_data["progress"] if run_data else 0.0,
        "events": events,
    }


@app.get("/api/auto/compare")
async def get_auto_comparison(run_id: Optional[str] = None):
    target_run_id = run_id
    if not target_run_id:
        conn = db.get_connection()
        latest = conn.execute(
            "SELECT id FROM runs WHERE type = 'auto' AND status = 'completed' ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        conn.close()
        if latest:
            target_run_id = latest["id"]

    if not target_run_id:
        # Fallback to empty default comparison structure
        return {
            "run_id": None,
            "target_count": 0,
            "human_asr_at_n": 0.0,
            "auto_asr_at_1": 0.0,
            "auto_asr_at_n": 0.0,
            "asr_gain": 0.0,
            "mean_attempts_to_first_success": None,
            "unique_successful_attacks": 0,
            "cumulative_curve": {"attempts": [], "auto_cumulative_asr": [], "human_cumulative_asr": []},
            "by_model": {},
            "strategy_distribution": {},
            "diversity": {"total_attacks": 0, "cluster_count": 0, "diversity_ratio": 0.0, "clusters": []},
        }

    return compute_comparison_metrics(target_run_id)


@app.get("/api/auto/strategies")
async def get_strategy_memory_stats(model: Optional[str] = None, scenario_family: Optional[str] = None):
    stats = strategy_memory.get_stats(model=model, scenario_family=scenario_family)
    return {
        "total_strategies": len(stats),
        "strategies": stats,
    }


@app.post("/api/auto/strategies/reset")
async def reset_strategy_memory_endpoint():
    strategy_memory.reset()
    return {"status": "ok", "message": "Strategy memory reset successfully."}


@app.get("/api/auto/gallery")
async def get_attack_gallery(
    run_id: Optional[str] = None,
    attack_source: Optional[str] = None,
    limit: int = 150,
):
    attacks = db.get_successful_attacks(run_id=run_id, attack_source=attack_source, limit=limit)
    return {
        "total": len(attacks),
        "attacks": attacks,
    }


@app.get("/api/auto/export")
async def export_campaign_results(run_id: str, format: str = "json"):
    run_data = db.get_run(run_id)
    if not run_data:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")

    content = export_campaign_data(run_id, format_type=format)
    media_type = "text/csv" if format.lower() == "csv" else "application/json"
    filename = f"redloop_campaign_{run_id}.{format.lower()}"

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ---------------------------------------------------------------------
# Static Frontend Serving
# ---------------------------------------------------------------------

if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    async def serve_index():
        index_file = FRONTEND_DIR / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return {"message": "Frontend index.html not found"}
