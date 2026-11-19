"""
Database seeding script for RedLoop.

Pre-populates the SQLite database with baseline evaluation results so the
presentation dashboard is populated with interactive charts and attempt tables
immediately upon initial startup.

Usage:
    python -m backend.seed
"""

import asyncio
import logging
import uuid
from backend import db
from backend.baseline import ATTACK_TEMPLATES, render_attack_prompt
from backend.config import settings
from backend.defender import run_defender
from backend.eval_auto import run_auto_campaign
from backend.judge import judge
from backend.scenarios import SCENARIOS, get_all_scenarios

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("redloop.seed")


async def seed():
    logger.info("Initializing database...")
    db.init_db()

    # Save scenario metadata
    scenarios = get_all_scenarios()
    db.save_scenario_metadata([s.to_dict() for s in scenarios])
    logger.info(f"Registered {len(scenarios)} scenarios.")

    run_id = f"baseline_seed_{uuid.uuid4().hex[:8]}"
    models = [settings.weak_defender_model, settings.strong_defender_model]

    # Pick 1 template from each category for clean representation (9 categories)
    categories_seen = set()
    selected_templates = []
    for tpl in ATTACK_TEMPLATES:
        if tpl.category not in categories_seen:
            selected_templates.append(tpl)
            categories_seen.add(tpl.category)

    total_seed_tasks = len(models) * len(scenarios) * len(selected_templates)
    logger.info(
        f"Seeding baseline run '{run_id}' with {len(models)} models, "
        f"{len(scenarios)} scenarios, and {len(selected_templates)} categories "
        f"({total_seed_tasks} total attempts)..."
    )

    db.create_run(
        run_id=run_id,
        run_type="baseline",
        config={
            "models": models,
            "defense": "none",
            "scenario_count": len(scenarios),
            "template_count": len(selected_templates),
            "seeded": True,
        },
    )

    completed = 0
    success_count = 0

    for model in models:
        for scenario in scenarios:
            for tpl in selected_templates:
                attack_text = render_attack_prompt(tpl, scenario)

                # Simulate weak defender susceptible to none, strong defender or warning more resilient
                # We also vary defenses: 70% none, 30% basic_system_warning
                defense = "none" if (completed % 3 != 0) else "basic_system_warning"

                defender_res = await run_defender(
                    scenario=scenario,
                    injection_text=attack_text,
                    model=model,
                    defense_config=defense,
                )

                judge_res = await judge(
                    scenario=scenario,
                    run_result=defender_res,
                    injection_text=attack_text,
                    enable_llm_judge=False,
                )

                attempt_id = f"seed_{uuid.uuid4().hex[:10]}"
                is_success = judge_res["success"]
                if is_success:
                    success_count += 1

                db.record_attack_attempt(
                    attempt_id=attempt_id,
                    run_id=run_id,
                    scenario_id=scenario.id,
                    model=model,
                    defense=defense,
                    attack_text=attack_text,
                    attack_category=tpl.category,
                    attack_source="human_baseline",
                    response=defender_res["response"],
                    tool_calls=defender_res["tool_calls"],
                    success=is_success,
                    reason=judge_res["reason"],
                    latency_ms=defender_res["latency_ms"],
                    cached=defender_res["cached"],
                )

                completed += 1
                if completed % 15 == 0:
                    db.update_run_progress(run_id, progress=round(completed / total_seed_tasks, 2), status="running")
                    logger.info(f"Progress: {completed}/{total_seed_tasks} ({completed * 100 // total_seed_tasks}%)")

    summary = db.get_stats_summary(run_id)
    db.update_run_progress(run_id, progress=1.0, status="completed", summary=summary)

    logger.info("==================================================")
    logger.info("BASELINE SEEDING COMPLETE!")
    logger.info(f"Baseline Run ID: {run_id}")
    logger.info(f"Total Attempts: {summary['total_attempts']}")
    logger.info(f"Overall ASR: {summary['asr_overall']}%")
    logger.info("==================================================")

    # Seed Automated Red-Teamer Campaign (Part 2)
    auto_run_id = f"auto_seed_{uuid.uuid4().hex[:8]}"
    logger.info(f"Seeding automated red-team campaign '{auto_run_id}' across models & scenarios...")
    auto_res = await run_auto_campaign(
        models=models,
        defense="none",
        budget_per_scenario=6,
        mode="first_success",
        run_id=auto_run_id,
    )
    comp = auto_res["comparison"]

    logger.info("==================================================")
    logger.info("AUTOMATED RED-TEAM SEEDING COMPLETE!")
    logger.info(f"Auto Run ID: {auto_run_id}")
    logger.info(f"Human Baseline ASR@N: {comp['human_asr_at_n']}%")
    logger.info(f"Automated ASR@1: {comp['auto_asr_at_1']}%")
    logger.info(f"Automated ASR@N: {comp['auto_asr_at_n']}%")
    logger.info(f"Net ASR Gain: +{comp['asr_gain']}%")
    logger.info(f"Distinct Attack Clusters: {comp['diversity']['cluster_count']}")
    logger.info("==================================================")


if __name__ == "__main__":
    asyncio.run(seed())

