"""
Evaluation and Comparison Engine for Automated Red-Teaming (Part 2).

Orchestrates automated red-teaming campaigns and performs fair, rigorous
comparisons against the human baseline:
1. Matching query budgets (N attempts per scenario).
2. Metrics: ASR@1, ASR@N, mean attempts-to-first-success.
3. Cumulative success trajectory curves over attempts 1..N.
4. Lightweight pure-Python TF-IDF + Cosine Clustering for attack diversity.
5. Export serialization (CSV and JSON).
"""

import asyncio
import csv
import io
import json
import logging
import math
import re
import uuid
from collections import Counter, defaultdict
from typing import Any, Optional

from backend import db
from backend.attacker.attacker import RedTeamer
from backend.config import settings
from backend.scenarios import SCENARIOS, Scenario, get_all_scenarios, get_scenario

logger = logging.getLogger("redloop.eval_auto")


# =====================================================================
# Lightweight Pure-Python Attack Diversity Clustering
# =====================================================================

class TextClusterer:
    """
    Dependency-free TF-IDF vectorizer and greedy distance clusterer.
    Measures semantic and lexical diversity of successful adversarial attacks.
    """

    @staticmethod
    def tokenize(text: str) -> list[str]:
        words = re.findall(r"\b[a-zA-Z]{3,}\b", text.lower())
        stopwords = {
            "the", "and", "for", "with", "that", "this", "from", "you", "are",
            "all", "have", "not", "your", "can", "out", "about", "will", "our"
        }
        return [w for w in words if w not in stopwords]

    @classmethod
    def compute_tfidf_vectors(cls, documents: list[str]) -> list[dict[str, float]]:
        doc_count = len(documents)
        if doc_count == 0:
            return []

        doc_tokens = [cls.tokenize(doc) for doc in documents]
        df = Counter()
        for tokens in doc_tokens:
            unique_terms = set(tokens)
            df.update(unique_terms)

        idf = {term: math.log((1.0 + doc_count) / (1.0 + freq)) + 1.0 for term, freq in df.items()}

        vectors = []
        for tokens in doc_tokens:
            tf = Counter(tokens)
            vec: dict[str, float] = {}
            norm_sq = 0.0
            for term, count in tf.items():
                val = (count / max(1, len(tokens))) * idf.get(term, 1.0)
                vec[term] = val
                norm_sq += val * val

            norm = math.sqrt(norm_sq) or 1.0
            for term in vec:
                vec[term] /= norm
            vectors.append(vec)

        return vectors

    @staticmethod
    def cosine_similarity(v1: dict[str, float], v2: dict[str, float]) -> float:
        intersection = set(v1.keys()) & set(v2.keys())
        return sum(v1[k] * v2[k] for k in intersection)

    @classmethod
    def cluster_attacks(
        cls,
        attack_texts: list[str],
        similarity_threshold: float = 0.40,
    ) -> dict[str, Any]:
        """
        Greedy threshold clustering on attack texts.
        Returns:
            {
                "total_attacks": int,
                "cluster_count": int,
                "diversity_ratio": float, # clusters / total
                "clusters": list[dict]
            }
        """
        if not attack_texts:
            return {"total_attacks": 0, "cluster_count": 0, "diversity_ratio": 0.0, "clusters": []}

        vectors = cls.compute_tfidf_vectors(attack_texts)
        clusters: list[list[int]] = []

        for i, vec in enumerate(vectors):
            assigned = False
            for cluster in clusters:
                # Compare with cluster representative (first item)
                sim = cls.cosine_similarity(vec, vectors[cluster[0]])
                if sim >= similarity_threshold:
                    cluster.append(i)
                    assigned = True
                    break
            if not assigned:
                clusters.append([i])

        cluster_details = []
        for c_idx, member_indices in enumerate(clusters):
            rep_text = attack_texts[member_indices[0]]
            cluster_details.append({
                "cluster_id": c_idx + 1,
                "size": len(member_indices),
                "representative_sample": rep_text[:140] + ("..." if len(rep_text) > 140 else ""),
            })

        cluster_count = len(clusters)
        diversity_ratio = round(cluster_count / max(1, len(attack_texts)), 2)

        return {
            "total_attacks": len(attack_texts),
            "cluster_count": cluster_count,
            "diversity_ratio": diversity_ratio,
            "clusters": cluster_details,
        }


# =====================================================================
# Automated Campaign Orchestrator
# =====================================================================

async def run_auto_campaign(
    models: Optional[list[str]] = None,
    defense: str = "none",
    scenario_ids: Optional[list[str]] = None,
    budget_per_scenario: int = 8,
    mode: str = "first_success",
    run_id: Optional[str] = None,
) -> dict[str, Any]:
    """
    Executes an automated red-teaming campaign across specified models & scenarios.
    """
    models_to_test = models or [settings.weak_defender_model]
    target_run_id = run_id or f"auto_camp_{uuid.uuid4().hex[:10]}"

    if scenario_ids:
        scenarios_to_test = [get_scenario(sid) for sid in scenario_ids if get_scenario(sid)]
    else:
        scenarios_to_test = SCENARIOS

    total_scenarios = len(models_to_test) * len(scenarios_to_test)

    # Record run in DB
    config_dict = {
        "models": models_to_test,
        "defense": defense,
        "scenario_ids": [s.id for s in scenarios_to_test],
        "budget_per_scenario": budget_per_scenario,
        "mode": mode,
        "attacker_model": settings.attacker_model,
    }
    db.create_run(target_run_id, "auto", config_dict)

    red_teamer = RedTeamer(
        model=settings.attacker_model,
        budget=budget_per_scenario,
        initial_candidates=min(4, budget_per_scenario),
        mode=mode,
    )

    scenario_results: list[dict[str, Any]] = []
    scenarios_completed = 0

    for model in models_to_test:
        for scenario in scenarios_to_test:
            result = await red_teamer.attack_scenario(
                scenario=scenario,
                defender_model=model,
                defense=defense,
                run_id=target_run_id,
            )
            scenario_results.append(result)
            scenarios_completed += 1
            progress = round(scenarios_completed / max(1, total_scenarios), 3)
            db.update_run_progress(target_run_id, progress=progress, status="running")

    # Generate comparison and final summary
    comparison_data = compute_comparison_metrics(target_run_id, budget_per_scenario)
    db.update_run_progress(
        target_run_id,
        progress=1.0,
        status="completed",
        summary=comparison_data,
    )

    return {
        "run_id": target_run_id,
        "models": models_to_test,
        "scenarios_tested": len(scenarios_to_test),
        "comparison": comparison_data,
    }


# =====================================================================
# Fair Comparison Computation: Human Baseline vs. Automated Red-Teamer
# =====================================================================

def compute_comparison_metrics(run_id: str, budget_n: int = 8) -> dict[str, Any]:
    """
    Computes rigorous comparative performance between automated attacks and human baseline.
    Ensures a fair comparison by evaluating the human baseline with an equal query budget N.
    """
    # 1. Fetch automated attempts for this run
    auto_attempts = db.get_run_attempts(run_id, limit=1000)
    if not auto_attempts:
        # Fallback query if run_id attempts empty
        conn = db.get_connection()
        rows = conn.execute(
            "SELECT * FROM attack_attempts WHERE run_id = ? ORDER BY created_at ASC", (run_id,)
        ).fetchall()
        conn.close()
        auto_attempts = [dict(r) for r in rows]

    # Group auto attempts by (scenario_id, model)
    auto_by_target: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for a in auto_attempts:
        key = (a["scenario_id"], a["model"])
        auto_by_target[key].append(a)

    target_count = len(auto_by_target)

    # Metric: ASR@1 (First attempt success rate)
    first_attempt_successes = sum(
        1 for attempts in auto_by_target.values() if attempts and attempts[0]["success"]
    )
    auto_asr_at_1 = round(first_attempt_successes / max(1, target_count) * 100.0, 1)

    # Metric: ASR@N (Success within budget N)
    budget_successes = sum(
        1 for attempts in auto_by_target.values() if any(a["success"] for a in attempts[:budget_n])
    )
    auto_asr_at_n = round(budget_successes / max(1, target_count) * 100.0, 1)

    # Metric: Mean Attempts to First Success
    attempts_to_success = []
    for attempts in auto_by_target.values():
        for idx, a in enumerate(attempts[:budget_n]):
            if a["success"]:
                attempts_to_success.append(idx + 1)
                break
    mean_attempts = round(sum(attempts_to_success) / max(1, len(attempts_to_success)), 2) if attempts_to_success else None

    # Cumulative success curve over attempts 1..N
    cumulative_auto = []
    for step in range(1, budget_n + 1):
        wins = sum(1 for attempts in auto_by_target.values() if any(a["success"] for a in attempts[:step]))
        cumulative_auto.append(round(wins / max(1, target_count) * 100.0, 1))

    # 2. Fair Human Baseline Evaluation with MATCHING Budget N
    # Look up human_baseline attempts from DB for the same models and scenarios
    conn = db.get_connection()
    scenario_ids = list({a["scenario_id"] for a in auto_attempts})
    models = list({a["model"] for a in auto_attempts})

    placeholders_sc = ",".join("?" for _ in scenario_ids)
    placeholders_md = ",".join("?" for _ in models)

    human_query = f"""
    SELECT scenario_id, model, success, attack_category, created_at
    FROM attack_attempts
    WHERE attack_source = 'human_baseline'
      AND scenario_id IN ({placeholders_sc})
      AND model IN ({placeholders_md})
    ORDER BY created_at ASC
    """
    human_rows = conn.execute(human_query, scenario_ids + models).fetchall() if scenario_ids and models else []
    conn.close()

    human_by_target: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for r in human_rows:
        key = (r["scenario_id"], r["model"])
        human_by_target[key].append(dict(r))

    human_target_count = len(human_by_target) or target_count
    human_budget_successes = sum(
        1 for attempts in human_by_target.values() if any(a["success"] for a in attempts[:budget_n])
    )
    human_asr_at_n = round(human_budget_successes / max(1, human_target_count) * 100.0, 1)

    cumulative_human = []
    for step in range(1, budget_n + 1):
        wins = sum(1 for attempts in human_by_target.values() if any(a["success"] for a in attempts[:step]))
        cumulative_human.append(round(wins / max(1, human_target_count) * 100.0, 1))

    # 3. Strategy distribution of successful attacks
    successful_auto = [a for a in auto_attempts if a["success"]]
    strategy_counts = Counter(a["attack_category"] for a in successful_auto)

    # 4. Attack diversity clustering
    successful_texts = [a["attack_text"] for a in successful_auto]
    diversity_metrics = TextClusterer.cluster_attacks(successful_texts)

    # Breakdown by Model for comparative charts
    by_model_comp = {}
    for model_name in models:
        m_auto_targets = [att for key, att in auto_by_target.items() if key[1] == model_name]
        m_human_targets = [att for key, att in human_by_target.items() if key[1] == model_name]

        m_auto_cnt = len(m_auto_targets)
        m_human_cnt = len(m_human_targets) or m_auto_cnt

        m_auto_asr1 = round(sum(1 for atts in m_auto_targets if atts and atts[0]["success"]) / max(1, m_auto_cnt) * 100.0, 1)
        m_auto_asrn = round(sum(1 for atts in m_auto_targets if any(a["success"] for a in atts[:budget_n])) / max(1, m_auto_cnt) * 100.0, 1)
        m_human_asrn = round(sum(1 for atts in m_human_targets if any(a["success"] for a in atts[:budget_n])) / max(1, m_human_cnt) * 100.0, 1)

        by_model_comp[model_name] = {
            "human_asr": m_human_asrn,
            "auto_asr_1": m_auto_asr1,
            "auto_asr_n": m_auto_asrn,
        }

    return {
        "run_id": run_id,
        "budget_per_scenario": budget_n,
        "target_count": target_count,
        "human_asr_at_n": human_asr_at_n,
        "auto_asr_at_1": auto_asr_at_1,
        "auto_asr_at_n": auto_asr_at_n,
        "asr_gain": round(auto_asr_at_n - human_asr_at_n, 1),
        "mean_attempts_to_first_success": mean_attempts,
        "unique_successful_attacks": len(set(successful_texts)),
        "cumulative_curve": {
            "attempts": list(range(1, budget_n + 1)),
            "auto_cumulative_asr": cumulative_auto,
            "human_cumulative_asr": cumulative_human,
        },
        "by_model": by_model_comp,
        "strategy_distribution": dict(strategy_counts),
        "diversity": diversity_metrics,
    }


# =====================================================================
# Export Utilities (CSV / JSON)
# =====================================================================

def export_campaign_data(run_id: str, format_type: str = "json") -> str:
    """Exports campaign attempts and metrics formatted as CSV or JSON."""
    attempts = db.get_run_attempts(run_id, limit=2000)
    summary = compute_comparison_metrics(run_id)

    if format_type.lower() == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "attempt_id", "run_id", "scenario_id", "scenario_name", "model",
            "defense", "strategy", "success", "reason", "latency_ms", "attack_text", "response"
        ])
        for a in attempts:
            writer.writerow([
                a["id"], a.get("run_id", ""), a["scenario_id"], a.get("scenario_name", ""),
                a["model"], a["defense"], a["attack_category"], 1 if a["success"] else 0,
                a["reason"], a["latency_ms"], a["attack_text"].replace("\n", " "),
                a["response"].replace("\n", " ")
            ])
        return output.getvalue()

    # JSON export
    payload = {
        "run_id": run_id,
        "summary": summary,
        "attempts": attempts,
    }
    return json.dumps(payload, indent=2)
