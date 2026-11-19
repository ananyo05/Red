"""
Database layer for RedLoop using SQLite.

Manages testbed runs, attack attempt records, and scenario metadata.
Configured with WAL mode and indexes for fast queries.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from backend.config import settings


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    path = db_path or settings.database_path
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    conn = get_connection(db_path)
    with conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS scenarios (
            id TEXT PRIMARY KEY,
            family TEXT NOT NULL,
            name TEXT NOT NULL,
            attacker_goal_type TEXT NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS runs (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL, -- 'baseline', 'manual', 'adversarial'
            config_json TEXT NOT NULL,
            status TEXT NOT NULL, -- 'pending', 'running', 'completed', 'failed'
            progress REAL NOT NULL DEFAULT 0.0,
            summary_json TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS attack_attempts (
            id TEXT PRIMARY KEY,
            run_id TEXT,
            scenario_id TEXT NOT NULL,
            model TEXT NOT NULL,
            defense TEXT NOT NULL,
            attack_text TEXT NOT NULL,
            attack_category TEXT NOT NULL,
            attack_source TEXT NOT NULL, -- 'human_baseline', 'manual', 'auto'
            response TEXT NOT NULL,
            tool_calls_json TEXT,
            success INTEGER NOT NULL, -- 1 for attack success, 0 for defended
            reason TEXT NOT NULL,
            latency_ms REAL NOT NULL DEFAULT 0.0,
            cached INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (run_id) REFERENCES runs (id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_attempts_run_id ON attack_attempts(run_id);
        CREATE INDEX IF NOT EXISTS idx_attempts_model ON attack_attempts(model);
        CREATE INDEX IF NOT EXISTS idx_attempts_scenario ON attack_attempts(scenario_id);
        CREATE INDEX IF NOT EXISTS idx_attempts_category ON attack_attempts(attack_category);
        CREATE INDEX IF NOT EXISTS idx_runs_created_at ON runs(created_at DESC);

        CREATE TABLE IF NOT EXISTS strategy_memory (
            strategy TEXT NOT NULL,
            model TEXT NOT NULL,
            scenario_family TEXT NOT NULL,
            tries INTEGER NOT NULL DEFAULT 0,
            successes INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (strategy, model, scenario_family)
        );
        CREATE INDEX IF NOT EXISTS idx_strategy_mem_strat ON strategy_memory(strategy);
        CREATE INDEX IF NOT EXISTS idx_strategy_mem_model ON strategy_memory(model);

        CREATE TABLE IF NOT EXISTS run_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            event_type TEXT NOT NULL, -- 'attempt', 'reflection', 'round_start', 'completed'
            data_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (run_id) REFERENCES runs (id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_events_run ON run_events(run_id);
        """)
    conn.close()


def save_scenario_metadata(scenarios_list: list[dict[str, Any]], db_path: Optional[Path] = None) -> None:
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        for s in scenarios_list:
            conn.execute(
                """
                INSERT INTO scenarios (id, family, name, attacker_goal_type, description, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    family=excluded.family,
                    name=excluded.name,
                    attacker_goal_type=excluded.attacker_goal_type,
                    description=excluded.description
                """,
                (s["id"], s["family"], s["name"], s["attacker_goal_type"], s.get("description", ""), now),
            )
    conn.close()


def create_run(run_id: str, run_type: str, config: dict[str, Any], db_path: Optional[Path] = None) -> None:
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            """
            INSERT INTO runs (id, type, config_json, status, progress, created_at)
            VALUES (?, ?, ?, 'running', 0.0, ?)
            """,
            (run_id, run_type, json.dumps(config), now),
        )
    conn.close()


def update_run_progress(
    run_id: str,
    progress: float,
    status: str = "running",
    summary: Optional[dict[str, Any]] = None,
    db_path: Optional[Path] = None,
) -> None:
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat() if status in ("completed", "failed") else None
    with conn:
        conn.execute(
            """
            UPDATE runs
            SET progress = ?,
                status = ?,
                summary_json = COALESCE(?, summary_json),
                completed_at = COALESCE(?, completed_at)
            WHERE id = ?
            """,
            (progress, status, json.dumps(summary) if summary else None, now, run_id),
        )
    conn.close()


def record_attack_attempt(
    attempt_id: str,
    run_id: Optional[str],
    scenario_id: str,
    model: str,
    defense: str,
    attack_text: str,
    attack_category: str,
    attack_source: str,
    response: str,
    tool_calls: list[dict[str, Any]],
    success: bool,
    reason: str,
    latency_ms: float = 0.0,
    cached: bool = False,
    db_path: Optional[Path] = None,
) -> None:
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            """
            INSERT INTO attack_attempts (
                id, run_id, scenario_id, model, defense, attack_text, attack_category,
                attack_source, response, tool_calls_json, success, reason, latency_ms,
                cached, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                attempt_id,
                run_id,
                scenario_id,
                model,
                defense,
                attack_text,
                attack_category,
                attack_source,
                response,
                json.dumps(tool_calls),
                1 if success else 0,
                reason,
                latency_ms,
                1 if cached else 0,
                now,
            ),
        )
    conn.close()


def get_run(run_id: str, db_path: Optional[Path] = None) -> Optional[dict[str, Any]]:
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    conn.close()
    if not row:
        return None
    data = dict(row)
    data["config"] = json.loads(data["config_json"]) if data.get("config_json") else {}
    data["summary"] = json.loads(data["summary_json"]) if data.get("summary_json") else None
    return data


def get_run_attempts(run_id: str, limit: int = 500, db_path: Optional[Path] = None) -> list[dict[str, Any]]:
    conn = get_connection(db_path)
    rows = conn.execute(
        """
        SELECT a.*, s.family as scenario_family, s.name as scenario_name
        FROM attack_attempts a
        LEFT JOIN scenarios s ON a.scenario_id = s.id
        WHERE a.run_id = ?
        ORDER BY a.created_at ASC
        LIMIT ?
        """,
        (run_id, limit),
    ).fetchall()
    conn.close()

    results = []
    for r in rows:
        item = dict(r)
        item["tool_calls"] = json.loads(item["tool_calls_json"]) if item.get("tool_calls_json") else []
        item["success"] = bool(item["success"])
        item["cached"] = bool(item["cached"])
        results.append(item)
    return results


def get_latest_baseline_run(db_path: Optional[Path] = None) -> Optional[dict[str, Any]]:
    conn = get_connection(db_path)
    row = conn.execute(
        "SELECT * FROM runs WHERE type = 'baseline' AND status = 'completed' ORDER BY created_at DESC LIMIT 1"
    ).fetchone()
    conn.close()
    if not row:
        return None
    data = dict(row)
    data["config"] = json.loads(data["config_json"]) if data.get("config_json") else {}
    data["summary"] = json.loads(data["summary_json"]) if data.get("summary_json") else None
    return data


def get_stats_summary(run_id: Optional[str] = None, db_path: Optional[Path] = None) -> dict[str, Any]:
    """
    Computes aggregated Attack Success Rate (ASR):
    - Overall ASR
    - By model
    - By scenario family
    - By attack category
    """
    conn = get_connection(db_path)
    where_clause = "WHERE a.run_id = ?" if run_id else ""
    params = (run_id,) if run_id else ()

    # Overall stats
    query_overall = f"""
    SELECT
        COUNT(*) as total_attempts,
        SUM(a.success) as successful_attacks,
        AVG(a.latency_ms) as avg_latency_ms
    FROM attack_attempts a
    {where_clause}
    """
    overall_row = conn.execute(query_overall, params).fetchone()
    total = overall_row["total_attempts"] if overall_row and overall_row["total_attempts"] else 0
    successful = overall_row["successful_attacks"] if overall_row and overall_row["successful_attacks"] else 0
    asr = round((successful / total * 100.0), 1) if total > 0 else 0.0
    avg_latency = round(overall_row["avg_latency_ms"], 1) if overall_row and overall_row["avg_latency_ms"] else 0.0

    # By model
    query_model = f"""
    SELECT
        a.model,
        COUNT(*) as total,
        SUM(a.success) as success_count
    FROM attack_attempts a
    {where_clause}
    GROUP BY a.model
    """
    by_model = {}
    for r in conn.execute(query_model, params).fetchall():
        m_total = r["total"]
        m_success = r["success_count"] or 0
        by_model[r["model"]] = {
            "total": m_total,
            "success": m_success,
            "asr": round((m_success / m_total * 100.0), 1) if m_total > 0 else 0.0,
        }

    # By family
    query_family = f"""
    SELECT
        COALESCE(s.family, 'unknown') as family,
        COUNT(*) as total,
        SUM(a.success) as success_count
    FROM attack_attempts a
    LEFT JOIN scenarios s ON a.scenario_id = s.id
    {where_clause}
    GROUP BY family
    """
    by_family = {}
    for r in conn.execute(query_family, params).fetchall():
        f_total = r["total"]
        f_success = r["success_count"] or 0
        by_family[r["family"]] = {
            "total": f_total,
            "success": f_success,
            "asr": round((f_success / f_total * 100.0), 1) if f_total > 0 else 0.0,
        }

    # By category
    query_cat = f"""
    SELECT
        a.attack_category,
        COUNT(*) as total,
        SUM(a.success) as success_count
    FROM attack_attempts a
    {where_clause}
    GROUP BY a.attack_category
    """
    by_category = {}
    for r in conn.execute(query_cat, params).fetchall():
        c_total = r["total"]
        c_success = r["success_count"] or 0
        by_category[r["attack_category"]] = {
            "total": c_total,
            "success": c_success,
            "asr": round((c_success / c_total * 100.0), 1) if c_total > 0 else 0.0,
        }

    conn.close()

    return {
        "run_id": run_id,
        "total_attempts": total,
        "successful_attacks": successful,
        "blocked_attacks": total - successful,
        "asr_overall": asr,
        "avg_latency_ms": avg_latency,
        "by_model": by_model,
        "by_family": by_family,
        "by_category": by_category,
    }


# =====================================================================
# Strategy Memory & Run Event Helpers (Part 2)
# =====================================================================

def record_strategy_outcome(
    strategy: str,
    model: str,
    scenario_family: str,
    success: bool,
    db_path: Optional[Path] = None,
) -> None:
    """Updates try/success counts for a strategy against a model and family."""
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    inc_success = 1 if success else 0
    with conn:
        conn.execute(
            """
            INSERT INTO strategy_memory (strategy, model, scenario_family, tries, successes, updated_at)
            VALUES (?, ?, ?, 1, ?, ?)
            ON CONFLICT(strategy, model, scenario_family) DO UPDATE SET
                tries = strategy_memory.tries + 1,
                successes = strategy_memory.successes + excluded.successes,
                updated_at = excluded.updated_at
            """,
            (strategy, model, scenario_family, inc_success, now),
        )
    conn.close()


def get_strategy_stats(
    model: Optional[str] = None,
    scenario_family: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> list[dict[str, Any]]:
    """Retrieves aggregated strategy memory statistics with success rates."""
    conn = get_connection(db_path)
    conditions = []
    params: list[Any] = []
    if model:
        conditions.append("model = ?")
        params.append(model)
    if scenario_family:
        conditions.append("scenario_family = ?")
        params.append(scenario_family)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    query = f"""
    SELECT
        strategy,
        SUM(tries) as total_tries,
        SUM(successes) as total_successes,
        ROUND(CAST(SUM(successes) AS REAL) / MAX(SUM(tries), 1) * 100.0, 1) as success_rate_pct
    FROM strategy_memory
    {where}
    GROUP BY strategy
    ORDER BY total_successes DESC, success_rate_pct DESC
    """
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def reset_strategy_memory(db_path: Optional[Path] = None) -> None:
    """Resets all learned strategy statistics."""
    conn = get_connection(db_path)
    with conn:
        conn.execute("DELETE FROM strategy_memory;")
    conn.close()


def record_run_event(
    run_id: str,
    event_type: str,
    data: dict[str, Any],
    db_path: Optional[Path] = None,
) -> None:
    """Records a fine-grained run event (e.g. attempt outcome, reflection note)."""
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            """
            INSERT INTO run_events (run_id, event_type, data_json, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (run_id, event_type, json.dumps(data), now),
        )
    conn.close()


def get_run_events(
    run_id: str,
    since_id: int = 0,
    limit: int = 500,
    db_path: Optional[Path] = None,
) -> list[dict[str, Any]]:
    """Fetches run events for live streaming/polling since a given event id."""
    conn = get_connection(db_path)
    rows = conn.execute(
        """
        SELECT id, run_id, event_type, data_json, created_at
        FROM run_events
        WHERE run_id = ? AND id > ?
        ORDER BY id ASC
        LIMIT ?
        """,
        (run_id, since_id, limit),
    ).fetchall()
    conn.close()

    events = []
    for r in rows:
        item = dict(r)
        item["data"] = json.loads(item["data_json"]) if item.get("data_json") else {}
        events.append(item)
    return events


def get_successful_attacks(
    run_id: Optional[str] = None,
    attack_source: Optional[str] = None,
    limit: int = 200,
    db_path: Optional[Path] = None,
) -> list[dict[str, Any]]:
    """Returns successful attack records for the Attack Gallery and diversity analysis."""
    conn = get_connection(db_path)
    conditions = ["a.success = 1"]
    params: list[Any] = []
    if run_id:
        conditions.append("a.run_id = ?")
        params.append(run_id)
    if attack_source:
        conditions.append("a.attack_source = ?")
        params.append(attack_source)

    where = f"WHERE {' AND '.join(conditions)}"
    query = f"""
    SELECT a.*, s.family as scenario_family, s.name as scenario_name
    FROM attack_attempts a
    LEFT JOIN scenarios s ON a.scenario_id = s.id
    {where}
    ORDER BY a.created_at DESC
    LIMIT ?
    """
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()

    results = []
    for r in rows:
        item = dict(r)
        item["tool_calls"] = json.loads(item["tool_calls_json"]) if item.get("tool_calls_json") else []
        item["success"] = True
        item["cached"] = bool(item["cached"])
        results.append(item)
    return results


