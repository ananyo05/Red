# RedLoop: Progress Tracking

## Project and Current Part
RedLoop, Part 2: Automated Red-Teamer (In-Context Search + Strategy Memory)

## Goal (3 Lines)
Build an LLM-powered red-teamer that automatically discovers prompt-injection attacks against defenders.
Use in-context learning, reflection, and bandit strategy memory instead of RL to iteratively improve attacks.
Demonstrate that the automated red-teamer outperforms the fixed human-written baseline within a fair budget.

## Status Checklist
- [x] Task 1: Initialize PROGRESS.md & project architecture plan
- [x] Task 2: Core configuration & database schema extensions (`strategy_memory` and `run_events` tables)
- [x] Task 3: Scenario public view isolation (`get_public_view()` excluding system prompt & canary)
- [x] Task 4: Attacker utilities: robust JSON repair parser (`backend/attacker/json_utils.py`)
- [x] Task 5: Strategy memory with bandit selection (UCB/epsilon-greedy) (`backend/attacker/strategy_memory.py`)
- [x] Task 6: RedTeamer class with reflection loop and mock mode (`backend/attacker/attacker.py`)
- [x] Task 7: Evaluation engine: automated vs human baseline & diversity clustering (`backend/eval_auto.py`)
- [x] Task 8: FastAPI backend routes (`/api/auto/run`, `/api/auto/compare`, `/api/auto/strategies`, export)
- [x] Task 9: Presentation frontend: Auto Red-Team Live, Human vs Automated, Attack Gallery, Replay, Export
- [x] Task 10: Update seed command (`backend/seed.py`) with pre-computed auto campaign
- [x] Task 11: Comprehensive unit & integration tests (`backend/tests/test_attacker.py`, etc.)
- [x] Task 12: Documentation: README update, architecture diagram, limitations, 7-min demo script

## Done
- `backend/config.py`: Added `attacker_model`, `default_attack_budget`, `default_initial_candidates`, `api_call_warning_threshold`.
- `backend/db.py`: Added `strategy_memory` and `run_events` tables, plus helper functions for recording and fetching strategy outcomes, events, and successful attacks.
- `backend/scenarios.py`: Added `get_public_view()` ensuring strict black-box isolation without system prompts or canaries. Sanitized all scenario goal descriptions.
- `backend/attacker/json_utils.py`: Created resilient multi-stage JSON repair parser handling markdown fences, trailing commas, and unescaped newlines.
- `backend/attacker/strategy_memory.py`: Implemented UCB1 and Epsilon-Greedy multi-armed bandit strategy selection and prompt guidance generation.
- `backend/attacker/attacker.py`: Implemented `RedTeamer` class with Round 0 generation, near-miss detection, reflection mutation loop, and deterministic mock fallback.
- `backend/eval_auto.py`: Implemented campaign orchestrator, fair query budget matching, ASR@1, ASR@N, attempts-to-success, pure-Python TF-IDF clustering, and CSV/JSON export.
- `backend/main.py`: Added `/api/auto/run`, `/api/auto/runs/{id}/events`, `/api/auto/compare`, `/api/auto/strategies`, `/api/auto/strategies/reset`, `/api/auto/gallery`, `/api/auto/export`.
- `backend/seed.py`: Pre-runs baseline and auto red-team campaign, calculating fair comparisons and clustering.
- `backend/tests/test_attacker.py`: 6 comprehensive tests covering black-box isolation, JSON parsing, bandit selection, early stopping, clustering, and end-to-end campaign with export.
- `frontend/index.html`, `frontend/style.css`, `frontend/app.js`: Added Auto Red-Team Live tab with animated streaming cards and reflection separators, Human vs Auto comparison tab with cumulative curve, Attack Gallery tab, campaign Replay, and JSON/CSV export.
- `README.md`: Updated architecture diagram, GPT-Red relationship table, limitations, and 7-minute presenter demo script for Review 2.

## Decisions and Assumptions
- Pure-Python TF-IDF + greedy clustering measures attack diversity without heavy ML dependencies.
- Fair comparison evaluates both human baseline and auto red-teamer at matching budget N.
- `get_public_view()` strips `system_prompt` and `target_canary` to simulate realistic black-box red-teaming.
- Replay feature simulates live streaming of a stored run for flawless offline examiner presentations.

## How to Run and Test
- Environment: `/Users/srabaniadhikary/Desktop/Major project/.venv/bin/activate`
- Pytest: `./.venv/bin/pytest backend/tests -v` (All 24 passed in 1.25s)
- Seed: `./.venv/bin/python -m backend.seed`
- Server: `./.venv/bin/uvicorn backend.main:app --port 8000`

## Known Issues and Bugs
None. All 24 tests pass cleanly.

## Next Steps
Part 2 complete, nothing left. Ready for presentation and demonstration.

Last updated: 2026-11-19 21:16 IST
