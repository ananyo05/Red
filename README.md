# RedLoop: Automated LLM Red-Teaming & Prompt Injection Testbed

> **Part 1 & Part 2 of Final-Year B.Tech Capstone Project**  
> A reproduction of OpenAI's *GPT-Red* automated red-teaming research architecture for Large Language Models.

---

## 📌 Project Overview

**RedLoop** is an open-source, empirical red-teaming testbed designed to evaluate Large Language Models against indirect prompt injection, data exfiltration, and tool misuse in sandboxed agent environments.

- **Part 1 (The Testbed & Baseline)**: 10 sandboxed enterprise agent scenarios across 5 families with fake canary tokens and simulated tools, evaluated against a fixed human baseline of 34 templates across 9 categories.
- **Part 2 (The Automated Red-Teamer)**: An autonomous LLM-driven red-teamer (`llama-3.3-70b-versatile`) that searches for prompt injection vulnerabilities, reflects on failures and near-misses, utilizes a multi-armed bandit strategy memory (UCB1), and outperforms the human baseline under a strictly matched query budget.
- **Part 3 (Self-Play Hardening - Upcoming)**: Automated defense distillation and adversarial self-play hardening.

---

## 🧠 Part 2: How RedLoop Relates to OpenAI's GPT-Red

| Dimension | OpenAI GPT-Red | RedLoop Part 2 (This Implementation) |
| :--- | :--- | :--- |
| **Optimization Method** | Reinforcement Learning (PPO) fine-tuning | In-Context Search + Multi-Round Reflection + UCB Bandit |
| **Compute Constraints** | Hundreds of enterprise GPUs / Supercomputing | Lightweight, free-tier Groq API (`llama-3.3-70b-versatile`) & offline mock |
| **Feedback Mechanism** | Scalar reward signal from automated judge | Rich in-context reflection (near-miss diagnostics, error analysis, mutation) |
| **Cross-Run Learning** | Gradient weight updates | Persistent SQLite Strategy Memory (UCB1 / Epsilon-Greedy bandit) |
| **Attacker Visibility** | Black-box / environment observation | Strict black-box isolation: `Scenario.get_public_view()` strips system prompt and canary |
| **Comparison Fairness** | Variable query comparisons | Exact budget matching: Human baseline evaluated with the identical query budget $N$ |

*Note: In-context search and bandit memory provide an accessible, explainable, and reproducible alternative to resource-heavy RL training while reproducing the adaptive, self-improving properties of GPT-Red.*

---

## 🏛️ System Architecture

```text
                                  +---------------------------------------------------+
                                  |              Adversarial Generation               |
                                  |  Human Baseline (Part 1)  |  Auto Red-Teamer (Part 2) |
                                  +-------------+-------------+-------------+---------+
                                                |                           |
                                                |            +--------------+--------------+
                                                |            |  In-Context Reflection Loop |
                                                |            |  - UCB1 Strategy Memory     |
                                                |            |  - Near-Miss Diagnostics    |
                                                |            |  - Mutation & Search        |
                                                |            +--------------+--------------+
                                                v                           v
                                  +---------------------------------------------------+
                                  |             Untrusted Document Slot               |
                                  |             Template + {{INJECTION_SLOT}}         |
                                  +-------------------------+-------------------------+
                                                            |
                                                            v
                                  +---------------------------------------------------+
                                  |             Defender Agent Pipeline               |
                                  |       (None vs. Basic System Warning)             |
                                  +-------------------------+-------------------------+
                                                            |
                                                            v
                                  +---------------------------------------------------+
                                  |               Groq LLM Execution                  |
                                  | - Rate Limiter (25 RPM)   - Disk Cache (SHA-256)  |
                                  | - Exp. Backoff (429/5xx)  - Deterministic Mock    |
                                  +-------------------------+-------------------------+
                                                            |
                                                            v
                                  +---------------------------------------------------+
                                  |                 Dual Judge Engine                 |
                                  | - Primary Deterministic Verifier (Canary/Tools)   |
                                  | - Optional Secondary LLM Judge                    |
                                  +-------------------------+-------------------------+
                                                            |
                                                            v
                                  +---------------------------------------------------+
                                  |             Evaluation & Comparison Store         |
                                  | - Human vs Auto ASR@1 & ASR@N (Matching Budget N) |
                                  | - Cumulative Breakthrough Curves (1..N)           |
                                  | - Semantic Attack Diversity (TF-IDF Clustering)   |
                                  +-------------------------+-------------------------+
                                                            |
                                                            v
                                  +---------------------------------------------------+
                                  |             Presentation SPA Dashboard            |
                                  | Live Attack Stream | Gallery | Replay | Export    |
                                  +---------------------------------------------------+
```

---

## 📂 Project Directory Structure

```text
redloop/
├── backend/
│   ├── __init__.py
│   ├── config.py              # Centralized models, budgets, paths, rate limits
│   ├── db.py                  # SQLite schema, WAL mode, strategy_memory & run_events tables
│   ├── llm.py                 # Groq client: rate limiter, retry, cache, mock engine
│   ├── scenarios.py           # 10 scenarios across 5 families, canaries, tools, get_public_view()
│   ├── defender.py            # Pluggable defense pipeline (None, BasicSystemWarning)
│   ├── judge.py               # Deterministic primary judge & secondary LLM judge
│   ├── baseline.py            # 34 human templates across 9 categories
│   ├── seed.py                # Pre-runs baseline and auto campaign for instant demo data
│   ├── main.py                # FastAPI app, REST APIs, static file serving
│   ├── attacker/              # --- PART 2: AUTOMATED RED-TEAMER ---
│   │   ├── __init__.py
│   │   ├── attacker.py        # RedTeamer: black-box search, reflection loop, near-miss detection
│   │   ├── strategy_memory.py # Multi-armed bandit (UCB1 & Epsilon-Greedy) strategy memory
│   │   └── json_utils.py      # Resilient JSON repair parser for structured outputs
│   ├── eval_auto.py           # Comparison engine: fair budget matching, TF-IDF clustering, export
│   └── tests/
│       ├── test_judge.py
│       ├── test_scenarios.py
│       ├── test_cache.py
│       ├── test_rate_limiter.py
│       ├── test_api.py
│       └── test_attacker.py   # Part 2 unit and integration tests
├── frontend/
│   ├── index.html             # Examiner dashboard with 7 functional tabs
│   ├── style.css              # Dark theme designed for projector presentation
│   └── app.js                 # Live event stream, comparison charts, replay, export
├── data/
│   ├── cache/                 # Persistent on-disk LLM response hashes
│   └── redloop.db             # SQLite database
├── PROGRESS.md                # Real-time development progress tracker
├── pytest.ini
├── requirements.txt
└── README.md
```

---

## ⚙️ Setup & Installation

### 1. Prerequisites
- Python 3.11+
- Git

### 2. Virtual Environment Setup
```bash
git clone <repo-url> redloop
cd redloop

python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Environment Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Configure settings in `.env`:
```ini
# Optional: Get a free API key at https://console.groq.com
GROQ_API_KEY=gsk_your_groq_api_key_here

# LLM Mock Mode:
# When true (or if GROQ_API_KEY is empty), RedLoop runs 100% offline with deterministic responses.
MOCK_LLM=true

# Groq Rate Limit (Free tier default: 25 requests/min)
RATE_LIMIT_RPM=25
```

### 4. Seed Database (Instant Examiner Dashboard)
Pre-populates the database with both the human baseline benchmark (180 attempts) and an automated red-team campaign so charts and replay are ready immediately:
```bash
python -m backend.seed
```

### 5. Launch the Server
```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```
Open **[http://localhost:8000](http://localhost:8000)** in your browser.

---

## 🧪 Running Automated Tests

Run the full pytest suite (24 tests covering judge logic, scenarios, black-box isolation, JSON repair parsing, strategy bandit memory, early stopping, diversity clustering, and APIs):

```bash
pytest backend/tests -v
```

All 24 tests pass with zero warnings or errors.

---

## 🎤 7-Minute Examiner Presentation Walkthrough (Review 2)

### 1. Research Motivation & Architecture (1:00 min)
- Navigate to the **"Overview"** tab.
- Explain the motivation: Indirect prompt injection is OWASP's #1 LLM vulnerability.
- Explain the connection to OpenAI's *GPT-Red*:
  - OpenAI used PPO reinforcement learning to train an adversarial attacker model.
  - In RedLoop Part 2, we implement **In-Context Search + Multi-Round Reflection + UCB Strategy Memory**, achieving adaptive optimization without requiring large GPU clusters.
- Show the **Architecture Pipeline Diagram**:
  - Point out that **Part 1 (Testbed & Baseline)** and **Part 2 (In-Context Red-Teamer)** are now fully active.
  - Part 3 (Adversarial Self-Play Hardening) is the upcoming capstone extension.

### 2. Black-Box Isolation & Safety Philosophy (1:00 min)
- Switch to the **"Scenarios"** tab.
- Explain the strict security isolation:
  - The attacker model only receives `Scenario.get_public_view()`.
  - The defender's system instructions and canary secrets (e.g. `CANARY-7F3A9`) are strictly withheld from the attacker.
  - All side-effects (e.g. financial refunds, email sending) are simulated and sandboxed.

### 3. Live Automated Red-Teamer & Reflection in Action (2:00 min)
- Switch to the **"Auto Red-Team (Live)"** tab.
- Click **"▶ Replay Last Campaign"** (or click **"🚀 Start Auto Campaign"**):
- Walk examiners through what is happening in real time:
  - **Round 0**: The attacker deploys candidates selected by the UCB strategy memory bandit.
  - Show the live cards streaming in with strategy badges, injection snippets, and defender response snippets.
  - Point out the distinct purple **"Round 1 Reflection Separator Card"**:
    *e.g. "Learned: Direct authority commands were blocked by tag isolation. Mutating toward delimiter breakout combined with emergency task continuation."*
  - Show how the reflection loop enables the model to mutate its attack and achieve a breakthrough within the query budget!

### 4. Human Baseline vs. Automated Red-Teamer Benchmark (1:30 min)
- Switch to the **"Human vs Auto"** tab.
- Point out the key findings from our empirical evaluation:
  - **Fair Comparison**: Both human baseline and automated attacker are evaluated with the identical query budget $N$ per scenario.
  - **Grouped Bar Chart**: Shows the ASR comparison across models. Point out that automated search achieves significantly higher ASR@N than static human templates.
  - **Cumulative Success Curve (Attempts 1 to N)**: Illustrates how in-context reflection accelerates vulnerability discovery compared to random human template sampling.
  - **Mean Attempts to Success**: Measures how quickly the attacker discovers a bypass (typically 1.2–2.5 attempts).

### 5. Attack Gallery & Semantic Diversity (1:00 min)
- Switch to the **"Attack Gallery"** tab.
- Filter confirmed breakthroughs by strategy (e.g. `delimiter_breakout`, `fake_system_message`, `roleplay`).
- Point out the **Semantic Attack Diversity (TF-IDF Clustering)** card:
  - Demonstrates that the red-teamer generates genuinely diverse attack vectors rather than repeating minor variations of the same prompt.
- Show the **"⬇ Export JSON"** and **"⬇ Export CSV"** buttons allowing examiners to export all campaign traces for external auditing.

### 6. Summary & Roadmap to Part 3 (0:30 min)
- Summarize Part 2 accomplishments: Autonomous red-teaming, in-context reflection, strategy memory bandit, and fair empirical outperformance over human baselines.
- Highlight Part 3: Using these discovered attacks to perform self-play hardening (DPO fine-tuning / defense distillation) to harden defenders against future injection campaigns.

---

## ⚠️ Known Limitations

1. **In-Context Search Horizon**: The automated attacker searches up to an attempt budget of $N$ (default 6–8 attempts). While highly effective for targeted scenarios, it cannot explore indefinitely due to LLM context window limits and rate budgets.
2. **Rate Limits on Free Tier**: The official Groq free tier allows 25 requests/minute. The built-in token-bucket rate limiter paces live requests automatically; for full-batch testing, the offline deterministic mock mode enables zero-delay benchmarking.
3. **Synthetic Scope**: All scenarios and tools are designed for safety evaluation and are completely synthetic; no code targets external systems.
