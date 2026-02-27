# SOCrates
> *Know your threats.*

## The Problem

Security Operations Centers are drowning in alerts.

A typical enterprise SOC receives thousands of alerts per day. Tier 1 analysts spend most of their shift manually triaging noise — low-signal alerts that turn out to be nothing. By the time a real threat surfaces, analyst attention is exhausted.

The result:
- **Alert fatigue** — analysts stop trusting the system
- **Slow MTTD** — real attacks go undetected for hours or days
- **High turnover** — junior analysts burn out fast

## The Solution

SOCrates is an **automated threat triage engine** for SOC analysts.

It analyzes web proxy logs through a three-tier detection pipeline and returns a ranked alert queue — the most critical threats at the top, with plain-English explanations and recommended actions so an analyst can make a triage decision in under 60 seconds.

## Who It's For

**Tier 1 SOC Analysts** — doing alert triage, need fast confident decisions  
**Tier 2 SOC Analysts** — deeper investigation, need synthesized context fast  
**SOC Managers** — need their team focused on real threats, not noise

## Success Metrics

SOCrates is designed to move the needle on the metrics SOC teams actually care about:

**MTTD — Mean Time to Detect**  
How long between an attack starting and the SOC knowing about it.
SOCrates reduces MTTD by surfacing high-confidence threats at the top of the queue instead of burying them in thousands of undifferentiated alerts.

**MTTR — Mean Time to Respond**  
How long between detection and containment action taken.
SOCrates reduces MTTR by giving the analyst everything they need in one place — what happened, why it's suspicious, and exactly what to do next.

**Alert Fatigue Index**  
The ratio of true positives to total alerts reviewed.
SOCrates optimizes this directly — Tier 1 runs at 100% precision, meaning every rule-based flag is a real threat. Tier 2 adds recall at the cost of some false positives, which are clearly labeled for analyst review.

**Analyst Ramp Time**  
How long it takes a junior analyst to triage with the confidence of a senior.
SOCrates compresses expert pattern recognition into the pipeline — the Tier 3 explanation tells a junior analyst exactly what a 10-year veteran would notice.

> **Note:** These metrics are design goals measured against synthetic data today.
> See [Evaluation](#evaluation) for how to instrument and measure them against
> real SOC data in production.

---

## How It Works

```
CSV Upload
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  TIER 1 — Rule Based Detection                      │
│  Goal: Catch everything obvious (optimize recall)   │
│                                                     │
│  · Z-score on request count                         │
│  · Interval threshold (avg + jitter)                │
│  · IQR on request intervals                         │
│                                                     │
│  Precision: 100%  Recall: 67%  F1: 80%              │
└─────────────────────┬───────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────┐
│  TIER 2 — ML Detection (Isolation Forest)           │
│  Goal: Catch what rules miss (improve recall)       │
│                                                     │
│  Features per (src_ip, domain) pair:                │
│  · cv              — interval regularity            │
│  · avg_interval_s  — beacon frequency               │
│  · bytes_sent_cv   — payload consistency            │
│  · unique_paths    — path diversity                 │
│  · night_ratio     — 24/7 activity pattern          │
│  · request_count   — volume                         │
│                                                     │
│  Catches subtle beacons Tier 1 misses               │
└─────────────────────┬───────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────┐
│  TIER 3 — LLM Agent (Claude API / Mock)             │
│  Goal: Plain-English explanation for the analyst    │
│                                                     │
│  · Threat summary                                   │
│  · What happened                                    │
│  · Why it's suspicious                              │
│  · Recommended action                               │
└─────────────────────┬───────────────────────────────┘
                      │
                      ▼
            Ranked Alert Queue
         (<10 seconds on 33k logs)
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 15 (React + TypeScript + Tailwind) |
| Backend | FastAPI (Python 3.11) |
| ML | scikit-learn Isolation Forest |
| LLM | Anthropic Claude API (mock available) |
| Package manager | uv |
| Auth | JWT (python-jose) |

---

## Setup

### Prerequisites
- Python 3.11+
- Node.js 18+
- uv (`curl -LsSf https://astral.sh/uv/install.sh | sh`)

### Backend

```bash
cd backend
uv venv .venv --python 3.11
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Frontend

```bash
cd frontend
npm install
```

---
## Running
**Data Generation** :
```bash
cd backend
python -m socrates.data_generator.generate
python -m socrates.ml.train
```

**Backend** (terminal 1):
```bash
cd backend
source .venv/bin/activate
uvicorn socrates.main:app --reload --port 8000
```

**Frontend** (terminal 2):
```bash
cd frontend
npm run dev
```

Open `http://localhost:3000` and log in with:
```
username: analyst
password: socrates123
```

Upload `data/synthetic_logs.csv` to see the full pipeline in action.

---

## Evaluation

### Current Detection Metrics (Synthetic Data)

```bash
cd backend
python -m socrates.evaluation.evaluate_tier1
```
```bash
cd backend
python -m socrates.evaluation.evaluate_tier2
```

### Running Tiers

# Tier 1
./scripts/run_tier1.sh

# Tier 2
./scripts/run_tier2.sh

# Full pipeline
./scripts/run_pipeline.sh

