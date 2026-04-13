# 🛡 LLM-Based SQL Injection & Insider Threat Detection System

A final-year BTech research project implementing a hybrid AI-powered database security system.

## Architecture

```
SQL Query Input
      │
      ▼
┌─────────────────────┐
│   Rule Engine       │ ── high-confidence match ──→ Risk Aggregator
└──────────┬──────────┘
           │ no match / low confidence
           ▼
┌─────────────────────┐
│  LLM Classifier     │ ── Groq / LLaMA 3.1 ────→ Risk Aggregator
│  (Groq API)         │
└─────────────────────┘
                                    │
                          ┌─────────▼──────────┐
                          │  Risk Aggregator   │ ← role-aware multiplier
                          └─────────┬──────────┘
                                    │
                             Security Log DB
```

## Tech Stack

| Layer     | Technology                  |
|-----------|-----------------------------|
| Backend   | FastAPI + Python 3.11       |
| AI        | Groq API (LLaMA 3.1-8b)    |
| Database  | SQLite (aiosqlite)          |
| Frontend  | HTML + Bootstrap + Chart.js |

## Project Structure

```
sql-llm-security/
├── backend/
│   ├── main.py              # FastAPI entry point
│   ├── config.py            # Settings from .env
│   ├── detection/
│   │   ├── engine.py        # Hybrid orchestrator
│   │   ├── rule_engine.py   # 30+ deterministic rules
│   │   ├── llm_classifier.py# Groq LLM few-shot classifier
│   │   └── risk_scorer.py   # Role-aware risk aggregation
│   ├── database/
│   │   ├── company_db.py    # Dummy company DB (auto-created)
│   │   ├── security_db.py   # SIEM log DB (auto-created)
│   │   └── seed.py          # Seed dummy data
│   └── routers/
│       ├── query.py         # POST /api/query/analyze
│       ├── dashboard.py     # GET /api/dashboard/*
│       └── logs.py          # GET /api/logs
├── frontend/
│   ├── index.html           # Query analyzer
│   ├── dashboard.html       # Security dashboard
│   └── logs.html            # Audit log viewer
├── evaluation/
│   ├── metrics.py           # Classification metrics
│   └── run_validation.py    # Batch validation on CSV
└── tests/
    ├── test_rule_engine.py  # Unit tests (no server needed)
    └── test_api.py          # API smoke tests (server needed)
```

---

## Setup & Run

### 1. Clone / navigate to project

```bash
cd sql-llm-security
```

### 2. Create virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure `.env`

Edit `.env` and add your Groq API key:

```env
GROQ_API_KEY=gsk_your_actual_key_here
GROQ_MODEL=llama-3.1-8b-instant
APP_ENV=development
APP_PORT=8000
COMPANY_DB_PATH=./data/company.db
SECURITY_DB_PATH=./data/security.db
LLM_TIMEOUT_SECONDS=15
RISK_FLAG_THRESHOLD=0.6
```

Get a free Groq API key at: https://console.groq.com

### 5. Run the server

```bash
uvicorn backend.main:app --reload --port 8000
```

On first run, the system will automatically:
- Create `data/company.db` with users, employees, orders, transactions tables
- Seed it with 6 demo users and records
- Create `data/security.db` with query_logs, detection_stats, role_stats tables

### 6. Open in browser

| Page             | URL                          |
|------------------|------------------------------|
| Query Analyzer   | http://localhost:8000        |
| Dashboard        | http://localhost:8000/dashboard |
| Audit Logs       | http://localhost:8000/logs   |
| API Docs         | http://localhost:8000/docs   |

---

## Running Tests

### Rule engine unit tests (no server required)

```bash
python tests/test_rule_engine.py
```

### API smoke tests (server must be running)

```bash
python tests/test_api.py
```

### Batch validation on dataset

```bash
python evaluation/run_validation.py
```

---

## API Endpoints

| Method | Endpoint                      | Description                    |
|--------|-------------------------------|--------------------------------|
| POST   | /api/query/analyze            | Submit query for detection     |
| GET    | /api/dashboard/stats          | Aggregate counts               |
| GET    | /api/dashboard/timeline       | Hourly attack counts (24h)     |
| GET    | /api/dashboard/threat-distribution | Donut chart data          |
| GET    | /api/dashboard/heatmap        | Role × attack type matrix      |
| GET    | /api/dashboard/recent-flags   | Latest flagged queries         |
| GET    | /api/dashboard/role-stats     | Per-role statistics            |
| GET    | /api/logs                     | Paginated audit log            |
| GET    | /api/logs/{id}                | Single log entry detail        |
| GET    | /health                       | Health check                   |

---

## Detection Categories

| Label    | Description                                      |
|----------|--------------------------------------------------|
| benign   | Normal business query, no threat detected        |
| sqli     | SQL Injection attack (18 pattern types)          |
| insider  | Insider threat / data misuse (15 pattern types)  |

## Risk Score

| Range       | Severity | Color  |
|-------------|----------|--------|
| 0.00 – 0.39 | Low      | 🟢 Green  |
| 0.40 – 0.69 | Medium   | 🟠 Orange |
| 0.70 – 1.00 | High     | 🔴 Red    |

## Role Multipliers

| Role     | Multiplier | Reason                               |
|----------|------------|--------------------------------------|
| outsider | ×1.35      | External access is inherently riskier |
| employee | ×1.00      | Baseline                             |
| admin    | ×0.75      | Legitimate elevated access           |

---

## Validation Results (Current)

| Label    | Precision | Recall | F1    |
|----------|-----------|--------|-------|
| benign   | 1.00      | 0.69   | 0.82  |
| sqli     | 1.00      | 0.81   | 0.89  |
| insider  | 0.70      | 1.00   | 0.82  |

**Overall Accuracy: 85%**