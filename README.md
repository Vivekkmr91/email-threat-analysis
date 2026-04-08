# 🛡️ Multi-Agent Email Threat Analysis System

> Production-grade email security platform powered by LangGraph multi-agent AI, Neo4j graph intelligence, and deep learning threat detection.

[![CI/CD Pipeline](https://github.com/Vivekkmr91/email-threat-analysis/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/Vivekkmr91/email-threat-analysis/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![React 18](https://img.shields.io/badge/react-18-61dafb.svg)](https://reactjs.org)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.2-green.svg)](https://langchain-ai.github.io/langgraph/)
[![Neo4j](https://img.shields.io/badge/Neo4j-5.x-008CC1.svg)](https://neo4j.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    EMAIL THREAT ANALYSIS SYSTEM                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  📧 Email Sources                                                 │
│     Gmail API │ Microsoft 365 │ SMTP │ Direct API                │
│                          │                                        │
│  📦 Ingestion Layer                                               │
│     Email Parser (RFC 2822/MIME) → Structured Components         │
│                          │                                        │
│  🤖 LangGraph Orchestration (Parallel Agents)                    │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  📝 Text Agent  │  🔍 Metadata Agent  │  🌐 Enrichment Agent│  │
│  │  (LLM Analysis) │  (SPF/DKIM/Headers) │  (URLs/QR/Attach)  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                          │                                        │
│  🕸️ Graph Agent (Neo4j) → Campaign Correlation                   │
│                          │                                        │
│  ⚖️ Decision Agent → Weighted MCDA Scoring                       │
│                          │                                        │
│  📊 Output Layer                                                  │
│     Verdict │ Reasoning Trace │ SOAR Integration                 │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

## 🔍 Threat Detection Capabilities

| Threat Type | Detection Method | Agent |
|------------|-----------------|-------|
| **Business Email Compromise (BEC)** | Wire transfer patterns, exec impersonation | Text + Graph |
| **Phishing** | URL lookalike detection, credential harvest patterns | Enrichment + Metadata |
| **LLM-Generated Phishing** | AI text fingerprinting, linguistic analysis | Text (LLM) |
| **QR Code Phishing (Quishing)** | QR code extraction from images/PDFs | Enrichment |
| **Adversary-in-the-Middle (AiTM)** | Proxy URL patterns, credential redirect detection | Enrichment |
| **Living-off-the-Land (LotL)** | Legitimate service abuse detection | Enrichment |
| **Malware Attachments** | File hash, VirusTotal, extension analysis | Enrichment |
| **Spoofing/Impersonation** | SPF/DKIM/DMARC, display name analysis | Metadata |
| **Campaign Correlation** | Graph relationship mapping | Graph (Neo4j) |

## 🚀 Quick Start

**Two deployment options:**
- **🐳 Docker (Recommended)**: One-command deployment, zero config hassle
- **💻 Local Development**: Full control, hot reload, ideal for development → [See Local Development Guide](#-local-development-without-docker)

### Docker Deployment (Production-Ready)

#### Prerequisites
- **Docker Desktop 4.x** (Windows/Mac) or **Docker Engine 24+** (Linux)
- Docker Desktop must be **running** before executing any `docker compose` commands
- 4 GB RAM minimum (8 GB recommended with Neo4j)
- Optional: OpenAI API key, VirusTotal API key, or OpenRouter API key (free)

### 1. Clone & Configure
```bash
git clone https://github.com/Vivekkmr91/email-threat-analysis.git
cd email-threat-analysis

# Configure environment (copy the example and optionally add API keys)
cp .env.example .env
```

**Optional: Add LLM API key** (edit `.env`):
```env
# Option 1: OpenRouter (FREE models available - recommended for testing)
OPENROUTER_API_KEY=sk-or-v1-your-key-from-openrouter.ai
OPENROUTER_MODEL=google/gemma-3-27b-it:free

# Option 2: OpenAI (requires paid API key)
# OPENAI_API_KEY=sk-your-openai-key-here
# OPENAI_MODEL=gpt-4o-mini
```
Get free OpenRouter key at: https://openrouter.ai/keys

### 2. Start All Services
```bash
docker compose up -d
```

First run pulls/builds images (~3–5 min). Subsequent starts are fast.

### 3. Verify Everything Is Up
```bash
docker compose ps          # all services should show "healthy" or "running"
docker compose logs -f     # tail logs (Ctrl+C to exit)
```

### 4. Access the System
| Service | URL | Credentials |
|---------|-----|-------------|
| **SOC Dashboard** | http://localhost:8080 | — |
| **API Docs** | http://localhost:8000/redoc | — |
| **Neo4j Browser** | http://localhost:7474 | neo4j / emailthreat123 |
| **Grafana** | http://localhost:3001 | admin / admin123 |
| **Prometheus** | http://localhost:9090 | — |

### 5. Analyze Your First Email
```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo-api-key-change-in-production" \
  -d '{
    "subject": "URGENT: Verify Your Account",
    "sender": "security@paypa1.com",
    "body_text": "Click here to verify: https://secure.paypa1-verify.xyz/login",
    "headers": {
      "Authentication-Results": "spf=fail; dkim=fail",
      "Reply-To": "attacker@evil.tk"
    }
  }'
```

### 6. ML-only fast prediction
```bash
curl -X POST http://localhost:8000/api/v1/ml/predict \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo-api-key-change-in-production" \
  -d '{
    "subject": "Your invoice is overdue",
    "body_text": "Please wire $25,000 to the new account immediately.",
    "sender": "cfo@company-fake.com"
  }'
```

---

## 💻 Local Development (Without Docker)

This project is fully compatible with local development without Docker. The code follows 12-factor app principles and reads all configuration from environment variables.

### Prerequisites

- **Python 3.11+** ([python.org](https://python.org))
- **Node.js 18+** and npm ([nodejs.org](https://nodejs.org))
- **PostgreSQL 15+** ([postgresql.org](https://www.postgresql.org/download/))
- **Redis 7+** ([redis.io](https://redis.io/download/))
- **Neo4j Desktop** or Community Edition 5.x ([neo4j.com](https://neo4j.com/download/))
- **Git** for cloning the repo

### Step 1: Install System Dependencies

#### Windows
```powershell
# Install PostgreSQL 15
# Download installer from https://www.postgresql.org/download/windows/
# During installation, remember the postgres password

# Install Redis (via WSL2 or Memurai for native Windows)
# Option A: WSL2 + Ubuntu
wsl --install
wsl -d Ubuntu
sudo apt update && sudo apt install redis-server -y
sudo service redis-server start

# Option B: Memurai (Windows native Redis)
# Download from https://www.memurai.com/get-memurai

# Install Neo4j Desktop
# Download from https://neo4j.com/download/
# Create a new database with password: emailthreat123
```

#### Linux (Ubuntu/Debian)
```bash
# PostgreSQL
sudo apt update
sudo apt install postgresql postgresql-contrib -y
sudo systemctl start postgresql

# Redis
sudo apt install redis-server -y
sudo systemctl start redis-server

# Neo4j (Community Edition)
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable latest' | sudo tee /etc/apt/sources.list.d/neo4j.list
sudo apt update
sudo apt install neo4j -y
sudo systemctl start neo4j
```

#### macOS
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# PostgreSQL
brew install postgresql@15
brew services start postgresql@15

# Redis
brew install redis
brew services start redis

# Neo4j
brew install --cask neo4j
```

### Step 2: Configure Databases

#### PostgreSQL Setup
```bash
# Create database and user
psql -U postgres
```
```sql
CREATE DATABASE emailthreat;
CREATE USER emailthreat WITH PASSWORD 'emailthreat';
GRANT ALL PRIVILEGES ON DATABASE emailthreat TO emailthreat;
\q
```

#### Neo4j Setup
```bash
# If using Neo4j Desktop:
# 1. Create a new project
# 2. Add a local database
# 3. Set password to: emailthreat123
# 4. Start the database

# If using Neo4j Community (Linux/Mac):
sudo neo4j-admin set-initial-password emailthreat123
```

### Step 3: Clone & Configure Backend

```bash
git clone https://github.com/Vivekkmr91/email-threat-analysis.git
cd email-threat-analysis

# Create backend .env file
cp .env.example .env
```

Edit `.env` with **localhost** connection strings:
```env
# Core Settings
DEBUG=true
ENVIRONMENT=development
SECRET_KEY=your-dev-secret-key-here
ALLOWED_API_KEYS=["local-dev-api-key"]
ALLOWED_ORIGINS=["http://localhost:3000","http://localhost:8080"]

# Database URLs (localhost for local dev)
DATABASE_URL=postgresql+asyncpg://emailthreat:emailthreat@localhost:5432/emailthreat
REDIS_URL=redis://localhost:6379/0
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=emailthreat123

# Celery (using Redis)
CELERY_BROKER_URL=redis://localhost:6379/1
CELERY_RESULT_BACKEND=redis://localhost:6379/2

# LLM Provider (choose one)
# Option 1: OpenRouter (FREE models available)
OPENROUTER_API_KEY=sk-or-v1-your-openrouter-key-here
OPENROUTER_MODEL=google/gemma-3-27b-it:free

# Option 2: OpenAI (requires paid API key)
# OPENAI_API_KEY=sk-your-openai-key-here
# OPENAI_MODEL=gpt-4o-mini

# Optional: External APIs
VIRUSTOTAL_API_KEY=your-virustotal-key
PHISHTANK_API_KEY=your-phishtank-key

# Risk Thresholds
HIGH_RISK_THRESHOLD=0.75
MEDIUM_RISK_THRESHOLD=0.45
ANALYSIS_TIMEOUT_SECONDS=30
RATE_LIMIT_PER_MINUTE=60

# ML Model Settings
ML_MODEL_DIR=./ml_models
ML_PHISHING_THRESHOLD=0.5
ML_LLM_DETECT_THRESHOLD=0.5

# RLHF Training
RLHF_MIN_EXAMPLES=10
RLHF_TRAIN_INTERVAL_HOURS=6
RLHF_LEARNING_RATE=0.0005
RLHF_EPOCHS=15
```

### Step 4: Install Backend Dependencies

```bash
cd backend
python -m venv venv

# Activate virtual environment
# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Windows CMD:
.\venv\Scripts\activate.bat
# Linux/Mac:
source venv/bin/activate

# Install packages
pip install --upgrade pip
pip install -r requirements.txt

# Create ML models directory
mkdir -p ml_models
```

### Step 5: Initialize Database

```bash
# Still in backend/ with venv activated
# The database tables will be created automatically on first run
# Or manually trigger with:
python -c "from app.core.database import init_db, init_neo4j_schema; import asyncio; asyncio.run(init_db()); asyncio.run(init_neo4j_schema())"
```

### Step 6: Start Backend Services

Open **3 terminal windows** (all with activated venv in `backend/`):

**Terminal 1: FastAPI Server**
```bash
cd backend
source venv/bin/activate  # or .\venv\Scripts\Activate.ps1 on Windows
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2: Celery Worker**
```bash
cd backend
source venv/bin/activate
celery -A app.workers.celery_app worker --loglevel=info --concurrency=2 --queues=celery
```

**Terminal 3: Celery Beat (scheduler)**
```bash
cd backend
source venv/bin/activate
celery -A app.workers.celery_app beat --loglevel=info
```

### Step 7: Configure Frontend

```bash
# New terminal window
cd frontend

# Create local environment file
cat > .env.local << EOF
REACT_APP_API_URL=http://localhost:8000/api/v1
REACT_APP_API_KEY=local-dev-api-key
EOF

# Install dependencies
npm install --legacy-peer-deps
```

### Step 8: Start Frontend Dev Server

```bash
# Still in frontend/
npm run dev
```

The Vite dev server will start on **http://localhost:3000**

### Step 9: Verify Everything Works

#### Health Check
```bash
curl http://localhost:8000/api/v1/health
```
Expected output:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "services": {
    "api": "healthy",
    "redis": "healthy",
    "neo4j": "healthy"
  },
  "timestamp": "2026-04-08T..."
}
```

#### Test Email Analysis
```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: local-dev-api-key" \
  -d '{
    "subject": "URGENT: Verify Your PayPal Account",
    "sender": "security@paypa1-verify.com",
    "recipients": ["victim@company.com"],
    "body_text": "Your account has been suspended. Click here immediately: https://paypa1-secure.xyz/verify",
    "headers": {
      "SPF": "fail",
      "DKIM-Signature": "none"
    },
    "source": "api"
  }'
```

### Local Development URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| **Frontend Dashboard** | http://localhost:3000 | — |
| **Backend API** | http://localhost:8000 | — |
| **API Docs (ReDoc)** | http://localhost:8000/redoc | — |
| **Swagger UI** | http://localhost:8000/docs | — |
| **Neo4j Browser** | http://localhost:7474 | neo4j / emailthreat123 |
| **PostgreSQL** | localhost:5432 | emailthreat / emailthreat |
| **Redis** | localhost:6379 | (no auth in dev) |

### Running Tests Locally

```bash
# Backend tests (with venv activated)
cd backend
pytest tests/ -v --cov=app --cov-report=html
# View coverage report at: htmlcov/index.html

# Frontend tests
cd frontend
npm test

# Type checking (frontend)
npm run type-check
```

### Stopping Services

```bash
# Stop each terminal with Ctrl+C
# Deactivate Python virtual environment:
deactivate

# Stop system services (if needed)
# Windows (Memurai):
net stop Memurai

# Linux:
sudo systemctl stop postgresql redis-server neo4j

# macOS:
brew services stop postgresql@15 redis neo4j
```

### Key Differences: Docker vs. Local

| Aspect | Docker (Production) | Local Development |
|--------|---------------------|-------------------|
| **Database URLs** | Service names (`postgres:5432`) | `localhost:5432` |
| **Environment** | Set to `production` | Set to `development` |
| **API Key** | Strong key required | `local-dev-api-key` |
| **Debug Mode** | `DEBUG=false` | `DEBUG=true` |
| **Volumes** | Named Docker volumes | Local directories |
| **Networking** | Bridge network | Host network (localhost) |
| **Process Management** | Docker handles restart | Manual terminal management |
| **Hot Reload** | Requires rebuild | Automatic (uvicorn --reload, Vite HMR) |

### Why No Code Changes Are Needed

✅ **Zero code modifications** required to switch between Docker and local development:

1. **Environment-based configuration**: All connection strings, API keys, and settings are read from environment variables via `pydantic-settings`.

2. **CORS origins**: `ALLOWED_ORIGINS` in `.env` accepts both Docker hostnames and localhost URLs.

3. **Database abstraction**: SQLAlchemy and Neo4j drivers accept any URI format (Docker service names or localhost).

4. **Frontend proxy**: Vite's `proxy` config in `vite.config.ts` routes `/api` requests to the backend URL specified in `REACT_APP_API_URL`.

5. **API authentication**: The same `X-API-Key` header mechanism works in both environments; just use different keys (strong for production, simple for dev).

6. **LLM provider flexibility**: The `get_llm()` factory function detects available API keys (`OPENROUTER_API_KEY` or `OPENAI_API_KEY`) and configures the appropriate provider automatically.

### Recommended Free LLM Models (via OpenRouter)

Get a free API key at [openrouter.ai](https://openrouter.ai/):

```env
OPENROUTER_API_KEY=sk-or-v1-your-key-here
OPENROUTER_MODEL=google/gemma-3-27b-it:free
```

**Top Free Models** (no cost per request):
- `google/gemma-3-27b-it:free` (default, 27B parameters, excellent reasoning)
- `google/gemma-3-12b-it:free` (smaller, faster)
- `thudm/glm-z1-32b:free` (Chinese NLP specialist, good for phishing)
- `meta-llama/llama-4-scout:free` (Meta's latest)
- `deepseek/deepseek-r1:free` (reasoning-optimized)
- `mistralai/mistral-7b-instruct:free` (7B, very fast)
- `qwen/qwen3-235b-a22b:free` (235B, strongest free model)

To switch models, just change `OPENROUTER_MODEL` in `.env` and restart the backend — **no code changes**.

---

## 🔧 Troubleshooting

### Docker Desktop not running (Windows/Mac)
```
error during connect: open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified
```
**Fix:** Start Docker Desktop and wait for the whale icon in the system tray to show "Docker Desktop is running", then re-run `docker compose up -d`.

### `version` attribute warning
```
the attribute `version` is obsolete, it will be ignored
```
**This is just a warning, not an error.** The `version` key has been removed from `docker-compose.yml` in this repo.

### Port already in use
```bash
# Find and kill the process using port 8000 (or 80, 5432, 6379, 7474, 7687)
# Windows
netstat -ano | findstr :8000
taskkill /PID <PID> /F

# Linux/Mac
lsof -i :8000 | awk 'NR>1 {print $2}' | xargs kill -9
```

### Backend unhealthy / keeps restarting
```bash
docker compose logs backend   # see the actual error
docker compose logs postgres  # check DB is up
```

### Reset everything (fresh start)
```bash
docker compose down -v        # removes containers AND volumes
docker compose up -d          # start fresh
```

## 📁 Project Structure

```
email-threat-analysis/
├── backend/                    # FastAPI Python Backend
│   ├── app/
│   │   ├── agents/            # Multi-agent implementation
│   │   │   ├── orchestrator.py   # LangGraph pipeline
│   │   │   ├── email_parser.py   # Email ingestion & parsing
│   │   │   ├── text_agent.py     # Text/LLM analysis agent
│   │   │   ├── metadata_agent.py # Header/authentication agent
│   │   │   ├── enrichment_agent.py # URL/attachment agent
│   │   │   ├── graph_agent.py    # Neo4j correlation agent
│   │   │   ├── decision_agent.py # MCDA verdict agent
│   │   │   └── state.py          # LangGraph shared state
│   │   ├── api/
│   │   │   ├── routes.py         # FastAPI endpoints
│   │   │   └── middleware.py     # Auth, rate limiting, logging
│   │   ├── core/
│   │   │   ├── config.py         # Pydantic settings
│   │   │   ├── database.py       # PostgreSQL + Neo4j setup
│   │   │   └── logging.py        # Structured logging
│   │   ├── models/
│   │   │   ├── email.py          # SQLAlchemy ORM models
│   │   │   └── schemas.py        # Pydantic API schemas
│   │   └── main.py               # FastAPI app entry point
│   ├── tests/                    # Unit & integration tests
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/                   # React SOC Dashboard
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx     # SOC overview with charts
│   │   │   ├── AnalyzeEmail.jsx  # Email submission + results
│   │   │   ├── AnalysisHistory.jsx # Historical analysis table
│   │   │   └── ThreatGraph.jsx   # Neo4j graph visualization
│   │   ├── components/
│   │   │   ├── VerdictBadge.jsx  # Threat verdict display
│   │   │   ├── ScoreGauge.jsx    # Circular threat score
│   │   │   ├── AgentCard.jsx     # Per-agent findings
│   │   │   └── Sidebar.jsx       # Navigation
│   │   └── utils/
│   │       ├── api.js            # Axios API client
│   │       └── helpers.js        # Utility functions
│   ├── Dockerfile
│   └── nginx.conf
├── monitoring/
│   ├── prometheus.yml            # Metrics scraping config
│   └── grafana/                  # Dashboards & datasources
├── scripts/
│   └── init_postgres.sql        # Database initialization
├── .github/workflows/
│   └── ci-cd.yml                # GitHub Actions CI/CD
├── docker-compose.yml           # Full stack orchestration
└── .env.example                 # Environment template
```

## 🔌 API Reference

### Analyze Email
```http
POST /api/v1/analyze
Content-Type: application/json

{
  "subject": "Invoice Payment Required",
  "sender": "ceo@company.com",
  "recipients": ["finance@company.com"],
  "body_text": "...",
  "headers": {},
  "source": "api"
}
```

**Response:**
```json
{
  "analysis_id": "uuid",
  "verdict": "malicious",
  "threat_score": 0.87,
  "threat_categories": ["business_email_compromise", "phishing"],
  "agent_findings": [
    {
      "agent_name": "text_analysis_agent",
      "score": 0.85,
      "confidence": 0.9,
      "findings": ["Wire transfer request detected", "Urgency language: 3 patterns"],
      "threat_categories": ["business_email_compromise"]
    }
  ],
  "reasoning_trace": "**Email Analysis Report**\n...",
  "recommended_actions": [
    "QUARANTINE: Move email to quarantine immediately",
    "BLOCK: Block sender address and domain"
  ],
  "analysis_duration_ms": 1250
}
```

### Key Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/analyze` | Submit email for analysis |
| `GET` | `/api/v1/analyses` | List all analyses (paginated) |
| `GET` | `/api/v1/analyses/{id}` | Get specific analysis |
| `POST` | `/api/v1/analyses/{id}/feedback` | Submit analyst feedback |
| `GET` | `/api/v1/dashboard/stats` | SOC dashboard statistics |
| `GET` | `/api/v1/health` | System health check |

## ⚙️ Agent Configuration

### Threat Scoring Weights (MCDA)
```
Text Analysis Agent:    25%
Metadata Agent:         30%
Enrichment Agent:       30%
Graph Correlation:      15%
```

### Verdict Thresholds
```
Malicious:   score ≥ 0.75
Suspicious:  score ≥ 0.45
Spam:        score ≥ 0.25
Clean:       score < 0.25
```

## 🔗 Integration Guide

### Gmail Integration
```python
# Subscribe to Gmail push notifications via Pub/Sub
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

service = build('gmail', 'v1', credentials=credentials)
service.users().watch(userId='me', body={
    'topicName': 'projects/your-project/topics/email-notifications'
}).execute()
```

### Microsoft 365 Integration
```http
POST https://graph.microsoft.com/v1.0/subscriptions
Authorization: Bearer {token}
{
  "changeType": "created",
  "notificationUrl": "https://your-api.com/api/v1/webhooks/microsoft",
  "resource": "me/messages",
  "expirationDateTime": "2024-12-31T18:23:45.9356913Z"
}
```

### SOAR Webhook
Configure `SOAR_WEBHOOK_URL` in `.env`. The system will POST:
```json
{
  "event": "email_threat_detected",
  "verdict": "malicious",
  "threat_score": 0.92,
  "sender": "attacker@evil.com",
  "recommended_action": "quarantine"
}
```

## 📊 Non-Functional Requirements Met

| NFR | Target | Implementation |
|-----|--------|----------------|
| **Latency** | < 30s | Parallel agent execution, async I/O |
| **Scalability** | 1000s emails/min | Docker Compose → Kubernetes-ready |
| **Accuracy** | FPR < 0.1%, DR > 99% | Multi-agent MCDA, human feedback loop |
| **Security** | Hardened | API key auth, rate limiting, input validation |
| **Observability** | Full | Prometheus + Grafana + structured logs |
| **Modularity** | Pluggable agents | LangGraph node architecture |

## 🧪 Running Tests

```bash
# Backend unit tests
cd backend
pip install -r requirements.txt
pytest tests/ -v --cov=app

# Frontend build test
cd frontend
npm install --legacy-peer-deps
npm run build
```

## 📈 Implementation Roadmap

- [x] **Phase 1 (MVP)**: LangGraph + Text + Metadata agents, API, basic verdict
- [x] **Phase 2 (Graph)**: Neo4j integration, Graph Correlation Agent
- [x] **Phase 3 (Advanced)**: Enrichment Agent (QR, AiTM, LotL), SOAR integration
- [x] **Phase 4 (Production)**: Docker Compose, CI/CD, monitoring, React dashboard
- [ ] **Phase 5 (Scale)**: Kubernetes Helm chart, horizontal scaling
- [ ] **Phase 6 (ML)**: Custom ML models for LLM phishing detection, RLHF

## 📄 License

MIT License - see [LICENSE](LICENSE)

---

Built with ❤️ using LangGraph, FastAPI, Neo4j, and React.
