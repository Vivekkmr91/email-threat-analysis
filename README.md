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

### Prerequisites
- Docker & Docker Compose
- 4GB RAM minimum
- Optional: OpenAI API key, VirusTotal API key

### 1. Clone & Configure
```bash
git clone https://github.com/Vivekkmr91/email-threat-analysis.git
cd email-threat-analysis

# Configure environment
cp .env.example .env
# Edit .env with your API keys (OPENAI_API_KEY, VIRUSTOTAL_API_KEY, etc.)
```

### 2. Start All Services
```bash
docker compose up -d
```

### 3. Access the System
| Service | URL | Credentials |
|---------|-----|-------------|
| **SOC Dashboard** | http://localhost:80 | - |
| **API Documentation** | http://localhost:8000/redoc | - |
| **Neo4j Browser** | http://localhost:7474 | neo4j / emailthreat123 |
| **Grafana** | http://localhost:3001 | admin / admin123 |

### 4. Analyze Your First Email
```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
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
