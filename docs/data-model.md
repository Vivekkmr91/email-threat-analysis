# Data Model

This project stores analysis results in PostgreSQL and relationship intelligence in Neo4j. The two data stores are complementary:

- **PostgreSQL** holds the authoritative analysis records used by the SOC dashboard KPIs and case history.
- **Neo4j** stores entity relationships (domains, campaigns, IPs, URLs) used by the Threat Graph visualization and correlation logic.

---

## PostgreSQL (SQLAlchemy models)

### `email_analyses`
The primary table that powers dashboard KPIs and the analysis history UI.

**Key fields**
- **id** (UUID): Primary key for each analysis.
- **created_at / updated_at**: Timestamps used by dashboard trend queries.
- **message_id / subject / sender_email / recipient_emails**: Email metadata used by filters and search.
- **raw_headers / body_text / body_html**: Parsed email content used by agents.
- **verdict**: Enum (`clean`, `spam`, `suspicious`, `malicious`, `unknown`).
- **threat_score**: 0–1 float used for severity.
- **threat_categories**: JSON list of categories (e.g., `phishing`, `business_email_compromise`).
- **agent scores**: `text_agent_score`, `metadata_agent_score`, `enrichment_agent_score`, `graph_agent_score`.
- **reasoning_trace**: JSON trace of agent reasoning.
- **analysis_duration_ms**: Used for KPI averages.
- **analyst_feedback / analyst_notes / feedback_at**: Human-in-the-loop feedback fields.
- **email_source / external_email_id**: Source system identifiers.

**Relationships**
- One-to-many with `url_analyses`
- One-to-many with `attachment_analyses`

### `url_analyses`
URLs extracted from an email and enriched with threat intel.

**Key fields**
- **email_analysis_id**: FK to `email_analyses`.
- **url / domain**
- **is_malicious / virustotal_score / phishtank_detected**
- **is_look_alike / look_alike_target / ssl_valid**
- **threat_details**: JSON blob for enrichment details.

### `attachment_analyses`
Attachments extracted from an email and enriched with threat intel.

**Key fields**
- **email_analysis_id**: FK to `email_analyses`.
- **filename / file_type / file_size_bytes**
- **sha256_hash / md5_hash**
- **is_malicious / virustotal_score**
- **contains_qr_code / qr_code_urls**
- **sandbox_detonated / sandbox_verdict**
- **threat_details**: JSON blob for enrichment details.

### `seed_markers`
Used for demo data seeding guards to avoid duplicating curated data on restart.

**Key fields**
- **source**: Unique identifier for a seed batch (e.g., `demo_seed_v1`).
- **created_at / notes**

---

## Neo4j (Threat Graph)

The graph is used by the `Graph Agent` and `/api/v1/graph/snapshot` endpoint to render relationships in the Threat Graph UI.

### Nodes
- **EmailAddress**: `{ address, threat_score, last_seen }`
- **Domain**: `{ name, threat_score, age_days, last_seen }`
- **URL**: `{ url, threat_score, last_seen }`
- **IPAddress**: `{ address }`
- **Campaign**: `{ id, name, category, email_count, sender_domain, url_domain, first_seen }`
- **SeedMarker** (demo guard): `{ id, created_at, notes }`

### Relationships
- **(EmailAddress)-[:USES_DOMAIN]->(Domain)**
- **(Domain)-[:RESOLVES_TO]->(IPAddress)**
- **(Domain)-[:HOSTS]->(URL)**
- **(EmailAddress|Domain|URL)-[:PART_OF]->(Campaign)**
- **(EmailAddress)-[:COMMUNICATED_WITH]->(EmailAddress)** (behavioral baseline)

---

## Where the KPIs come from
The SOC dashboard KPIs are aggregated from `email_analyses` and rely on:

- **Total analyzed**: count of `email_analyses` in the selected window.
- **Malicious / Suspicious / Spam / Clean**: grouped counts by `verdict`.
- **Detection rate**: `(malicious + suspicious) / total`.
- **False positives**: `analyst_feedback == false_positive`.
- **Average analysis time**: average `analysis_duration_ms`.

---

## Related Files
- PostgreSQL models: `backend/app/models/email.py`
- Graph Agent: `backend/app/agents/graph_agent.py`
- Dashboard stats endpoint: `backend/app/api/routes.py`
- Demo seed helpers: `backend/app/core/demo_seed.py`
