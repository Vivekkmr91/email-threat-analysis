"""
Seed curated demo data into PostgreSQL and Neo4j.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import delete, select

from app.core.database import AsyncSessionLocal, init_db, init_neo4j_schema, neo4j_session
from app.models.email import (
    AttachmentAnalysis,
    EmailAnalysis,
    SeedMarker,
    ThreatCategory,
    ThreatVerdict,
    URLAnalysis,
)

MARKER_SOURCE = "demo_seed_v1"


CURATED_EMAILS: list[dict[str, Any]] = [
    {
        "subject": "URGENT: Payroll Update Required",
        "sender_email": "hr@payroll-supports.com",
        "sender_display_name": "HR Services",
        "recipient_emails": ["finance@contoso.com"],
        "reply_to": "payroll-update@payroll-supports.com",
        "body_text": "Please update payroll info at https://payrol1-secure.com/login today.",
        "raw_headers": "spf=fail dkim=fail dmarc=fail",
        "verdict": ThreatVerdict.MALICIOUS,
        "threat_score": 0.92,
        "categories": [ThreatCategory.PHISHING, ThreatCategory.AITM],
        "text_agent_score": 0.86,
        "metadata_agent_score": 0.78,
        "enrichment_agent_score": 0.93,
        "graph_agent_score": 0.88,
        "urls": [
            {
                "url": "https://payrol1-secure.com/login",
                "domain": "payrol1-secure.com",
                "is_malicious": True,
                "virustotal_score": 0.89,
                "phishtank_detected": True,
                "is_look_alike": True,
                "look_alike_target": "payroll.com",
                "ssl_valid": False,
                "ip_address": "185.72.8.44",
            }
        ],
        "attachments": [],
    },
    {
        "subject": "Invoice #5541 - Payment Required",
        "sender_email": "billing@global-invoice.net",
        "sender_display_name": "Global Invoicing",
        "recipient_emails": ["ap@contoso.com"],
        "reply_to": "billing@global-invoice.net",
        "body_text": "Attached is the invoice. Please process within 24 hours.",
        "raw_headers": "spf=pass dkim=pass dmarc=pass",
        "verdict": ThreatVerdict.SUSPICIOUS,
        "threat_score": 0.58,
        "categories": [ThreatCategory.BEC, ThreatCategory.MALWARE],
        "text_agent_score": 0.62,
        "metadata_agent_score": 0.42,
        "enrichment_agent_score": 0.7,
        "graph_agent_score": 0.52,
        "urls": [],
        "attachments": [
            {
                "filename": "Invoice_5541.pdf",
                "file_type": "pdf",
                "file_size_bytes": 245120,
                "sha256_hash": "6f7a1d96d8a1322f0b165e5cbf61c1026a7c13a9106f44bb5d4d9ed1b3022a3f",
                "is_malicious": True,
                "virustotal_score": 0.65,
                "sandbox_detonated": True,
                "sandbox_verdict": "suspicious",
            }
        ],
    },
    {
        "subject": "Shared Doc: Q2 Strategy Update",
        "sender_email": "julia.morgan@partnershare.io",
        "sender_display_name": "Julia Morgan",
        "recipient_emails": ["leadership@contoso.com"],
        "reply_to": "julia.morgan@partnershare.io",
        "body_text": "Review the plan at https://drive-share.io/contoso-q2",
        "raw_headers": "spf=pass dkim=pass dmarc=pass",
        "verdict": ThreatVerdict.SUSPICIOUS,
        "threat_score": 0.51,
        "categories": [ThreatCategory.LOTL],
        "text_agent_score": 0.41,
        "metadata_agent_score": 0.4,
        "enrichment_agent_score": 0.61,
        "graph_agent_score": 0.48,
        "urls": [
            {
                "url": "https://drive-share.io/contoso-q2",
                "domain": "drive-share.io",
                "is_malicious": False,
                "virustotal_score": 0.1,
                "phishtank_detected": False,
                "is_look_alike": False,
                "ssl_valid": True,
                "ip_address": "52.19.88.12",
            }
        ],
        "attachments": [],
    },
    {
        "subject": "Security Alert: Suspicious Login Attempt",
        "sender_email": "alerts@contoso-security.com",
        "sender_display_name": "Contoso Security",
        "recipient_emails": ["employee@contoso.com"],
        "reply_to": "alerts@contoso-security.com",
        "body_text": "We blocked a login from Berlin. If this was you, ignore this alert.",
        "raw_headers": "spf=pass dkim=pass dmarc=pass",
        "verdict": ThreatVerdict.CLEAN,
        "threat_score": 0.08,
        "categories": [ThreatCategory.CLEAN],
        "text_agent_score": 0.12,
        "metadata_agent_score": 0.05,
        "enrichment_agent_score": 0.05,
        "graph_agent_score": 0.08,
        "urls": [],
        "attachments": [],
    },
    {
        "subject": "Action Required: Account Verification",
        "sender_email": "support@micr0soft-alerts.com",
        "sender_display_name": "Microsoft Security",
        "recipient_emails": ["admin@contoso.com"],
        "reply_to": "support@micr0soft-alerts.com",
        "body_text": "Verify your account here: https://login-micr0soft.com/auth",
        "raw_headers": "spf=fail dkim=fail dmarc=fail",
        "verdict": ThreatVerdict.MALICIOUS,
        "threat_score": 0.95,
        "categories": [ThreatCategory.PHISHING, ThreatCategory.LLM_PHISHING],
        "text_agent_score": 0.91,
        "metadata_agent_score": 0.86,
        "enrichment_agent_score": 0.94,
        "graph_agent_score": 0.9,
        "urls": [
            {
                "url": "https://login-micr0soft.com/auth",
                "domain": "login-micr0soft.com",
                "is_malicious": True,
                "virustotal_score": 0.93,
                "phishtank_detected": True,
                "is_look_alike": True,
                "look_alike_target": "login.microsoftonline.com",
                "ssl_valid": False,
                "ip_address": "193.169.254.8",
            }
        ],
        "attachments": [],
    },
    {
        "subject": "Team Offsite Photos",
        "sender_email": "events@contoso.com",
        "sender_display_name": "Contoso Events",
        "recipient_emails": ["all@contoso.com"],
        "reply_to": "events@contoso.com",
        "body_text": "Photos are attached. Thanks everyone!",
        "raw_headers": "spf=pass dkim=pass dmarc=pass",
        "verdict": ThreatVerdict.CLEAN,
        "threat_score": 0.04,
        "categories": [ThreatCategory.CLEAN],
        "text_agent_score": 0.06,
        "metadata_agent_score": 0.04,
        "enrichment_agent_score": 0.03,
        "graph_agent_score": 0.05,
        "urls": [],
        "attachments": [
            {
                "filename": "offsite_photos.zip",
                "file_type": "zip",
                "file_size_bytes": 1048576,
                "sha256_hash": "8b3e3f7f0b1e3f2f8d7b9d3a4f2e0e4f1d2c8b7a6f5e4d3c2b1a0f9e8d7c6b5",
                "is_malicious": False,
                "virustotal_score": 0.02,
                "sandbox_detonated": False,
            }
        ],
    },
    {
        "subject": "Wire Transfer Confirmation",
        "sender_email": "ceo@contoso-corp.net",
        "sender_display_name": "CEO Office",
        "recipient_emails": ["treasury@contoso.com"],
        "reply_to": "ceo@contoso-corp.net",
        "body_text": "Process the $85,000 transfer to the vendor today.",
        "raw_headers": "spf=softfail dkim=fail dmarc=fail",
        "verdict": ThreatVerdict.MALICIOUS,
        "threat_score": 0.88,
        "categories": [ThreatCategory.BEC],
        "text_agent_score": 0.85,
        "metadata_agent_score": 0.74,
        "enrichment_agent_score": 0.69,
        "graph_agent_score": 0.91,
        "urls": [],
        "attachments": [],
    },
    {
        "subject": "Quarterly Compliance Update",
        "sender_email": "compliance@trustedpartner.com",
        "sender_display_name": "Trusted Partner",
        "recipient_emails": ["risk@contoso.com"],
        "reply_to": "compliance@trustedpartner.com",
        "body_text": "Please review the compliance update by end of week.",
        "raw_headers": "spf=pass dkim=pass dmarc=pass",
        "verdict": ThreatVerdict.SPAM,
        "threat_score": 0.32,
        "categories": [ThreatCategory.SPAM],
        "text_agent_score": 0.29,
        "metadata_agent_score": 0.22,
        "enrichment_agent_score": 0.24,
        "graph_agent_score": 0.2,
        "urls": [],
        "attachments": [],
    },
]


CAMPAIGNS: list[dict[str, Any]] = [
    {
        "id": "camp-hr-payroll-2024",
        "name": "Payroll Redirect",
        "category": "phishing",
        "email_count": 42,
        "sender_domain": "payroll-supports.com",
        "url_domain": "payrol1-secure.com",
        "first_seen": datetime.utcnow() - timedelta(days=18),
    },
    {
        "id": "camp-bec-wire-2024",
        "name": "Wire Transfer Fraud",
        "category": "business_email_compromise",
        "email_count": 29,
        "sender_domain": "contoso-corp.net",
        "url_domain": "",
        "first_seen": datetime.utcnow() - timedelta(days=35),
    },
    {
        "id": "camp-credential-harvest-2024",
        "name": "Credential Harvest",
        "category": "llm_generated_phishing",
        "email_count": 55,
        "sender_domain": "micr0soft-alerts.com",
        "url_domain": "login-micr0soft.com",
        "first_seen": datetime.utcnow() - timedelta(days=9),
    },
]

ENTITIES: list[dict[str, Any]] = [
    {
        "email": "hr@payroll-supports.com",
        "domain": "payroll-supports.com",
        "domain_age_days": 12,
        "domain_threat": 0.82,
        "email_threat": 0.88,
        "ip": "185.72.8.44",
        "url": "https://payrol1-secure.com/login",
        "url_domain": "payrol1-secure.com",
        "campaign_id": "camp-hr-payroll-2024",
    },
    {
        "email": "ceo@contoso-corp.net",
        "domain": "contoso-corp.net",
        "domain_age_days": 24,
        "domain_threat": 0.71,
        "email_threat": 0.86,
        "ip": "91.213.42.19",
        "url": "",
        "url_domain": "",
        "campaign_id": "camp-bec-wire-2024",
    },
    {
        "email": "support@micr0soft-alerts.com",
        "domain": "micr0soft-alerts.com",
        "domain_age_days": 7,
        "domain_threat": 0.93,
        "email_threat": 0.91,
        "ip": "193.169.254.8",
        "url": "https://login-micr0soft.com/auth",
        "url_domain": "login-micr0soft.com",
        "campaign_id": "camp-credential-harvest-2024",
    },
    {
        "email": "julia.morgan@partnershare.io",
        "domain": "partnershare.io",
        "domain_age_days": 120,
        "domain_threat": 0.25,
        "email_threat": 0.3,
        "ip": "52.19.88.12",
        "url": "https://drive-share.io/contoso-q2",
        "url_domain": "drive-share.io",
        "campaign_id": "camp-hr-payroll-2024",
    },
]


def _build_email(entry: dict[str, Any], created_at: datetime) -> EmailAnalysis:
    analysis = EmailAnalysis(
        message_id=f"<seed-{uuid4()}@demo.local>",
        subject=entry["subject"],
        sender_email=entry["sender_email"],
        sender_display_name=entry["sender_display_name"],
        recipient_emails=entry["recipient_emails"],
        reply_to=entry["reply_to"],
        raw_headers=entry["raw_headers"],
        body_text=entry["body_text"],
        verdict=entry["verdict"],
        threat_score=entry["threat_score"],
        threat_categories=[category.value for category in entry["categories"]],
        text_agent_score=entry["text_agent_score"],
        metadata_agent_score=entry["metadata_agent_score"],
        enrichment_agent_score=entry["enrichment_agent_score"],
        graph_agent_score=entry["graph_agent_score"],
        reasoning_trace=[
            {
                "agent": "text_agent",
                "summary": "Curated sample generated for dashboard KPIs.",
                "score": entry["text_agent_score"],
            }
        ],
        analysis_duration_ms=random.randint(820, 1980),
        agents_triggered=["text_agent", "metadata_agent", "enrichment_agent", "decision_agent"],
        email_source="curated_seed",
        external_email_id=f"seed-{uuid4()}",
        created_at=created_at,
        updated_at=created_at,
    )

    for url in entry.get("urls", []):
        analysis.urls.append(
            URLAnalysis(
                url=url["url"],
                domain=url.get("domain"),
                is_malicious=url.get("is_malicious"),
                virustotal_score=url.get("virustotal_score"),
                phishtank_detected=url.get("phishtank_detected"),
                is_look_alike=url.get("is_look_alike", False),
                look_alike_target=url.get("look_alike_target"),
                ssl_valid=url.get("ssl_valid"),
                ip_address=url.get("ip_address"),
                threat_details={"seed": True},
            )
        )

    for attachment in entry.get("attachments", []):
        analysis.attachments.append(
            AttachmentAnalysis(
                filename=attachment["filename"],
                file_type=attachment.get("file_type"),
                file_size_bytes=attachment.get("file_size_bytes"),
                sha256_hash=attachment.get("sha256_hash"),
                is_malicious=attachment.get("is_malicious"),
                virustotal_score=attachment.get("virustotal_score"),
                sandbox_detonated=attachment.get("sandbox_detonated", False),
                sandbox_verdict=attachment.get("sandbox_verdict"),
                threat_details={"seed": True},
            )
        )

    return analysis


async def seed_postgres_demo(truncate: bool, repeat: int, hours_step: int) -> int:
    await init_db()
    async with AsyncSessionLocal() as session:
        if truncate:
            await session.execute(delete(AttachmentAnalysis))
            await session.execute(delete(URLAnalysis))
            await session.execute(delete(EmailAnalysis))
            await session.execute(delete(SeedMarker))
            await session.commit()
        else:
            marker_stmt = select(SeedMarker).where(SeedMarker.source == MARKER_SOURCE)
            marker = (await session.execute(marker_stmt)).scalar_one_or_none()
            if marker:
                return 0

        now = datetime.utcnow()
        analyses: list[EmailAnalysis] = []
        for iteration in range(repeat):
            for index, entry in enumerate(CURATED_EMAILS):
                created_at = now - timedelta(hours=(iteration * len(CURATED_EMAILS) + index) * hours_step)
                analyses.append(_build_email(entry, created_at))

        session.add_all(analyses)
        session.add(SeedMarker(source=MARKER_SOURCE, notes="Demo seed applied"))
        await session.commit()

        return len(analyses)


async def seed_neo4j_demo(truncate: bool) -> int:
    await init_neo4j_schema()

    async with neo4j_session() as session:
        if truncate:
            await session.run("MATCH (n) DETACH DELETE n")
        else:
            marker_check = await session.run(
                "MATCH (m:SeedMarker {id: $id}) RETURN m LIMIT 1",
                id=MARKER_SOURCE,
            )
            if await marker_check.single():
                return 0

        for campaign in CAMPAIGNS:
            await session.run(
                """
                MERGE (c:Campaign {id: $id})
                SET c.name = $name,
                    c.category = $category,
                    c.email_count = $email_count,
                    c.sender_domain = $sender_domain,
                    c.url_domain = $url_domain,
                    c.first_seen = $first_seen
                """,
                **campaign,
            )

        created_nodes = 0
        for entity in ENTITIES:
            await session.run(
                """
                MERGE (e:EmailAddress {address: $email})
                SET e.threat_score = $email_threat,
                    e.last_seen = datetime($last_seen)
                MERGE (d:Domain {name: $domain})
                SET d.threat_score = $domain_threat,
                    d.age_days = $domain_age_days,
                    d.last_seen = datetime($last_seen)
                MERGE (i:IPAddress {address: $ip})
                MERGE (e)-[:USES_DOMAIN]->(d)
                MERGE (d)-[:RESOLVES_TO]->(i)
                """,
                **entity,
                last_seen=datetime.utcnow().isoformat(),
            )
            created_nodes += 3

            if entity.get("url"):
                await session.run(
                    """
                    MERGE (u:URL {url: $url})
                    SET u.threat_score = $domain_threat,
                        u.last_seen = datetime($last_seen)
                    WITH u
                    MATCH (d:Domain {name: $url_domain})
                    MERGE (d)-[:HOSTS]->(u)
                    """,
                    **entity,
                    last_seen=datetime.utcnow().isoformat(),
                )
                created_nodes += 1

            await session.run(
                """
                MATCH (c:Campaign {id: $campaign_id})
                MATCH (e:EmailAddress {address: $email})
                MATCH (d:Domain {name: $domain})
                MERGE (e)-[:PART_OF]->(c)
                MERGE (d)-[:PART_OF]->(c)
                """,
                **entity,
            )

            if entity.get("url"):
                await session.run(
                    """
                    MATCH (c:Campaign {id: $campaign_id})
                    MATCH (u:URL {url: $url})
                    MERGE (u)-[:PART_OF]->(c)
                    """,
                    **entity,
                )

        await session.run(
            """
            MERGE (m:SeedMarker {id: $id})
            SET m.created_at = datetime($created_at),
                m.notes = $notes
            """,
            id=MARKER_SOURCE,
            created_at=datetime.utcnow().isoformat(),
            notes="Demo seed applied",
        )

        return created_nodes
