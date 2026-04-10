"""
SQLAlchemy ORM models for email analysis records.
"""
from sqlalchemy import (
    Column, String, Float, Boolean, DateTime, Text, JSON,
    Integer, ForeignKey, Enum as SAEnum, Index
)
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid
import enum

from app.core.database import Base


class ThreatVerdict(str, enum.Enum):
    CLEAN = "clean"
    SPAM = "spam"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class ThreatCategory(str, enum.Enum):
    BEC = "business_email_compromise"
    PHISHING = "phishing"
    MALWARE = "malware"
    SPAM = "spam"
    QUISHING = "quishing"
    AITM = "adversary_in_the_middle"
    LOTL = "living_off_the_land"
    LLM_PHISHING = "llm_generated_phishing"
    DEEPFAKE = "deepfake_social_engineering"
    CLEAN = "clean"


class EmailAnalysis(Base):
    __tablename__ = "email_analyses"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Email identification
    message_id = Column(String(512), nullable=True, index=True)
    subject = Column(Text, nullable=True)
    sender_email = Column(String(255), nullable=True, index=True)
    sender_display_name = Column(String(255), nullable=True)
    recipient_emails = Column(JSON, nullable=True)  # list of strings
    reply_to = Column(String(255), nullable=True)

    # Raw data
    raw_headers = Column(Text, nullable=True)
    body_text = Column(Text, nullable=True)
    body_html = Column(Text, nullable=True)

    # Verdict
    verdict = Column(SAEnum(ThreatVerdict), nullable=False, default=ThreatVerdict.UNKNOWN)
    threat_score = Column(Float, nullable=False, default=0.0)
    threat_categories = Column(JSON, nullable=True)  # list of ThreatCategory

    # Agent scores
    text_agent_score = Column(Float, nullable=True)
    metadata_agent_score = Column(Float, nullable=True)
    enrichment_agent_score = Column(Float, nullable=True)
    graph_agent_score = Column(Float, nullable=True)

    # Reasoning trace (explainability)
    reasoning_trace = Column(JSON, nullable=True)

    # Analysis metadata
    analysis_duration_ms = Column(Integer, nullable=True)
    agents_triggered = Column(JSON, nullable=True)  # list of agent names
    error_info = Column(Text, nullable=True)

    # Human feedback
    analyst_feedback = Column(String(50), nullable=True)  # 'correct', 'false_positive', 'false_negative'
    analyst_notes = Column(Text, nullable=True)
    feedback_at = Column(DateTime, nullable=True)
    feedback_by = Column(String(255), nullable=True)

    # Automated response
    auto_response_triggered = Column(Boolean, default=False)
    auto_response_actions = Column(JSON, nullable=True)

    # Source
    email_source = Column(String(50), nullable=True)  # 'gmail', 'microsoft365', 'smtp', 'api'
    external_email_id = Column(String(512), nullable=True)

    # Relationships
    urls = relationship("URLAnalysis", back_populates="email_analysis", cascade="all, delete-orphan")
    attachments = relationship("AttachmentAnalysis", back_populates="email_analysis", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_email_verdict_created", "verdict", "created_at"),
        Index("ix_email_threat_score", "threat_score"),
    )


class URLAnalysis(Base):
    __tablename__ = "url_analyses"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_analysis_id = Column(UUID(as_uuid=True), ForeignKey("email_analyses.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    url = Column(Text, nullable=False)
    domain = Column(String(255), nullable=True, index=True)
    is_malicious = Column(Boolean, nullable=True)
    virustotal_score = Column(Float, nullable=True)
    phishtank_detected = Column(Boolean, nullable=True)
    is_qr_code_url = Column(Boolean, default=False)
    is_redirect = Column(Boolean, default=False)
    final_url = Column(Text, nullable=True)
    domain_age_days = Column(Integer, nullable=True)
    is_look_alike = Column(Boolean, default=False)
    look_alike_target = Column(String(255), nullable=True)
    ssl_valid = Column(Boolean, nullable=True)
    ip_address = Column(String(45), nullable=True)
    threat_details = Column(JSON, nullable=True)

    email_analysis = relationship("EmailAnalysis", back_populates="urls")


class AttachmentAnalysis(Base):
    __tablename__ = "attachment_analyses"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_analysis_id = Column(UUID(as_uuid=True), ForeignKey("email_analyses.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    filename = Column(String(512), nullable=False)
    file_type = Column(String(100), nullable=True)
    file_size_bytes = Column(Integer, nullable=True)
    sha256_hash = Column(String(64), nullable=True, index=True)
    md5_hash = Column(String(32), nullable=True)
    is_malicious = Column(Boolean, nullable=True)
    virustotal_score = Column(Float, nullable=True)
    contains_qr_code = Column(Boolean, default=False)
    qr_code_urls = Column(JSON, nullable=True)  # list of extracted URLs
    sandbox_detonated = Column(Boolean, default=False)
    sandbox_verdict = Column(String(50), nullable=True)
    threat_details = Column(JSON, nullable=True)

    email_analysis = relationship("EmailAnalysis", back_populates="attachments")


class SeedMarker(Base):
    __tablename__ = "seed_markers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    source = Column(String(100), nullable=False, unique=True, index=True)
    notes = Column(Text, nullable=True)
