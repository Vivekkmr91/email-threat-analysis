"""
Pydantic schemas for API request/response validation.
"""
from pydantic import BaseModel, Field, EmailStr, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import uuid


# ─── Enums ──────────────────────────────────────────────────────────────────

class ThreatVerdictEnum(str, Enum):
    CLEAN = "clean"
    SPAM = "spam"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class ThreatCategoryEnum(str, Enum):
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


class FeedbackTypeEnum(str, Enum):
    CORRECT = "correct"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"


# ─── Request Schemas ─────────────────────────────────────────────────────────

class EmailSubmitRequest(BaseModel):
    """Request body for submitting a raw email for analysis."""
    raw_email: Optional[str] = Field(None, description="Raw email in RFC 2822 format (EML)")
    subject: Optional[str] = Field(None, description="Email subject line")
    sender: Optional[str] = Field(None, description="Sender email address")
    recipients: Optional[List[str]] = Field(default=[], description="List of recipient emails")
    body_text: Optional[str] = Field(None, description="Plain text body")
    body_html: Optional[str] = Field(None, description="HTML body")
    headers: Optional[Dict[str, str]] = Field(default={}, description="Email headers as key-value pairs")
    attachments_base64: Optional[List[Dict[str, str]]] = Field(
        default=[],
        description="List of attachments: [{filename, content_base64, mime_type}]"
    )
    source: Optional[str] = Field(default="api", description="Email source: api, gmail, microsoft365, smtp")
    external_email_id: Optional[str] = Field(None, description="External email ID for tracking")

    class Config:
        json_schema_extra = {
            "example": {
                "subject": "Urgent: Invoice Payment Required",
                "sender": "ceo@company-fake.com",
                "recipients": ["finance@mycompany.com"],
                "body_text": "Please process the attached invoice immediately. Wire $50,000 to the new account.",
                "headers": {
                    "From": "CEO <ceo@company-fake.com>",
                    "Reply-To": "attacker@evil.com",
                    "X-Originating-IP": "185.220.101.1"
                },
                "source": "api"
            }
        }


class FeedbackRequest(BaseModel):
    """Analyst feedback on a verdict."""
    feedback_type: FeedbackTypeEnum
    notes: Optional[str] = Field(None, max_length=2000)
    analyst_id: Optional[str] = Field(None, description="Analyst identifier")


class LoginRequest(BaseModel):
    """Login request for dashboard session auth."""
    username: str
    password: str


class SessionResponse(BaseModel):
    """Response with active session details."""
    username: str
    expires_at: datetime


# ─── Response Schemas ────────────────────────────────────────────────────────

class AgentFinding(BaseModel):
    """Finding from a single agent."""
    agent_name: str
    score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    findings: List[str] = []
    indicators: Dict[str, Any] = {}
    threat_categories: List[ThreatCategoryEnum] = []
    processing_time_ms: Optional[int] = None


class URLResult(BaseModel):
    """URL analysis result."""
    url: str
    domain: Optional[str] = None
    is_malicious: Optional[bool] = None
    virustotal_score: Optional[float] = None
    phishtank_detected: Optional[bool] = None
    is_qr_code_url: bool = False
    is_look_alike: bool = False
    look_alike_target: Optional[str] = None
    domain_age_days: Optional[int] = None
    ssl_valid: Optional[bool] = None
    threat_details: Dict[str, Any] = {}


class AttachmentResult(BaseModel):
    """Attachment analysis result."""
    filename: str
    file_type: Optional[str] = None
    file_size_bytes: Optional[int] = None
    sha256_hash: Optional[str] = None
    is_malicious: Optional[bool] = None
    virustotal_score: Optional[float] = None
    contains_qr_code: bool = False
    qr_code_urls: List[str] = []
    sandbox_verdict: Optional[str] = None
    threat_details: Dict[str, Any] = {}


class EmailAnalysisResponse(BaseModel):
    """Complete analysis response."""
    analysis_id: str
    created_at: datetime
    verdict: ThreatVerdictEnum
    threat_score: float = Field(ge=0.0, le=1.0)
    threat_categories: List[ThreatCategoryEnum] = []

    # Agent results
    agent_findings: List[AgentFinding] = []

    # Detailed results
    url_results: List[URLResult] = []
    attachment_results: List[AttachmentResult] = []

    # Explainability
    reasoning_trace: str
    reasoning_steps: List[Dict[str, Any]] = []
    recommended_actions: List[str] = []

    # Performance
    analysis_duration_ms: int = 0
    agents_triggered: List[str] = []

    class Config:
        from_attributes = True


class AnalysisListItem(BaseModel):
    """Summary item for list endpoints."""
    analysis_id: str
    created_at: datetime
    subject: Optional[str] = None
    sender_email: Optional[str] = None
    verdict: ThreatVerdictEnum
    threat_score: float
    threat_categories: List[str] = []
    has_feedback: bool = False

    class Config:
        from_attributes = True


class AnalysisListResponse(BaseModel):
    items: List[AnalysisListItem]
    total: int
    page: int
    page_size: int


class DashboardStats(BaseModel):
    """Statistics for the SOC dashboard."""
    total_analyzed: int
    malicious_count: int
    suspicious_count: int
    spam_count: int
    clean_count: int
    detection_rate: float
    false_positive_rate: float
    avg_analysis_time_ms: float
    top_threat_categories: List[Dict[str, Any]]
    threats_over_time: List[Dict[str, Any]]
    top_sender_domains: List[Dict[str, Any]]


class HealthResponse(BaseModel):
    status: str
    version: str
    services: Dict[str, str]
    timestamp: datetime
