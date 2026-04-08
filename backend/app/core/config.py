"""
Application configuration management using Pydantic Settings.
All secrets are loaded from environment variables.

LLM Provider priority (checked in order):
  1. OpenRouter  – set OPENROUTER_API_KEY  (free OSS models: gemma, GLM, mistral …)
  2. OpenAI      – set OPENAI_API_KEY       (GPT-4o-mini default)
  3. None        – heuristic + ML only (still fully functional)
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    # ── Application ──────────────────────────────────────────────────────────
    APP_NAME: str    = "Email Threat Analysis System"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool      = Field(default=False)
    ENVIRONMENT: str = Field(default="production")

    # ── API Security ─────────────────────────────────────────────────────────
    SECRET_KEY: str          = Field(default="changeme-32char-secret-key-here!!")
    API_KEY_HEADER: str      = "X-API-Key"
    ALLOWED_API_KEYS: list[str] = Field(
        default=["demo-api-key-change-in-production"]
    )

    # ── CORS ─────────────────────────────────────────────────────────────────
    ALLOWED_ORIGINS: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:8080", "http://frontend:80"]
    )

    # ── Database (PostgreSQL) ─────────────────────────────────────────────────
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://emailthreat:emailthreat@postgres:5432/emailthreat"
    )

    # ── Redis ────────────────────────────────────────────────────────────────
    REDIS_URL: str = Field(default="redis://redis:6379/0")

    # ── Neo4j Graph Database ──────────────────────────────────────────────────
    NEO4J_URI:      str = Field(default="bolt://neo4j:7687")
    NEO4J_USERNAME: str = Field(default="neo4j")
    NEO4J_PASSWORD: str = Field(default="emailthreat123")
    NEO4J_DATABASE: str = Field(default="neo4j")

    # ── OpenRouter (preferred – free OSS models) ──────────────────────────────
    # Sign up free at https://openrouter.ai  →  Dashboard → Keys → Create key
    # Free models to try:
    #   google/gemma-3-27b-it:free
    #   meta-llama/llama-4-scout:free
    #   microsoft/phi-4-reasoning:free
    #   thudm/glm-z1-32b:free
    #   mistralai/mistral-7b-instruct:free
    #   qwen/qwen3-235b-a22b:free
    OPENROUTER_API_KEY:  Optional[str] = Field(default=None)
    OPENROUTER_BASE_URL: str           = Field(default="https://openrouter.ai/api/v1")
    OPENROUTER_MODEL:    str           = Field(default="google/gemma-3-27b-it:free")
    # Optional: tells OpenRouter which site/app is making requests (for analytics)
    OPENROUTER_SITE_URL:  str = Field(default="http://localhost:8080")
    OPENROUTER_SITE_NAME: str = Field(default="Email Threat Analysis")

    # ── OpenAI (fallback if OpenRouter key not set) ───────────────────────────
    OPENAI_API_KEY:    Optional[str] = Field(default=None)
    OPENAI_MODEL:      str           = Field(default="gpt-4o-mini")
    OPENAI_BASE_URL:   str           = Field(default="https://api.openai.com/v1")
    OPENAI_TEMPERATURE: float        = Field(default=0.1)

    # ── VirusTotal ────────────────────────────────────────────────────────────
    VIRUSTOTAL_API_KEY: Optional[str] = Field(default=None)
    VIRUSTOTAL_BASE_URL: str = "https://www.virustotal.com/api/v3"

    # ── PhishTank ─────────────────────────────────────────────────────────────
    PHISHTANK_API_KEY: Optional[str] = Field(default=None)
    PHISHTANK_BASE_URL: str = "https://checkurl.phishtank.com/checkurl/"

    # ── Email Provider Integration ────────────────────────────────────────────
    GMAIL_CLIENT_ID:      Optional[str] = Field(default=None)
    GMAIL_CLIENT_SECRET:  Optional[str] = Field(default=None)
    MICROSOFT_CLIENT_ID:  Optional[str] = Field(default=None)
    MICROSOFT_CLIENT_SECRET: Optional[str] = Field(default=None)
    MICROSOFT_TENANT_ID:  Optional[str] = Field(default=None)

    # ── SOAR / Webhook ────────────────────────────────────────────────────────
    SOAR_WEBHOOK_URL: Optional[str] = Field(default=None)
    SOAR_API_KEY:     Optional[str] = Field(default=None)

    # ── Analysis Thresholds ───────────────────────────────────────────────────
    HIGH_RISK_THRESHOLD:       float = Field(default=0.75)
    MEDIUM_RISK_THRESHOLD:     float = Field(default=0.45)
    ANALYSIS_TIMEOUT_SECONDS:  int   = Field(default=30)

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = Field(default=60)

    # ── Celery ────────────────────────────────────────────────────────────────
    CELERY_BROKER_URL:     str = Field(default="redis://redis:6379/1")
    CELERY_RESULT_BACKEND: str = Field(default="redis://redis:6379/2")

    # ── ML Model Configuration ────────────────────────────────────────────────
    ML_MODEL_DIR:           str   = Field(default="/tmp/email_threat_ml")
    ML_PHISHING_THRESHOLD:  float = Field(default=0.5)
    ML_LLM_DETECT_THRESHOLD: float = Field(default=0.5)

    # ── RLHF Configuration ────────────────────────────────────────────────────
    RLHF_MIN_EXAMPLES:         int   = Field(default=10)
    RLHF_TRAIN_INTERVAL_HOURS: float = Field(default=6.0)
    RLHF_LEARNING_RATE:        float = Field(default=5e-4)
    RLHF_EPOCHS:               int   = Field(default=15)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ── Derived helpers ───────────────────────────────────────────────────────

    @property
    def llm_provider(self) -> str:
        """Return the active LLM provider: 'openrouter', 'openai', or 'none'."""
        if self.OPENROUTER_API_KEY:
            return "openrouter"
        if self.OPENAI_API_KEY:
            return "openai"
        return "none"

    @property
    def active_llm_model(self) -> str:
        """Return the model name for the active provider."""
        if self.OPENROUTER_API_KEY:
            return self.OPENROUTER_MODEL
        return self.OPENAI_MODEL

    @property
    def active_llm_base_url(self) -> str:
        """Return the base URL for the active provider."""
        if self.OPENROUTER_API_KEY:
            return self.OPENROUTER_BASE_URL
        return self.OPENAI_BASE_URL

    @property
    def active_llm_api_key(self) -> Optional[str]:
        """Return the API key for the active provider."""
        if self.OPENROUTER_API_KEY:
            return self.OPENROUTER_API_KEY
        return self.OPENAI_API_KEY


settings = Settings()
