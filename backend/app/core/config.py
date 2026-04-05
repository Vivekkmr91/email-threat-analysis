"""
Application configuration management using Pydantic Settings.
All secrets are loaded from environment variables.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import Optional
import os


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Email Threat Analysis System"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = Field(default=False)
    ENVIRONMENT: str = Field(default="production")

    # API Security
    SECRET_KEY: str = Field(default="changeme-32char-secret-key-here!!")
    API_KEY_HEADER: str = "X-API-Key"
    ALLOWED_API_KEYS: list[str] = Field(default=["demo-api-key-change-in-production"])

    # CORS
    ALLOWED_ORIGINS: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:80", "http://frontend:3000"],
        env="ALLOWED_ORIGINS"
    )

    # Database (PostgreSQL)
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://emailthreat:emailthreat@postgres:5432/emailthreat",
        env="DATABASE_URL"
    )

    # Redis
    REDIS_URL: str = Field(default="redis://redis:6379/0")

    # Neo4j Graph Database
    NEO4J_URI: str = Field(default="bolt://neo4j:7687")
    NEO4J_USERNAME: str = Field(default="neo4j")
    NEO4J_PASSWORD: str = Field(default="emailthreat123")
    NEO4J_DATABASE: str = Field(default="neo4j")

    # OpenAI / LLM
    OPENAI_API_KEY: Optional[str] = Field(default=None)
    OPENAI_MODEL: str = Field(default="gpt-4o-mini")
    OPENAI_TEMPERATURE: float = Field(default=0.1)

    # VirusTotal
    VIRUSTOTAL_API_KEY: Optional[str] = Field(default=None)
    VIRUSTOTAL_BASE_URL: str = "https://www.virustotal.com/api/v3"

    # PhishTank
    PHISHTANK_API_KEY: Optional[str] = Field(default=None)
    PHISHTANK_BASE_URL: str = "https://checkurl.phishtank.com/checkurl/"

    # Email Provider Integration
    GMAIL_CLIENT_ID: Optional[str] = Field(default=None)
    GMAIL_CLIENT_SECRET: Optional[str] = Field(default=None)
    MICROSOFT_CLIENT_ID: Optional[str] = Field(default=None)
    MICROSOFT_CLIENT_SECRET: Optional[str] = Field(default=None)
    MICROSOFT_TENANT_ID: Optional[str] = Field(default=None)

    # SOAR / Webhook
    SOAR_WEBHOOK_URL: Optional[str] = Field(default=None)
    SOAR_API_KEY: Optional[str] = Field(default=None)

    # Analysis Thresholds
    HIGH_RISK_THRESHOLD: float = Field(default=0.75)
    MEDIUM_RISK_THRESHOLD: float = Field(default=0.45)
    ANALYSIS_TIMEOUT_SECONDS: int = Field(default=30)

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = Field(default=60)

    # Celery
    CELERY_BROKER_URL: str = Field(default="redis://redis:6379/1")
    CELERY_RESULT_BACKEND: str = Field(default="redis://redis:6379/2")

    # ML Model Configuration
    ML_MODEL_DIR: str = Field(default="/tmp/email_threat_ml")
    ML_PHISHING_THRESHOLD: float = Field(default=0.5)
    ML_LLM_DETECT_THRESHOLD: float = Field(default=0.5)

    # RLHF Configuration
    RLHF_MIN_EXAMPLES: int = Field(default=10)
    RLHF_TRAIN_INTERVAL_HOURS: float = Field(default=6.0)
    RLHF_LEARNING_RATE: float = Field(default=5e-4)
    RLHF_EPOCHS: int = Field(default=15)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
