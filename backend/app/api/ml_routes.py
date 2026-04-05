"""
ML & RLHF API Routes
====================

Endpoints
---------
POST   /ml/predict             – Run ML-only prediction on email text
GET    /ml/status              – Model registry status (versions, accuracy)
POST   /ml/feedback            – Submit analyst feedback → RLHF pipeline
POST   /ml/train               – Manually trigger a training cycle (admin)
GET    /ml/feedback/history    – List feedback records
GET    /ml/rlhf/status         – Full RLHF pipeline status
POST   /ml/batch-predict       – Batch prediction for multiple emails
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.core.config import settings

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/ml", tags=["ML & RLHF"])


# ──────────────────────────────────────────────────────────────────────────────
# Request / Response schemas
# ──────────────────────────────────────────────────────────────────────────────

class MLPredictRequest(BaseModel):
    subject:   str     = Field(..., description="Email subject line")
    body_text: str     = Field(..., description="Plain-text email body")
    sender:    str     = Field("", description="Sender email address")
    headers:   Dict[str, str] = Field(default={}, description="Email headers")
    urls:      List[str]      = Field(default=[], description="URLs found in email")

    class Config:
        json_schema_extra = {
            "example": {
                "subject": "URGENT: Your account has been suspended",
                "body_text": "Please verify your credentials immediately by clicking the link below.",
                "sender": "security@paypa1.com",
                "urls": ["https://secure.paypa1.com/verify"]
            }
        }


class FeatureImportance(BaseModel):
    feature_name:  str
    feature_value: float
    importance:    float


class MLPredictResponse(BaseModel):
    phishing_score:       float = Field(ge=0.0, le=1.0)
    llm_generated_score:  float = Field(ge=0.0, le=1.0)
    is_phishing:          bool
    is_llm_generated:     bool
    verdict_suggestion:   str   # clean / suspicious / malicious
    top_features:         List[FeatureImportance] = []
    model_version:        str
    inference_time_ms:    float


class FeedbackRequest(BaseModel):
    """Submit analyst feedback on a completed analysis for RLHF."""
    analysis_id:       str
    subject:           str
    body_text:         str
    sender:            str = ""
    headers:           Dict[str, str] = {}
    urls:              List[str]      = []
    predicted_verdict: str   # what the system originally predicted
    predicted_score:   float = Field(ge=0.0, le=1.0)
    predicted_llm:     bool  = False
    # Correction
    feedback_type:     str   = Field(..., description="correct | false_positive | false_negative")
    corrected_verdict: Optional[str] = Field(None, description="What the verdict should have been")
    analyst_id:        str   = "anonymous"
    notes:             str   = ""

    class Config:
        json_schema_extra = {
            "example": {
                "analysis_id": "abc-123",
                "subject": "Team lunch on Friday",
                "body_text": "Hey team, shall we do lunch on Friday?",
                "sender": "colleague@company.com",
                "predicted_verdict": "suspicious",
                "predicted_score": 0.6,
                "predicted_llm": False,
                "feedback_type": "false_positive",
                "corrected_verdict": "clean",
                "analyst_id": "analyst-001",
                "notes": "Internal colleague email, clearly legitimate"
            }
        }


class TrainRequest(BaseModel):
    epochs:     int   = Field(default=15, ge=1, le=100)
    lr:         float = Field(default=5e-4, ge=1e-6, le=0.1)
    batch_size: int   = Field(default=32, ge=4, le=256)


class BatchPredictRequest(BaseModel):
    emails: List[MLPredictRequest] = Field(..., max_length=50)


class BatchPredictResponse(BaseModel):
    results:        List[MLPredictResponse]
    total_time_ms:  float


# ──────────────────────────────────────────────────────────────────────────────
# Helper: lazy-import singletons
# ──────────────────────────────────────────────────────────────────────────────

def _get_registry():
    from app.ml.phishing_classifier import get_registry
    return get_registry()


def _get_rlhf():
    from app.ml.rlhf import get_rlhf_pipeline
    return get_rlhf_pipeline()


def _prediction_to_response(pred, subject: str = "") -> MLPredictResponse:
    """Convert MLPrediction dataclass to API response schema."""
    score = pred.phishing_score

    if score >= 0.75:
        verdict = "malicious"
    elif score >= 0.45:
        verdict = "suspicious"
    elif score >= 0.25:
        verdict = "spam"
    else:
        verdict = "clean"

    return MLPredictResponse(
        phishing_score      = pred.phishing_score,
        llm_generated_score = pred.llm_generated_score,
        is_phishing         = pred.is_phishing,
        is_llm_generated    = pred.is_llm_generated,
        verdict_suggestion  = verdict,
        top_features        = [
            FeatureImportance(**f) for f in pred.top_features
        ],
        model_version       = pred.model_version,
        inference_time_ms   = pred.inference_time_ms,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@router.post(
    "/predict",
    response_model=MLPredictResponse,
    summary="Run ML-only phishing & LLM-generation prediction",
)
async def ml_predict(request: MLPredictRequest) -> MLPredictResponse:
    """
    Runs the custom ML classifier (no LLM / no heuristics) directly on the
    provided email text.  Use this for fast, explainable predictions.
    """
    try:
        registry = _get_registry()
        pred     = registry.predict(
            subject  = request.subject,
            body     = request.body_text,
            sender   = request.sender,
            headers  = request.headers,
            urls     = request.urls,
        )
        return _prediction_to_response(pred, request.subject)
    except Exception as e:
        logger.error("ML predict failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"ML prediction failed: {e}"
        )


@router.post(
    "/batch-predict",
    response_model=BatchPredictResponse,
    summary="Batch ML prediction for multiple emails",
)
async def ml_batch_predict(request: BatchPredictRequest) -> BatchPredictResponse:
    """Run ML prediction on up to 50 emails in one request."""
    t0 = time.perf_counter()
    results = []
    registry = _get_registry()

    for email in request.emails:
        try:
            pred = registry.predict(
                subject = email.subject,
                body    = email.body_text,
                sender  = email.sender,
                headers = email.headers,
                urls    = email.urls,
            )
            results.append(_prediction_to_response(pred, email.subject))
        except Exception as e:
            logger.warning("Batch predict item failed", error=str(e))
            # Return a default response for failed items
            results.append(MLPredictResponse(
                phishing_score=0.0, llm_generated_score=0.0,
                is_phishing=False, is_llm_generated=False,
                verdict_suggestion="clean", top_features=[],
                model_version="error", inference_time_ms=0.0,
            ))

    total_ms = (time.perf_counter() - t0) * 1000
    return BatchPredictResponse(results=results, total_time_ms=total_ms)


@router.get(
    "/status",
    summary="Get ML model registry status",
)
async def ml_status() -> Dict[str, Any]:
    """
    Returns current model version, training statistics, and checkpoint info.
    """
    try:
        registry = _get_registry()
        return registry.status()
    except Exception as e:
        logger.error("ML status failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/feedback",
    summary="Submit analyst feedback for RLHF training",
    status_code=status.HTTP_202_ACCEPTED,
)
async def submit_ml_feedback(
    request: FeedbackRequest,
    background_tasks: BackgroundTasks,
) -> Dict[str, Any]:
    """
    Submit analyst feedback on a model prediction.
    The feedback is stored in the RLHF pipeline and used to fine-tune
    the ML models in the next training cycle.

    Feedback types:
    - **correct**: Model prediction was right
    - **false_positive**: Email was flagged but is actually legitimate
    - **false_negative**: Email was clean but is actually malicious
    """
    if request.feedback_type not in ("correct", "false_positive", "false_negative"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="feedback_type must be 'correct', 'false_positive', or 'false_negative'"
        )

    try:
        pipeline    = _get_rlhf()
        feedback_id = pipeline.submit_feedback(
            analysis_id        = request.analysis_id,
            subject            = request.subject,
            body_text          = request.body_text,
            sender             = request.sender,
            headers            = request.headers,
            urls               = request.urls,
            predicted_verdict  = request.predicted_verdict,
            predicted_score    = request.predicted_score,
            predicted_llm      = request.predicted_llm,
            feedback_type      = request.feedback_type,
            analyst_id         = request.analyst_id,
            notes              = request.notes,
            corrected_verdict  = request.corrected_verdict,
        )

        return {
            "status":      "accepted",
            "feedback_id": feedback_id,
            "message":     "Feedback queued for RLHF training",
        }
    except Exception as e:
        logger.error("Feedback submission failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/train",
    summary="Manually trigger RLHF training cycle (admin)",
)
async def trigger_training(
    request: TrainRequest,
    background_tasks: BackgroundTasks,
) -> Dict[str, Any]:
    """
    Manually trigger a full RLHF training cycle using collected feedback.
    Training runs asynchronously in the background.
    Requires at least MIN_EXAMPLES_FOR_TRAINING feedback records.
    """
    try:
        pipeline = _get_rlhf()
        store_stats = pipeline.store.stats()

        if store_stats["unused_feedback"] == 0:
            return {
                "status":  "skipped",
                "reason":  "No unused feedback records available",
                "store_stats": store_stats,
            }

        # Run in background task
        background_tasks.add_task(
            pipeline.trigger_training,
            epochs=request.epochs,
            lr=request.lr,
        )

        return {
            "status":      "training_started",
            "epochs":      request.epochs,
            "lr":          request.lr,
            "batch_size":  request.batch_size,
            "n_feedback":  store_stats["unused_feedback"],
            "message":     "Training cycle started in background",
        }
    except Exception as e:
        logger.error("Training trigger failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/rlhf/status",
    summary="Get RLHF pipeline status",
)
async def rlhf_status() -> Dict[str, Any]:
    """
    Returns comprehensive RLHF pipeline status including:
    - Feedback store statistics (total, unused, used)
    - Model registry status (version, accuracy, checkpoint)
    - Threshold adaptation suggestions
    - Training schedule info
    """
    try:
        pipeline = _get_rlhf()
        return pipeline.get_status()
    except Exception as e:
        logger.error("RLHF status failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/feedback/history",
    summary="List RLHF feedback records",
)
async def feedback_history(
    limit:       int  = Query(50, ge=1, le=500),
    only_unused: bool = Query(False, description="Show only records not yet used in training"),
) -> Dict[str, Any]:
    """
    List analyst feedback records stored in the RLHF pipeline.
    """
    try:
        pipeline = _get_rlhf()
        records  = pipeline.get_feedback_records(limit=limit, only_unused=only_unused)
        stats    = pipeline.store.stats()

        return {
            "records":    records,
            "total":      len(records),
            "store_stats": stats,
        }
    except Exception as e:
        logger.error("Feedback history failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/features/names",
    summary="Get feature vector description",
)
async def feature_names() -> Dict[str, Any]:
    """
    Returns the names and descriptions of all 60 features in the ML
    feature vector, along with their group membership.
    """
    from app.ml.features import FEATURE_NAMES

    groups = {
        "linguistic":          FEATURE_NAMES[0:15],
        "structural":          FEATURE_NAMES[15:25],
        "social_engineering":  FEATURE_NAMES[25:35],
        "llm_fingerprint":     FEATURE_NAMES[35:47],
        "url_signals":         FEATURE_NAMES[47:55],
        "header_auth":         FEATURE_NAMES[55:60],
    }

    return {
        "total_features": len(FEATURE_NAMES),
        "feature_names":  FEATURE_NAMES,
        "groups":         groups,
    }
