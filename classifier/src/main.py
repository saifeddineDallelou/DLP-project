"""
DLP Classifier microservice — FastAPI entry point.
Run: uvicorn src.main:app --reload --port 8000
"""

from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from loguru import logger
from pydantic import BaseModel

from .engine import classify_text

app = FastAPI(
    title="DLP Classifier",
    description="Regex + keyword + Luhn content classification engine",
    version="1.0.0",
)

# ── Request / response models ──────────────────────────────────────────────────

class ClassifyRequest(BaseModel):
    text: Optional[str] = None
    file: Optional[str] = None  # base64-encoded file content

class DetectionItem(BaseModel):
    type: str
    value: str
    rule: str
    confidence: float

class ClassifyResponse(BaseModel):
    risk_score: float
    sensitive: bool
    detections: List[DetectionItem]
    evidence_excerpt: str
    file_type: Optional[str] = None

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "service": "dlp-classifier", "version": "1.0.0"}


@app.post("/classify", response_model=ClassifyResponse)
def classify(req: ClassifyRequest) -> ClassifyResponse:
    if not req.text and not req.file:
        raise HTTPException(status_code=422, detail="Provide at least 'text' or 'file'")

    logger.info(
        f"classify request | text_len={len(req.text or '')} "
        f"file={'yes' if req.file else 'no'}"
    )

    result = classify_text(req.text, req.file)
    logger.info(
        f"classify result  | risk={result['risk_score']} "
        f"detections={len(result['detections'])}"
    )
    return ClassifyResponse(**result)
