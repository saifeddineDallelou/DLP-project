"""
DLP Classifier microservice — FastAPI entry point.
Run: uvicorn src.main:app --reload --port 8000
"""

from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from loguru import logger
from pydantic import BaseModel

from .engine import classify_text
from .edm import (
    build_reference_set,
    delete_reference_set,
    load_reference_sets,
    save_reference_set,
)

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


# ── Exact Data Match ──────────────────────────────────────────────────────────
#
# Regex answers "does this LOOK like a card number". EDM answers "is this OUR
# customer's card number", by matching against a hash of the organisation's
# real records. It also catches values no pattern can describe -- a customer
# name, an account reference -- because a hash lookup needs no shape.

class EdmUploadRequest(BaseModel):
    name: str
    rows: List[Dict[str, Any]]
    rule: str = "INTERNAL"


class EdmSetSummary(BaseModel):
    name: str
    rule: str
    columns: Dict[str, int]
    totalValues: int


@app.get("/edm", response_model=List[EdmSetSummary])
def list_edm_sets() -> List[EdmSetSummary]:
    """Configured reference sets. Returns counts per column, never digests --
    a digest is not a secret in the way its source value is, but publishing
    one over an API invites an offline dictionary attack against low-entropy
    values, which is the exact risk the salt exists to manage."""
    return [
        EdmSetSummary(
            name=rs.name,
            rule=rs.rule,
            columns={col: len(vals) for col, vals in rs.columns.items()},
            totalValues=rs.total_values,
        )
        for rs in load_reference_sets()
    ]


@app.post("/edm", response_model=EdmSetSummary, status_code=201)
def upload_edm_set(req: EdmUploadRequest) -> EdmSetSummary:
    """
    Build a reference set from real records.

    THE RAW ROWS ARE HASHED AND DISCARDED. They are never written to disk and
    never logged -- only salted digests are persisted. Storing an
    organisation's customer database inside its DLP tool would create exactly
    the concentration of sensitive data the tool exists to prevent.

    The request body does contain real records in transit, so this endpoint
    belongs behind the backend's authenticated proxy in any deployment where
    the classifier is not on localhost.
    """
    if not req.name.strip():
        raise HTTPException(status_code=422, detail="name is required")
    if not req.rows:
        raise HTTPException(status_code=422, detail="rows must not be empty")

    rs = build_reference_set(req.name.strip(), req.rows, rule=req.rule)
    if rs.total_values == 0:
        raise HTTPException(
            status_code=422,
            detail="No indexable values. Values under 4 characters are skipped "
                   "deliberately -- short tokens appear in ordinary prose and "
                   "would match everything.",
        )

    save_reference_set(rs)
    # Deliberately does not echo the submitted rows back.
    logger.info(f"EDM set '{rs.name}' indexed: {rs.total_values} values")
    return EdmSetSummary(
        name=rs.name,
        rule=rs.rule,
        columns={col: len(vals) for col, vals in rs.columns.items()},
        totalValues=rs.total_values,
    )


@app.delete("/edm/{name}", status_code=204)
def remove_edm_set(name: str) -> None:
    if not delete_reference_set(name):
        raise HTTPException(status_code=404, detail=f"No reference set named '{name}'")
