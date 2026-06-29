"""
DLP classification engine.
Runs regex detection → Luhn validation → keyword scoring → risk aggregation.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from loguru import logger

try:
    import magic as _magic
    _MAGIC_AVAILABLE = True
except Exception:  # pragma: no cover
    _MAGIC_AVAILABLE = False
    logger.warning("python-magic not available – file-type detection disabled")

from .dictionaries import KEYWORDS

# ── Luhn algorithm ─────────────────────────────────────────────────────────────

def _luhn_check(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0

# ── Value masking helpers ──────────────────────────────────────────────────────

def _mask_card(raw: str) -> str:
    digits = re.sub(r"\D", "", raw)
    return f"****-****-****-{digits[-4:]}"

def _mask_ssn(raw: str) -> str:
    return f"***-**-{raw[-4:]}"

def _mask_email(raw: str) -> str:
    if "@" not in raw:
        return raw
    local, domain = raw.split("@", 1)
    return f"{local[0]}{'*' * max(1, len(local)-1)}@{domain}"

def _mask_iban(raw: str) -> str:
    c = re.sub(r"\s", "", raw)
    return f"{c[:4]}...{c[-4:]}"

def _mask_nin(raw: str) -> str:
    return f"{raw[:2]}{'*' * 6}{raw[-1]}"

def _mask_tail(raw: str, keep: int = 4) -> str:
    if len(raw) <= keep:
        return raw
    return "*" * (len(raw) - keep) + raw[-keep:]

def _mask_phone(raw: str) -> str:
    digits = re.sub(r"\D", "", raw)
    return f"+{'*' * (len(digits) - 3)}{digits[-3:]}"

# ── Pattern dataclass ──────────────────────────────────────────────────────────

@dataclass
class _Pat:
    name: str
    pattern: re.Pattern
    rule: str
    weight: float
    confidence: float
    mask: Callable[[str], str]
    luhn: bool = False

# ── Ordered pattern list (high-confidence / high-priority first) ───────────────
# Order matters: matched spans are "consumed" so generic patterns (8-digit CIN)
# don't double-fire on digits already claimed by a credit card or IBAN.

PATTERNS: List[_Pat] = [

    # ── Payment / banking ──────────────────────────────────────────────────────
    _Pat(
        name="credit_card",
        pattern=re.compile(
            r"\b(?:"
            # Visa 16-digit (with optional separators)
            r"4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}"
            r"|4[0-9]{12}"                                          # Visa 13
            r"|5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}"  # MC classic
            r"|2[2-7][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}"  # MC 2xxx
            r"|3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}"       # Amex 15
            r")\b"
        ),
        rule="PCI-DSS",
        weight=0.40,
        confidence=0.99,
        mask=_mask_card,
        luhn=True,
    ),

    _Pat(
        name="iban",
        pattern=re.compile(
            r"\b(?:"
            r"TN[0-9]{2}[0-9]{20}"                      # Tunisian IBAN (TN + 2 check + 20 digits)
            r"|[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}"         # Generic international IBAN
            r")\b"
        ),
        rule="PCI-DSS",
        weight=0.30,
        confidence=0.95,
        mask=_mask_iban,
    ),

    _Pat(
        name="swift_bic",
        pattern=re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"),
        rule="PCI-DSS",
        weight=0.25,
        confidence=0.85,
        mask=lambda r: _mask_tail(r, 4),
    ),

    # ── Government / national IDs ──────────────────────────────────────────────
    _Pat(
        name="ssn",
        # Exclude invalid SSNs (000, 666, 9xx area; 00 group; 0000 serial)
        pattern=re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        rule="HIPAA",
        weight=0.25,
        confidence=0.97,
        mask=_mask_ssn,
    ),

    _Pat(
        name="nin_uk",
        # UK NIN: two letters, six digits, one letter A-D
        pattern=re.compile(
            r"\b(?![DFIQUV])[A-Z](?![DFIQUVO])[A-Z]\d{6}[A-D]\b",
            re.IGNORECASE,
        ),
        rule="GDPR",
        weight=0.25,
        confidence=0.92,
        mask=_mask_nin,
    ),

    _Pat(
        name="passport",
        # Generic: 1-2 uppercase letters followed by 7-9 digits
        pattern=re.compile(r"\b[A-Z]{1,2}[0-9]{7,9}\b"),
        rule="GDPR/loi-09-08",
        weight=0.25,
        confidence=0.75,
        mask=lambda r: _mask_tail(r, 4),
    ),

    # French CNI – 12 consecutive digits (must come before CIN_TN to claim span)
    _Pat(
        name="cin_france",
        pattern=re.compile(r"\b[0-9]{12}\b"),
        rule="GDPR",
        weight=0.25,
        confidence=0.70,
        mask=lambda r: _mask_tail(r, 4),
    ),

    # Tunisian CIN – exactly 8 digits (applied last to avoid submatches)
    _Pat(
        name="cin_tunisia",
        pattern=re.compile(r"\b[0-9]{8}\b"),
        rule="GDPR/loi-09-08",
        weight=0.25,
        confidence=0.72,
        mask=lambda r: _mask_tail(r, 4),
    ),

    # ── Contact info ───────────────────────────────────────────────────────────
    _Pat(
        name="email",
        pattern=re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        rule="GDPR",
        weight=0.15,
        confidence=0.90,
        mask=_mask_email,
    ),

    _Pat(
        name="phone_tunisia",
        pattern=re.compile(
            r"(?:\+216|00216)[\s.\-]?[2-9][0-9][\s.\-]?[0-9]{3}[\s.\-]?[0-9]{3}\b"
        ),
        rule="GDPR/loi-09-08",
        weight=0.10,
        confidence=0.88,
        mask=_mask_phone,
    ),

    _Pat(
        name="phone_international",
        pattern=re.compile(
            r"\+(?!216)[1-9]\d{1,3}[\s.\-]?\(?\d{1,4}\)?[\s.\-]?\d{1,4}[\s.\-]?\d{1,9}\b"
        ),
        rule="GDPR",
        weight=0.10,
        confidence=0.75,
        mask=_mask_phone,
    ),
]

# ── Span-aware pattern runner ──────────────────────────────────────────────────

def _run_patterns(text: str) -> List[Dict[str, Any]]:
    """Return detections; each pattern consumes its spans so generics don't double-fire."""
    claimed: set[int] = set()
    detections: List[Dict[str, Any]] = []

    for pat in PATTERNS:
        for m in pat.pattern.finditer(text):
            span_set = set(range(m.start(), m.end()))
            if span_set & claimed:          # already claimed by a higher-priority pattern
                continue

            raw = m.group()

            if pat.luhn and not _luhn_check(raw):
                continue

            claimed |= span_set
            detections.append({
                "type": pat.name,
                "value": pat.mask(raw),
                "rule": pat.rule,
                "confidence": pat.confidence,
                "_raw": raw,
                "_weight": pat.weight,
            })
            logger.debug(f"Detected {pat.name}: {pat.mask(raw)}")

    return detections

# ── Keyword scanner ────────────────────────────────────────────────────────────

def _run_keywords(text: str) -> List[Dict[str, Any]]:
    """Scan for sensitive keywords; return detection dicts."""
    text_lower = text.lower()
    hits: List[Dict[str, Any]] = []
    for key, (kw, weight, rule) in KEYWORDS.items():
        if kw.lower() in text_lower:
            hits.append({
                "type": "keyword",
                "value": kw,
                "rule": rule,
                "confidence": 0.80,
                "_weight": weight,
            })
            logger.debug(f"Keyword hit: {kw} → {rule}")
    return hits

# ── File type detection ────────────────────────────────────────────────────────

def _detect_file_type(raw_bytes: bytes) -> Optional[str]:
    if not _MAGIC_AVAILABLE:
        return None
    try:
        return _magic.from_buffer(raw_bytes, mime=True)
    except Exception as e:
        logger.warning(f"magic error: {e}")
        return None

# ── Evidence excerpt builder ───────────────────────────────────────────────────

def _build_excerpt(text: str, detections: List[Dict]) -> str:
    """Return first 300 chars of text with raw sensitive values replaced by their masked form."""
    excerpt = text[:300]
    for d in detections:
        raw = d.get("_raw", "")
        if raw and raw in excerpt:
            excerpt = excerpt.replace(raw, d["value"])
    return excerpt + ("..." if len(text) > 300 else "")

# ── Public classify function ───────────────────────────────────────────────────

def classify_text(
    text: Optional[str],
    file_b64: Optional[str],
) -> Dict[str, Any]:
    """
    Main classification entry point.

    Args:
        text:     Plain-text content to analyse (optional).
        file_b64: Base64-encoded file bytes (optional). Decoded for file-type
                  detection; text extracted via UTF-8 best-effort.

    Returns:
        Structured classification result.
    """
    if not text and not file_b64:
        return {
            "risk_score": 0.0,
            "sensitive": False,
            "detections": [],
            "evidence_excerpt": "",
            "file_type": None,
        }

    file_type: Optional[str] = None
    combined_text = text or ""

    if file_b64:
        try:
            raw_bytes = base64.b64decode(file_b64)
            file_type = _detect_file_type(raw_bytes)
            # Best-effort text extraction (PDF/Office would need dedicated parsers)
            extracted = raw_bytes.decode("utf-8", errors="ignore")
            combined_text = (combined_text + "\n" + extracted).strip()
        except Exception as e:
            logger.warning(f"Could not decode file_b64: {e}")

    # ── Run detectors ──────────────────────────────────────────────────────────
    pattern_hits = _run_patterns(combined_text)
    keyword_hits = _run_keywords(combined_text)

    # ── Risk scoring ───────────────────────────────────────────────────────────
    risk = 0.0

    # Each detected pattern TYPE adds its weight once
    seen_types: set[str] = set()
    for hit in pattern_hits:
        if hit["type"] not in seen_types:
            seen_types.add(hit["type"])
            risk += hit["_weight"]

    # Keywords accumulate up to 0.30
    keyword_risk = min(sum(h["_weight"] for h in keyword_hits), 0.30)
    risk = min(risk + keyword_risk, 1.0)

    # ── Build public detections (strip internal fields) ────────────────────────
    all_hits = pattern_hits + keyword_hits
    public_detections = [
        {
            "type": h["type"],
            "value": h["value"],
            "rule": h["rule"],
            "confidence": h["confidence"],
        }
        for h in all_hits
    ]

    evidence_excerpt = _build_excerpt(combined_text, all_hits)

    return {
        "risk_score": round(risk, 3),
        "sensitive": risk > 0.0,
        "detections": public_detections,
        "evidence_excerpt": evidence_excerpt,
        "file_type": file_type or ("text/plain" if text else None),
    }
