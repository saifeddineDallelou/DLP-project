"""
Pytest tests for the DLP classification engine.
Run from classifier/: pytest -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.engine import classify_text, _luhn_check


# ── Luhn ──────────────────────────────────────────────────────────────────────

def test_luhn_valid():
    assert _luhn_check("4532015112830366") is True   # Visa test number
    assert _luhn_check("5425233430109903") is True   # MC test number
    assert _luhn_check("371449635398431")  is True   # Amex test number

def test_luhn_invalid():
    assert _luhn_check("4532015112830367") is False  # last digit flipped
    assert _luhn_check("1234567890123456") is False


# ── Credit card detection ──────────────────────────────────────────────────────

def test_credit_card_visa():
    result = classify_text("Process card 4532015112830366 for payment", None)
    assert result["sensitive"] is True
    types = [d["type"] for d in result["detections"]]
    assert "credit_card" in types
    cc = next(d for d in result["detections"] if d["type"] == "credit_card")
    assert cc["rule"] == "PCI-DSS"
    assert cc["confidence"] == 0.99
    assert "****-****-****-0366" == cc["value"]
    assert result["risk_score"] >= 0.40

def test_credit_card_amex():
    result = classify_text("Amex: 371449635398431", None)
    types = [d["type"] for d in result["detections"]]
    assert "credit_card" in types

def test_credit_card_with_dashes():
    result = classify_text("Card: 4532-0151-1283-0366", None)
    types = [d["type"] for d in result["detections"]]
    assert "credit_card" in types

def test_invalid_luhn_not_flagged():
    result = classify_text("Number: 4532015112830367", None)  # bad Luhn
    types = [d["type"] for d in result["detections"]]
    assert "credit_card" not in types


# ── Tunisian CIN ───────────────────────────────────────────────────────────────

def test_tunisian_cin():
    result = classify_text("Numéro CIN: 12345678", None)
    types = [d["type"] for d in result["detections"]]
    assert "cin_tunisia" in types
    cin = next(d for d in result["detections"] if d["type"] == "cin_tunisia")
    assert cin["rule"] == "GDPR/loi-09-08"
    assert cin["value"].endswith("5678")

def test_combined_card_and_cin():
    """Core test requested by the user — one text with a credit card AND a CIN."""
    text = (
        "Employee file — CIN: 12345678\n"
        "Expense reimbursement card: 4532015112830366\n"
        "Contact: hr@company.tn"
    )
    result = classify_text(text, None)

    types = [d["type"] for d in result["detections"]]
    assert "credit_card" in types,  "Must detect credit card"
    assert "cin_tunisia" in types,  "Must detect Tunisian CIN"
    assert "email"       in types,  "Must detect email"
    assert result["sensitive"] is True
    assert result["risk_score"] >= 0.55   # 0.40 (card) + 0.15 (email) = 0.55 minimum
    # Credit card digits must NOT appear in the masked evidence excerpt
    assert "4532015112830366" not in result["evidence_excerpt"]


# ── SSN ────────────────────────────────────────────────────────────────────────

def test_ssn():
    result = classify_text("SSN: 123-45-6789", None)
    types = [d["type"] for d in result["detections"]]
    assert "ssn" in types
    ssn = next(d for d in result["detections"] if d["type"] == "ssn")
    assert ssn["rule"] == "HIPAA"
    assert ssn["value"] == "***-**-6789"


# ── IBAN ───────────────────────────────────────────────────────────────────────

def test_iban_tunisian():
    result = classify_text("IBAN: TN5910006035183598478831", None)
    types = [d["type"] for d in result["detections"]]
    assert "iban" in types
    ib = next(d for d in result["detections"] if d["type"] == "iban")
    assert ib["rule"] == "PCI-DSS"

def test_iban_international():
    result = classify_text("Bank: GB29NWBK60161331926819", None)
    types = [d["type"] for d in result["detections"]]
    assert "iban" in types


# ── Email ──────────────────────────────────────────────────────────────────────

def test_email():
    result = classify_text("Contact john.doe@example.com for details", None)
    types = [d["type"] for d in result["detections"]]
    assert "email" in types
    em = next(d for d in result["detections"] if d["type"] == "email")
    assert em["rule"] == "GDPR"
    assert "@example.com" in em["value"]

# ── UK NIN ─────────────────────────────────────────────────────────────────────

def test_nin_uk():
    result = classify_text("NIN: AB123456C", None)
    types = [d["type"] for d in result["detections"]]
    assert "nin_uk" in types


# ── Tunisian phone ─────────────────────────────────────────────────────────────

def test_phone_tunisia():
    result = classify_text("Call +216 22 123 456", None)
    types = [d["type"] for d in result["detections"]]
    assert "phone_tunisia" in types


# ── Keywords ───────────────────────────────────────────────────────────────────

def test_keyword_english():
    result = classify_text("This document is confidential and contains salary data", None)
    rules = [d["rule"] for d in result["detections"]]
    assert "INTERNAL" in rules
    assert "GDPR" in rules

def test_keyword_french():
    result = classify_text("Document confidentiel — salaire annuel 45000", None)
    types = [d["type"] for d in result["detections"] if d["type"] == "keyword"]
    assert len(types) >= 1

def test_keyword_medical_hipaa():
    result = classify_text("Patient medical record for John Smith", None)
    rules = [d["rule"] for d in result["detections"]]
    assert "HIPAA" in rules


# ── Risk score cap ─────────────────────────────────────────────────────────────

def test_risk_score_capped():
    text = (
        "Card 4532015112830366 IBAN TN5910006035183598478831 "
        "SSN 123-45-6789 patient medical confidential secret salary credentials"
    )
    result = classify_text(text, None)
    assert result["risk_score"] <= 1.0


# ── Clean text ─────────────────────────────────────────────────────────────────

def test_clean_text():
    result = classify_text("The weather is nice today in Tunis.", None)
    assert result["sensitive"] is False
    assert result["risk_score"] == 0.0
    assert result["detections"] == []


# ── Empty input ────────────────────────────────────────────────────────────────

def test_empty_input():
    result = classify_text(None, None)
    assert result["sensitive"] is False
    assert result["risk_score"] == 0.0
