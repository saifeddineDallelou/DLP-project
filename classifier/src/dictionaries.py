"""
Weighted keyword dictionaries for DLP content classification.
Each keyword carries a weight (added to risk) and a compliance rule tag.
"""

from typing import Dict, List, Tuple

# (keyword, weight_contribution, compliance_rule)
_KW = Tuple[str, float, str]

KEYWORDS: Dict[str, List[_KW]] = {
    # ── General sensitive (INTERNAL / GDPR) ─────────────────────────────────
    "confidential":   ("confidential",   0.08, "INTERNAL"),
    "secret":         ("secret",         0.06, "INTERNAL"),
    "restricted":     ("restricted",     0.06, "INTERNAL"),
    "password":       ("password",       0.10, "INTERNAL"),
    "credentials":    ("credentials",    0.10, "INTERNAL"),
    "api_key":        ("api_key",        0.10, "INTERNAL"),
    "api key":        ("api key",        0.10, "INTERNAL"),
    "salary":         ("salary",         0.08, "GDPR"),
    "payroll":        ("payroll",        0.08, "GDPR"),
    # French equivalents
    "confidentiel":   ("confidentiel",   0.08, "INTERNAL"),
    "restreint":      ("restreint",      0.06, "INTERNAL"),
    "mot de passe":   ("mot de passe",   0.10, "INTERNAL"),
    "salaire":        ("salaire",        0.08, "GDPR"),

    # ── Medical / HIPAA ──────────────────────────────────────────────────────
    "patient":        ("patient",        0.10, "HIPAA"),
    "medical":        ("medical",        0.10, "HIPAA"),
    "diagnosis":      ("diagnosis",      0.10, "HIPAA"),
    "prescription":   ("prescription",   0.10, "HIPAA"),
    "health record":  ("health record",  0.12, "HIPAA"),
    # French
    "médical":        ("médical",        0.10, "HIPAA"),
    "médication":     ("médication",     0.10, "HIPAA"),
    "ordonnance":     ("ordonnance",     0.10, "HIPAA"),
    "dossier médical":("dossier médical",0.12, "HIPAA"),
}
