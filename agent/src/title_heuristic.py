"""
"Does this NAME look sensitive?" -- for the channels that have no content to read.

Most channels classify content: a file is extracted, a clipboard payload is
read, an upload is sampled. Two cannot. A screenshot is pixels, and a print
job is a spooled render owned by the driver -- neither hands a user-mode agent
text to send to the classifier. What both DO have is a name: the title of the
window that was captured, the title of the document that was printed.

That is a real signal and a weak one, and it is treated as both. It carries a
confidence of 0.6, not the 0.95 a matched card number earns, and the matched
keyword is turned into a synthetic detection so the policy resolver can route
it to the compliance policy it actually implies. Resolving against an empty
detection list -- which is what the screenshot path did before these mappings
existed -- always lands on the default policy no matter which keyword matched,
so a payroll capture and a card-number capture were handled identically.

This lives in its own module because the print monitor needed it second. One
copy that both read is the reason repeat_window.py exists too.
"""

from __future__ import annotations

# Title substrings that make a capture or a print job worth acting on. This is
# a heuristic on TEXT IN A NAME, not classification of content -- widen it
# freely; the cost of a miss is a silent gap and the cost of a false hit is a
# recorded incident an analyst closes.
SENSITIVE_KEYWORDS = frozenset({
    "confidential", "client", "customer", "salary", "payroll",
    "ssn", "iban", "carte", "bancaire",
    "password", "secret", "dlp",
    "invoice", "contract", "budget",
    "personal", "private", "restricted", "internal",
    "bank", "account", "tax", "medical",
})

# Office documents announce themselves as "report_client.xlsx - Microsoft
# Excel", so the filename half is worth a narrower, less trigger-happy pass:
# "report" alone anywhere in a window title would match half the desktop.
SENSITIVE_FILENAME_KW = frozenset({
    "client", "customer", "confidential", "invoice", "contract", "budget", "report",
})

OFFICE_EXTS = frozenset({".xlsx", ".xls", ".docx", ".doc", ".pptx", ".ppt", ".pdf"})

# Which compliance rule a matched keyword implies -- the same rule vocabulary
# classifier/src/dictionaries.py uses, so a name-based hit reaches the same
# policy a content-based hit on the same subject would.
KEYWORD_RULE: dict[str, str] = {
    "confidential": "INTERNAL", "secret": "INTERNAL", "restricted": "INTERNAL",
    "password": "INTERNAL", "internal": "INTERNAL", "dlp": "INTERNAL",
    "contract": "INTERNAL", "budget": "INTERNAL", "report": "INTERNAL",
    "salary": "GDPR", "payroll": "GDPR", "personal": "GDPR", "private": "GDPR",
    "client": "GDPR", "customer": "GDPR", "tax": "GDPR",
    "ssn": "HIPAA", "medical": "HIPAA",
    "iban": "PCI-DSS", "carte": "PCI-DSS", "bancaire": "PCI-DSS",
    "bank": "PCI-DSS", "account": "PCI-DSS", "invoice": "PCI-DSS",
}

# What a name is worth. Real evidence, weaker than a content match, and the
# same number on both channels so one cannot quietly outrank the other.
TITLE_CONFIDENCE = 0.6


def matched_keyword(title: str) -> str | None:
    """The sensitive keyword this title matched, or None."""
    lower = (title or "").lower()
    for kw in SENSITIVE_KEYWORDS:
        if kw in lower:
            return kw
    for ext in OFFICE_EXTS:
        if ext in lower:
            filename_part = lower.split(" - ")[0].strip()
            for kw in SENSITIVE_FILENAME_KW:
                if kw in filename_part:
                    return kw
    return None


def is_sensitive(title: str) -> bool:
    return matched_keyword(title) is not None


def synthetic_detection(keyword: str) -> dict:
    """The matched keyword as a detection the policy resolver understands.

    Shaped exactly like a classifier keyword hit (type "keyword", the word in
    `value`), because the resolver's pattern gate reads `value` for those --
    see PolicyResolver._detection_matches_patterns. A detection shaped any
    other way would match a policy's configured patterns by accident or not
    at all.
    """
    return {
        "type": "keyword",
        "value": keyword,
        "rule": KEYWORD_RULE.get(keyword, "INTERNAL"),
        "confidence": TITLE_CONFIDENCE,
    }
