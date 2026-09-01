"""
Builds the short "what was blocked" snippet sent to the backend with an
incident or AI leak attempt.

WHY THIS EXISTS
Clipboard reporting previously masked the RAW copied text with a length
heuristic:

    def _mask(text):
        t = text[:100]
        if len(t) > 30:
            return t[:15] + "***[MASKED]***" + t[-5:]
        return t            # <- anything 30 chars or shorter, returned intact

Sensitive values are short. A payment card is 19 characters, a US SSN is 11,
most API keys are under 30 -- so precisely the data this agent exists to
protect fell through unmasked and was stored in the database. Verified live: a
blocked clipboard paste wrote " 4111 1111 1111 1111" into
AiLeakAttempt.contentSample verbatim. A DLP tool retaining unmasked cardholder
data is itself a PCI-DSS Requirement 3 failure, which is the first thing an
assessor would look for.

Raising the threshold would not have fixed it. Any rule that decides what to
redact by counting characters is wrong for some input, and the >30 branch was
also unsafe: keeping the first 15 characters leaks most of a card number that
happens to sit at the start of the string.

THE APPROACH
Never derive the snippet from the raw text at all. The classifier already
returns each detection with its value masked (`****-****-****-1111`), so the
snippet is assembled from those instead. The agent therefore cannot leak what
it never had to handle: the raw value stays on the endpoint.
"""

from __future__ import annotations

_MAX_LEN = 100
_MAX_DETECTIONS = 4  # beyond this the snippet stops being scannable


def safe_sample(
    detections: list | None,
    prefix: str = "",
    limit: int = _MAX_LEN,
) -> str:
    """
    Build a reportable snippet from classifier detections.

    `detections` are classifier output items: {type, value, rule, confidence},
    where `value` is ALREADY masked by classifier/src/engine.py. Nothing here
    unmasks anything, and no caller should pass raw content in `prefix` --
    it is for non-sensitive context such as a filename.

    Returns a string like:
        credit_card ****-****-****-1111 (PCI-DSS), ssn ***-**-6789 (HIPAA)

    Falls back to a count-only description when there are no detections to
    name, so the snippet is never silently empty.
    """
    items = [d for d in (detections or []) if isinstance(d, dict)]

    parts: list[str] = []
    for d in items[:_MAX_DETECTIONS]:
        dtype = str(d.get("type") or "unknown")
        value = str(d.get("value") or "")
        rule = str(d.get("rule") or "")

        # A keyword detection's "value" is the matched dictionary word, not a
        # secret, but it is still content from the user's document -- report
        # the type and rule only.
        if dtype == "keyword" or not value:
            parts.append(f"{dtype} ({rule})" if rule else dtype)
        else:
            parts.append(f"{dtype} {value} ({rule})" if rule else f"{dtype} {value}")

    remaining = len(items) - _MAX_DETECTIONS
    if remaining > 0:
        parts.append(f"+{remaining} more")

    body = ", ".join(parts) if parts else f"{len(items)} detection(s)"
    text = f"{prefix} | {body}" if prefix else body
    return text[:limit]
