"""
Exact Data Match (EDM).

Regex answers "does this LOOK like a card number". EDM answers "is this OUR
customer's card number" -- matching content against a hash of the
organisation's actual records rather than against a shape. That difference is
the whole point:

  * regex flags every 16-digit Luhn-valid string, including test data,
    example numbers in documentation, and a colleague's own card
  * EDM flags only values that appear in the reference set, so a document
    containing 400 real customer records is unmistakable and a document
    containing one made-up example is not

It also detects what no pattern can: a customer NAME, an account reference, an
internal employee ID -- values with no distinguishing shape at all. A regex
cannot be written for "Sarah Okafor"; a hash lookup does not need one.

THE RAW VALUES ARE NEVER STORED.

A reference set is built by hashing each value and keeping only the digest.
Uploading a customer database to a DLP tool would create exactly the
concentration of sensitive data the tool exists to prevent, and "we hold a
copy of your customer list to protect your customer list" is not a defensible
position. Only salted digests are persisted, so a stolen index yields nothing
directly usable.

WHAT THIS IS NOT
Commercial EDM (Purview, Symantec) indexes multi-column records and can
require several fields from the SAME ROW to match before it fires -- name AND
account number AND balance, which suppresses the false positives a single
common column produces. This implementation matches per-value, not per-row.
Row correlation is the honest next step and is not implemented; see
`match_text`'s docstring for why the distinction matters.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger

# A per-deployment secret. Without it, digests of low-entropy values (a
# surname, a six-digit account number) fall to a dictionary attack in
# seconds -- the search space is small enough to enumerate. The salt makes a
# stolen index useless without also stealing the key.
_SALT_ENV = "EDM_SALT"
_DEFAULT_SALT = "dlp-edm-development-salt-change-me"

# Values shorter than this are not indexed. A 3-character token appears in
# ordinary prose constantly, and indexing one guarantees false positives on
# every document.
_MIN_VALUE_LEN = 4

# Upper bound on indexed phrase length, and therefore on n-gram generation
# when scanning. A postal address is the realistic worst case; beyond this the
# candidate count grows without catching anything a shorter phrase would miss.
_MAX_PHRASE_WORDS = 6

# Tokens considered when scanning text. Anything shorter cannot match an
# indexed value anyway.
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+\-']{2,}")
# Runs of digits with separators, so "4111 1111 1111 1111" and
# "4111-1111-1111-1111" both reduce to the same candidate as the stored
# "4111111111111111". A reference set built from a database export will hold
# the unformatted form; a document will not.
_DIGIT_RUN_RE = re.compile(r"\d[\d\s\-]{3,}\d")


def _salt() -> bytes:
    return os.environ.get(_SALT_ENV, _DEFAULT_SALT).encode("utf-8")


# Word processors substitute these for the ASCII characters a database holds.
# NFKD decomposes accents but does NOT map a typographic apostrophe to a
# straight one, so "O'Brien" from a CSV and "O’Brien" from a .docx would
# otherwise hash differently and never match.
_PUNCT_FOLD = str.maketrans({
    "‘": "'", "’": "'", "‚": "'", "‛": "'",
    "“": '"', "”": '"', "„": '"',
    "–": "-", "—": "-", "−": "-",
    " ": " ",
})


def normalise(value: str) -> str:
    """
    Reduce a value to the form both sides agree on.

    A database holds "O'Brien"; a document might hold "o'brien" or "O’Brien".
    A phone number is stored as "+216 22 123 456" and written as
    "+21622123456". Without normalisation EDM matches only values that happen
    to be formatted identically, which in practice means almost nothing.
    """
    if value is None:
        return ""
    text = str(value).translate(_PUNCT_FOLD)
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = text.casefold().strip()
    # Collapse the separators that differ between a database and a document.
    text = re.sub(r"[\s\-_().]+", "", text)
    return text


def word_count(value: str) -> int:
    """Whitespace-separated words in a raw value, before normalisation
    collapses them. Used to bound n-gram generation when scanning."""
    return len(str(value or "").split())


def fingerprint(value: str, salt: bytes | None = None) -> str:
    """Salted digest of a normalised value. One-way: the raw value cannot be
    recovered, which is the entire security property of this module."""
    norm = normalise(value)
    if not norm:
        return ""
    return hmac.new(salt or _salt(), norm.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass
class ReferenceSet:
    """
    A hashed index of an organisation's real records.

    `columns` maps a column name to the set of digests in it, so a match can
    say WHICH field it hit -- "customer_email", not merely "something".
    """
    name: str
    columns: dict[str, set[str]] = field(default_factory=dict)
    rule: str = "INTERNAL"
    created_at: str = ""
    # Longest indexed value in words. Scanning generates word sequences up to
    # this length and no further -- a set of single-column account numbers
    # should not cost the same to scan as one holding full postal addresses.
    max_words: int = 1

    @property
    def total_values(self) -> int:
        return sum(len(v) for v in self.columns.values())

    def digests(self) -> set[str]:
        out: set[str] = set()
        for v in self.columns.values():
            out |= v
        return out


def build_reference_set(
    name: str,
    rows: list[dict],
    *,
    rule: str = "INTERNAL",
    salt: bytes | None = None,
    min_len: int = _MIN_VALUE_LEN,
) -> ReferenceSet:
    """
    Hash a list of record dicts into a reference set.

    `rows` is consumed and discarded -- nothing but digests is retained, and
    the caller is expected to hold the raw data no longer than this call.
    """
    columns: dict[str, set[str]] = {}
    skipped = 0
    max_words = 1

    for row in rows or []:
        if not isinstance(row, dict):
            continue
        for column, value in row.items():
            if value is None:
                continue
            norm = normalise(value)
            if len(norm) < min_len:
                # Too short to be distinctive -- indexing it would fire on
                # ordinary prose.
                skipped += 1
                continue
            columns.setdefault(str(column), set()).add(fingerprint(value, salt))
            max_words = max(max_words, min(word_count(value), _MAX_PHRASE_WORDS))

    rs = ReferenceSet(name=name, columns=columns, rule=rule, max_words=max_words)
    logger.info(
        f"[EDM] Built '{name}': {rs.total_values} values across "
        f"{len(columns)} column(s), up to {max_words} word(s), "
        f"{skipped} too short to index"
    )
    return rs


def _candidates(text: str, max_words: int = 1) -> set[str]:
    """
    Every substring of `text` worth hashing.

    Single tokens, separator-stripped digit runs, AND word sequences up to
    `max_words`. The last of those is not optional: an indexed value like
    "Sarah Okafor" is one value, but a document tokenised word-by-word yields
    "Sarah" and "Okafor" separately and would never match it -- which would
    have silently disabled EDM for exactly the values regex cannot describe.

    `max_words` comes from the reference set, so a set of single-column
    account numbers costs one pass and only a set that actually contains
    multi-word values pays for n-grams.
    """
    out: set[str] = set()

    tokens = [m.group() for m in _TOKEN_RE.finditer(text or "")]
    out.update(tokens)

    n = max(1, min(int(max_words or 1), _MAX_PHRASE_WORDS))
    for size in range(2, n + 1):
        for i in range(len(tokens) - size + 1):
            out.add(" ".join(tokens[i:i + size]))

    for m in _DIGIT_RUN_RE.finditer(text or ""):
        out.add(m.group())

    return out


def match_text(
    text: str,
    reference_sets: list[ReferenceSet],
    *,
    salt: bytes | None = None,
    max_hits: int = 50,
) -> list[dict]:
    """
    Find values from any reference set present in `text`.

    Returns detections in the same shape the regex engine produces, so a
    caller can merge them without special-casing. The `value` reported is a
    column name and a count -- never the matched content, which by definition
    is a real customer record.

    PER-VALUE, NOT PER-ROW. A hit means "this document contains a value that
    appears somewhere in the reference set". Commercial EDM can require
    several fields from the SAME ROW before firing, which is what makes a
    single common column (a city, a shared surname) safe to index. Here, a
    common value in the reference set will match documents that have nothing
    to do with that record -- so index distinctive columns, not every column.
    """
    if not text or not reference_sets:
        return []

    # One candidate pass sized to the longest phrase any set indexes, then
    # hash each candidate once rather than once per set.
    widest = max((rs.max_words or 1) for rs in reference_sets)
    candidates = _candidates(text, widest)
    if not candidates:
        return []

    hashed = {c: fingerprint(c, salt) for c in candidates}

    detections: list[dict] = []
    for rs in reference_sets:
        per_column: dict[str, int] = {}
        for _raw, digest in hashed.items():
            if not digest:
                continue
            for column, digests in rs.columns.items():
                if digest in digests:
                    per_column[column] = per_column.get(column, 0) + 1

        for column, count in sorted(per_column.items(), key=lambda kv: -kv[1]):
            detections.append({
                "type": f"edm:{rs.name}:{column}",
                # Never the matched content: it is, by construction, a real
                # record from the organisation's own database.
                "value": f"{count} value(s) matching {rs.name}.{column}",
                "rule": rs.rule,
                # An exact match against a known record is far stronger
                # evidence than a pattern that merely fits a shape.
                "confidence": 0.99,
                "_weight": min(0.6, 0.25 + 0.05 * count),
                "_edm": True,
                "_count": count,
            })
            if len(detections) >= max_hits:
                return detections

    return detections


# ── Persistence ───────────────────────────────────────────────────────────────
#
# A reference set is a set of digests, so it is safe at rest in a way the
# source data never is. Stored as JSON next to the classifier rather than in
# the backend database: it is classifier state, and the classifier is
# deliberately the only component that decides what is sensitive.

def _store_dir() -> Path:
    return Path(os.environ.get("EDM_STORE_DIR", Path(__file__).parent.parent / "edm_store"))


def save_reference_set(rs: ReferenceSet, directory: Path | None = None) -> Path:
    d = Path(directory) if directory else _store_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', rs.name)}.json"
    path.write_text(json.dumps({
        "name": rs.name,
        "rule": rs.rule,
        "createdAt": rs.created_at,
        "maxWords": rs.max_words,
        "columns": {k: sorted(v) for k, v in rs.columns.items()},
    }), encoding="utf-8")
    logger.info(f"[EDM] Saved '{rs.name}' ({rs.total_values} digests) to {path}")
    return path


def load_reference_sets(directory: Path | None = None) -> list[ReferenceSet]:
    d = Path(directory) if directory else _store_dir()
    if not d.is_dir():
        return []

    out: list[ReferenceSet] = []
    for path in sorted(d.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            out.append(ReferenceSet(
                name=raw.get("name") or path.stem,
                columns={k: set(v) for k, v in (raw.get("columns") or {}).items()},
                rule=raw.get("rule") or "INTERNAL",
                created_at=raw.get("createdAt") or "",
                max_words=int(raw.get("maxWords") or 1),
            ))
        except Exception as exc:
            # One corrupt file must not stop every other set from loading.
            logger.error(f"[EDM] Could not load {path.name}: {exc}")
    return out


def delete_reference_set(name: str, directory: Path | None = None) -> bool:
    d = Path(directory) if directory else _store_dir()
    path = d / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', name)}.json"
    if path.is_file():
        path.unlink()
        logger.info(f"[EDM] Deleted reference set '{name}'")
        return True
    return False
