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

ROW CORRELATION
A reference set can require several fields of the SAME RECORD to appear before
it fires -- name AND account number, not either alone. Set `min_fields` on the
set (1, the default, is per-value matching; 2+ correlates).

This is what makes a common column safe to index. "Okafor" on its own is a
surname thousands of people share and indexing it per-value guarantees false
positives; "Okafor" alongside that specific customer's account number is not a
coincidence. Without correlation the only safe columns are the distinctive
ones, which excludes most of what an organisation would want to protect.

Attribution is per (column, row), never per digest: a value can be a surname
in one record and a city in another -- Lincoln, Preston, Washington -- and
crediting one token to both fields of both records would manufacture exactly
the false positives this mode removes.

WHAT IT COSTS, STATED PLAINLY
Correlation requires knowing which digests belong to the same record, so a
correlated set stores that linkage. The values remain hashed and unrecoverable,
but a stolen correlated index reveals STRUCTURE the flat one does not: that
digest A and digest B describe the same person. Against a low-entropy column
that is a real escalation -- crack one surname by dictionary attack and you
have learned which account number sits beside it.

That is why the linkage is written only when `min_fields` > 1. A set that does
not use correlation stores exactly what it always stored: an unordered bag of
digests per column, with no way to tell which of them belong together.
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


# Set once the fallback has been reported, so a per-call warning does not
# drown the log on a scan that hashes thousands of candidates.
_warned_default_salt = False


def _salt() -> bytes:
    """The per-deployment secret, or a loud fallback.

    The default is a literal in this file, which means it is in the public
    repository: an index salted with it is salted with a value the attacker
    already has, and every low-entropy digest -- a surname, a six-digit
    account number -- falls to a dictionary attack in seconds. That is the
    entire property EDM depends on.

    Falling back silently was the problem. A deployment that never set
    EDM_SALT looked identical to one that did, right up until the index was
    stolen. It now says so, once, at CRITICAL.
    """
    global _warned_default_salt
    configured = os.environ.get(_SALT_ENV)
    if configured:
        return configured.encode("utf-8")

    if not _warned_default_salt:
        _warned_default_salt = True
        logger.critical(
            f"[EDM] {_SALT_ENV} is not set -- falling back to the built-in "
            f"development salt, which is a literal in this file and therefore "
            f"public. Digests built with it are dictionary-attackable by "
            f"anyone who can read the source. Set {_SALT_ENV} before indexing "
            f"real records."
        )
    return _DEFAULT_SALT.encode("utf-8")


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

    `row_index` is the same data keyed by record: column -> digest -> the row
    numbers that digest came from. It is what makes correlation possible --
    without it a set is a flat bag of digests and "these two values belong to
    the SAME customer" is not a question it can answer. It is populated only
    when `min_fields` > 1, because it is not free: see the note on
    `min_fields` below.

    `min_fields` is how many DISTINCT columns of one record must appear in a
    document before that record counts as matched. 1 (the default) is the
    per-value behaviour: any single indexed value fires. 2 or more is
    correlation.
    """
    name: str
    columns: dict[str, set[str]] = field(default_factory=dict)
    rule: str = "INTERNAL"
    created_at: str = ""
    # Longest indexed value in words. Scanning generates word sequences up to
    # this length and no further -- a set of single-column account numbers
    # should not cost the same to scan as one holding full postal addresses.
    max_words: int = 1
    # column -> digest -> row numbers. Empty when min_fields <= 1.
    row_index: dict[str, dict[str, set[int]]] = field(default_factory=dict)
    # Build-time feedback, NOT persisted -- it describes the upload, not the
    # set. Columns whose every value was too short to index vanish silently
    # otherwise: an account reference like "CR-1" normalises to "cr1", three
    # characters, under _MIN_VALUE_LEN. The uploader sees a set with fewer
    # columns than they submitted and no explanation, which is how someone
    # ends up believing a field is protected when it was never indexed.
    skipped_columns: list[str] = field(default_factory=list)
    skipped_values: int = 0
    # Distinct columns of one row required before that row is a match.
    min_fields: int = 1
    row_count: int = 0

    @property
    def correlated(self) -> bool:
        return self.min_fields > 1 and bool(self.row_index)

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
    min_fields: int = 1,
) -> ReferenceSet:
    """
    Hash a list of record dicts into a reference set.

    `rows` is consumed and discarded -- nothing but digests is retained, and
    the caller is expected to hold the raw data no longer than this call.

    `min_fields` > 1 additionally records WHICH ROW each digest came from, so
    matching can require several fields of the same record. That linkage is
    the point of correlation and also its cost -- see the module docstring --
    so it is built only when correlation is actually asked for.
    """
    min_fields = max(1, int(min_fields or 1))
    columns: dict[str, set[str]] = {}
    row_index: dict[str, dict[str, set[int]]] = {}
    skipped = 0
    max_words = 1
    row_count = 0
    # Every column name seen, so one whose values were ALL too short can be
    # named rather than merely missing from the result.
    seen_columns: set[str] = set()

    for row in rows or []:
        if not isinstance(row, dict):
            continue
        row_id = row_count
        row_count += 1
        for column, value in row.items():
            if value is None:
                continue
            seen_columns.add(str(column))
            norm = normalise(value)
            if len(norm) < min_len:
                # Too short to be distinctive -- indexing it would fire on
                # ordinary prose.
                skipped += 1
                continue
            col = str(column)
            digest = fingerprint(value, salt)
            columns.setdefault(col, set()).add(digest)
            if min_fields > 1:
                row_index.setdefault(col, {}).setdefault(digest, set()).add(row_id)
            max_words = max(max_words, min(word_count(value), _MAX_PHRASE_WORDS))

    rs = ReferenceSet(
        name=name,
        columns=columns,
        rule=rule,
        max_words=max_words,
        row_index=row_index,
        min_fields=min_fields,
        row_count=row_count,
        skipped_columns=sorted(seen_columns - set(columns)),
        skipped_values=skipped,
    )
    logger.info(
        f"[EDM] Built '{name}': {rs.total_values} values across "
        f"{len(columns)} column(s), {row_count} row(s), up to {max_words} "
        f"word(s), {skipped} too short to index"
        + (f" | correlated: {min_fields} field(s) of one row required"
           if min_fields > 1 else "")
    )
    if rs.skipped_columns:
        logger.warning(
            f"[EDM] '{name}' -- column(s) {rs.skipped_columns} indexed NOTHING: "
            f"every value was under {min_len} characters after normalisation"
        )
    if min_fields > len(columns) and columns:
        # Nothing can ever satisfy this -- say so at build time rather than
        # letting the set sit there silently matching nothing forever.
        logger.warning(
            f"[EDM] '{name}' requires {min_fields} fields but has only "
            f"{len(columns)} column(s) -- it can never match"
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

    Two modes, chosen per reference set by its `min_fields`:

    PER-VALUE (min_fields == 1, the default). A hit means "this document
    contains a value that appears somewhere in the reference set". A common
    value -- a shared surname, a city -- will match documents that have
    nothing to do with that record, so a per-value set should index
    distinctive columns only.

    PER-ROW (min_fields >= 2). A hit means "this document contains
    min_fields different fields OF THE SAME RECORD". That is what makes a
    common column safe to index: "Okafor" alone is noise, "Okafor" together
    with that customer's own account number is not a coincidence. Reported
    per record matched, not per column.
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
        if rs.correlated:
            detections.extend(_match_rows(rs, hashed))
        else:
            detections.extend(_match_values(rs, hashed))
        if len(detections) >= max_hits:
            return detections[:max_hits]

    return detections


def _match_values(rs: ReferenceSet, hashed: dict[str, str]) -> list[dict]:
    """Per-value matching: any indexed value present in the text fires."""
    per_column: dict[str, int] = {}
    for digest in hashed.values():
        if not digest:
            continue
        for column, digests in rs.columns.items():
            if digest in digests:
                per_column[column] = per_column.get(column, 0) + 1

    out: list[dict] = []
    for column, count in sorted(per_column.items(), key=lambda kv: -kv[1]):
        out.append({
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
    return out


def _match_rows(rs: ReferenceSet, hashed: dict[str, str]) -> list[dict]:
    """
    Per-row matching: a record counts only when `min_fields` distinct columns
    of THAT row appear in the text.

    Attribution is per (column, row), never per digest alone. The same value
    can legitimately sit in different columns of different records -- two
    customers sharing a surname, an account number reused as a reference --
    and crediting such a digest to the wrong row would invent correlations
    that do not exist, which is precisely the false positive this mode is
    supposed to remove.
    """
    per_row: dict[int, set[str]] = {}
    for digest in hashed.values():
        if not digest:
            continue
        for column, by_digest in rs.row_index.items():
            rows = by_digest.get(digest)
            if not rows:
                continue
            for row_id in rows:
                per_row.setdefault(row_id, set()).add(column)

    matched = {rid: cols for rid, cols in per_row.items()
               if len(cols) >= rs.min_fields}
    if not matched:
        return []

    # Group the matched records by WHICH combination of columns they hit, so
    # the report reads "3 records matched on name+account" rather than three
    # near-identical detections.
    by_combo: dict[tuple[str, ...], int] = {}
    for cols in matched.values():
        key = tuple(sorted(cols))
        by_combo[key] = by_combo.get(key, 0) + 1

    out: list[dict] = []
    for combo, records in sorted(by_combo.items(), key=lambda kv: (-kv[1], kv[0])):
        fields = "+".join(combo)
        out.append({
            "type": f"edm:{rs.name}:row",
            # Names the columns and how many records -- never a value, and
            # never anything that identifies WHICH records.
            "value": (f"{records} record(s) matching {rs.name} "
                      f"on {len(combo)} field(s): {fields}"),
            "rule": rs.rule,
            "confidence": 0.99,
            # Deliberately heavier than a per-value hit. Several fields of one
            # real record appearing together is not a coincidence the way a
            # single shared surname is, and it scales with how much of the
            # record leaked.
            "_weight": min(0.9, 0.4 + 0.15 * len(combo) + 0.05 * (records - 1)),
            "_edm": True,
            "_count": records,
            "_fields": list(combo),
        })
    return out


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
    payload: dict = {
        "name": rs.name,
        "rule": rs.rule,
        "createdAt": rs.created_at,
        "maxWords": rs.max_words,
        "minFields": rs.min_fields,
        "rowCount": rs.row_count,
    }
    if rs.correlated:
        # Correlated sets persist the row linkage; `columns` is derived from
        # it on load rather than stored twice. A per-value set writes exactly
        # the file it has always written -- opting out of correlation opts out
        # of storing which values belong to the same person.
        payload["rowIndex"] = {
            col: {dig: sorted(rows) for dig, rows in sorted(by_digest.items())}
            for col, by_digest in sorted(rs.row_index.items())
        }
    else:
        payload["columns"] = {k: sorted(v) for k, v in rs.columns.items()}
    path.write_text(json.dumps(payload), encoding="utf-8")
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
            row_index = {
                col: {dig: set(rows) for dig, rows in (by_digest or {}).items()}
                for col, by_digest in (raw.get("rowIndex") or {}).items()
            }
            if row_index:
                # Derived, not stored -- one source of truth for which digests
                # a column holds.
                columns = {col: set(by.keys()) for col, by in row_index.items()}
            else:
                columns = {k: set(v) for k, v in (raw.get("columns") or {}).items()}
            # A file written before correlation existed has neither key, and
            # loads as exactly what it was: a per-value set.
            out.append(ReferenceSet(
                name=raw.get("name") or path.stem,
                columns=columns,
                rule=raw.get("rule") or "INTERNAL",
                created_at=raw.get("createdAt") or "",
                max_words=int(raw.get("maxWords") or 1),
                row_index=row_index,
                min_fields=int(raw.get("minFields") or 1),
                row_count=int(raw.get("rowCount") or 0),
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
