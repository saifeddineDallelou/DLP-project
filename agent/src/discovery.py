"""
Data-at-rest discovery scanner.

Every other monitor in this agent reacts to ACTIVITY -- a file created, a
clipboard change, a screenshot taken. None of them can see sensitive data
that is already sitting on a share and has been for two years. That is a
separate DLP pillar (Forcepoint calls it Discovery, Purview ships an on-prem
scanner, and the standalone category is now sold as DSPM), and this project
had no answer to it at all.

The classifier is already the right building block, so this is a harness
rather than new detection logic: walk a tree, call the same classify() the
live watcher calls, report what is found. Nothing here decides what is
sensitive -- that stays in classifier/src/engine.py, which is the whole
reason a second opinion never needs maintaining.

DELIBERATELY READ-ONLY. A discovery scan finds and reports; it never blocks,
quarantines or moves anything. A crawler with write authority over a file
share is a very different risk to sign off on, and remediation on findings
this scan cannot see the context of would be reckless. Auto-remediation is a
real feature of commercial products and a deliberate non-goal here.

Run:  python src/discovery.py C:/shared --max-files 5000
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger

# ── Limits ────────────────────────────────────────────────────────────────────

_MAX_FILE_SIZE = 20 * 1024 * 1024   # 20 MB, same cap as file_watcher
_CLASSIFY_LIMIT = 10_000            # chars sent per file, same as file_watcher
_SENSITIVE_THRESHOLD = 0.5          # same bar the live monitors use

# Directories that are never worth walking: build output, dependency trees and
# VCS metadata are enormous, machine-generated, and produce nothing but noise.
# Skipping them is the difference between a scan that finishes and one that
# doesn't.
_SKIP_DIRS = frozenset({
    ".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", ".nuxt", "target", "vendor", ".gradle",
    ".idea", ".vscode", "$RECYCLE.BIN", "System Volume Information",
})


@dataclass
class Finding:
    path: str
    size_bytes: int
    risk_score: float
    detections: list
    rule: str | None
    modified: float

    @property
    def types(self) -> list[str]:
        return sorted({d.get("type", "?") for d in self.detections})


@dataclass
class ScanResult:
    root: str
    started_at: float
    finished_at: float = 0.0
    files_seen: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    errors: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        return round((self.finished_at or time.time()) - self.started_at, 2)

    def by_rule(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            for d in f.detections:
                rule = d.get("rule")
                if rule:
                    out[rule] = out.get(rule, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def _should_skip_dir(name: str) -> bool:
    return name in _SKIP_DIRS or name.startswith(".")


def _matches_any(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(name.lower(), p.lower()) for p in patterns)


def iter_files(
    root: str,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    follow_symlinks: bool = False,
):
    """
    Walk `root`, yielding candidate file paths.

    Symlinks are NOT followed by default: a link pointing back up the tree
    turns a scan into an infinite loop, and on a real file share that is not
    a hypothetical.
    """
    include = include or []
    exclude = exclude or []

    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        # Prune in place so os.walk never descends into them at all.
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(d)]

        for name in filenames:
            if exclude and _matches_any(name, exclude):
                continue
            if include and not _matches_any(name, include):
                continue
            yield os.path.join(dirpath, name)


def scan_tree(
    root: str,
    client,
    extract_fn,
    *,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    max_files: int | None = None,
    threshold: float = _SENSITIVE_THRESHOLD,
    progress_every: int = 200,
    logger_=logger,
) -> ScanResult:
    """
    Walk `root` and classify every readable file.

    `client` needs only .classify(text=...); `extract_fn` only (path) -> str|None.
    Both are injected rather than imported so this is testable without a live
    classifier, and so a caller can point it at a different backend.
    """
    result = ScanResult(root=root, started_at=time.time())

    for path in iter_files(root, include, exclude):
        if max_files is not None and result.files_scanned >= max_files:
            logger_.warning(f"[DISCOVERY] Stopping at max-files={max_files}")
            break

        result.files_seen += 1

        try:
            size = os.path.getsize(path)
        except OSError:
            result.errors += 1
            continue

        if size == 0 or size > _MAX_FILE_SIZE:
            result.files_skipped += 1
            continue

        try:
            text = extract_fn(path)
        except Exception as exc:
            # One unreadable file must never abort a scan of 100,000 others.
            logger_.debug(f"[DISCOVERY] Extract failed for {path}: {exc}")
            result.errors += 1
            continue

        if not text:
            result.files_skipped += 1
            continue

        try:
            classified = client.classify(text=text[:_CLASSIFY_LIMIT])
        except Exception as exc:
            logger_.debug(f"[DISCOVERY] Classify failed for {path}: {exc}")
            result.errors += 1
            continue

        if classified is None:
            result.errors += 1
            continue

        result.files_scanned += 1
        if result.files_scanned % progress_every == 0:
            logger_.info(
                f"[DISCOVERY] {result.files_scanned} scanned, "
                f"{len(result.findings)} sensitive so far"
            )

        risk = float(classified.get("risk_score") or 0.0)
        if risk <= threshold:
            continue

        detections = classified.get("detections") or []
        rules = [d.get("rule") for d in detections if d.get("rule")]

        try:
            modified = os.path.getmtime(path)
        except OSError:
            modified = 0.0

        result.findings.append(Finding(
            path=path,
            size_bytes=size,
            risk_score=risk,
            detections=detections,
            rule=rules[0] if rules else None,
            modified=modified,
        ))
        logger_.warning(
            f"[DISCOVERY] SENSITIVE AT REST: {path} | risk={risk:.2f} | "
            f"rules={sorted(set(rules)) or ['-']}"
        )

    result.finished_at = time.time()
    return result


def format_report(result: ScanResult, top: int = 25) -> str:
    """Human-readable summary. Values in findings are already masked by the
    classifier, so this is safe to print, pipe to a file, or paste into a
    ticket -- the same guarantee agent/src/evidence.py relies on."""
    lines: list[str] = []
    add = lines.append

    add("")
    add("=" * 68)
    add("  DATA-AT-REST DISCOVERY REPORT")
    add("=" * 68)
    add(f"  Root            : {result.root}")
    add(f"  Duration        : {result.duration_s}s")
    add(f"  Files seen      : {result.files_seen}")
    add(f"  Files classified: {result.files_scanned}")
    add(f"  Skipped         : {result.files_skipped}  (empty, too large, or no extractable text)")
    add(f"  Errors          : {result.errors}")
    add(f"  SENSITIVE FILES : {len(result.findings)}")
    add("")

    by_rule = result.by_rule()
    if by_rule:
        add("  Detections by compliance rule")
        add("  " + "-" * 40)
        for rule, count in by_rule.items():
            add(f"    {rule:<28} {count}")
        add("")

    if result.findings:
        ranked = sorted(result.findings, key=lambda f: -f.risk_score)[:top]
        add(f"  Highest-risk files (top {len(ranked)})")
        add("  " + "-" * 64)
        for f in ranked:
            add(f"    [{f.risk_score:.2f}] {f.path}")
            add(f"           {', '.join(f.types)}  ({f.size_bytes / 1024:.0f} KB)")
        if len(result.findings) > len(ranked):
            add(f"    ... and {len(result.findings) - len(ranked)} more")
        add("")
    else:
        add("  No sensitive data found at rest in this tree.")
        add("")

    add("  Read-only scan: nothing was blocked, moved or modified.")
    add("=" * 68)
    return "\n".join(lines)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="discovery",
        description="Scan a directory tree for sensitive data already at rest.",
    )
    parser.add_argument("root", help="Directory to scan")
    parser.add_argument("--include", nargs="*", default=None, help="Only these globs, e.g. *.pdf *.docx")
    parser.add_argument("--exclude", nargs="*", default=None, help="Skip these globs")
    parser.add_argument("--max-files", type=int, default=None, help="Stop after N classified files")
    parser.add_argument("--threshold", type=float, default=_SENSITIVE_THRESHOLD)
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of a report")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.root):
        print(f"Not a directory: {args.root}", file=sys.stderr)
        return 2

    # Imported here, not at module scope, so the scanner itself stays testable
    # without a configured environment.
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env")

    from api_client import DLPApiClient
    from file_extractor import extract

    backend_url = os.getenv("BACKEND_URL", "http://127.0.0.1:3001")
    classifier_url = os.getenv("CLASSIFIER_URL", "http://127.0.0.1:8000")
    client = DLPApiClient(backend_url, classifier_url, None)

    logger.info(f"[DISCOVERY] Scanning {args.root}")
    result = scan_tree(
        args.root, client, extract,
        include=args.include,
        exclude=args.exclude,
        max_files=args.max_files,
        threshold=args.threshold,
    )

    if args.json:
        import json
        print(json.dumps({
            "root": result.root,
            "durationSeconds": result.duration_s,
            "filesSeen": result.files_seen,
            "filesClassified": result.files_scanned,
            "filesSkipped": result.files_skipped,
            "errors": result.errors,
            "byRule": result.by_rule(),
            "findings": [{
                "path": f.path,
                "sizeBytes": f.size_bytes,
                "riskScore": f.risk_score,
                "types": f.types,
                "rule": f.rule,
                "detections": f.detections,
            } for f in result.findings],
        }, indent=2))
    else:
        print(format_report(result))

    # Non-zero when something sensitive was found, so this can gate a CI job
    # or a scheduled task without parsing the output.
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(_main())
