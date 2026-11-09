# Bismillah ir-Rahman ir-Rahim
"""
Precision study: classify furqan-lint and bandit findings by safety/health relevance.

Draws a stratified random sample from both tools' UNIQUE findings (non-overlapping),
reads the actual source code at each location, and outputs a classification template.

Classification categories:
  SAFETY    -- could cause security breach, data loss, outage, or safety incident
  HEALTH    -- degrades reliability, maintainability, or debuggability (not immediate danger)
  DESIGN    -- intentional design choice that matches the pattern (true but acceptable)
  FP        -- false positive (pattern matched incorrectly)

Usage:
  python precision_study.py --json-dir paper/ --sample-size 200 --out-dir paper/precision/
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
from collections import Counter, defaultdict
from pathlib import Path

PACKAGES = [
    "django", "flask", "fastapi", "tornado", "starlette",
    "requests", "httpx", "urllib3", "aiohttp", "sqlalchemy",
    "celery", "jinja2", "pydantic", "cryptography", "paramiko",
    "scrapy", "click", "rich", "typer", "boto3",
    "PIL", "werkzeug", "numpy", "pandas", "scipy",
]

# Rule categories for stratification
RULE_CATEGORIES = {
    # Security/trust boundary
    "TB-004": "security", "TB-005": "security", "TB-006": "security",
    "TB-010": "security", "TB-011": "security", "TB-012": "security",
    "TB-013": "security", "TB-014": "security", "TB-015": "security",
    "TB-016": "security", "TB-017": "security", "TB-018": "security",
    "TB-019": "security", "TB-020": "security", "TB-021": "security",
    "TB-022": "security", "TB-023": "security", "TB-024": "security",
    "TB-025": "security", "TB-026": "security", "TB-027": "security",
    "TB-028": "security",
    # Error handling
    "MR-001": "error_handling", "MR-002": "error_handling",
    "MR-003": "error_handling", "MR-005": "error_handling",
    "MR-007": "error_handling",
    # Resource management
    "RC-001": "resource", "RC-002": "resource", "RC-003": "resource",
    "RC-004": "resource", "RC-005": "resource",
    # Type/annotation quality
    "SI-001": "type_quality", "SI-002": "type_quality", "SI-003": "type_quality",
    # Completeness signals
    "SI-004": "completeness", "SI-005": "completeness",
    "SI-006": "completeness", "SI-007": "completeness",
}


def normalize_path(p: str) -> str:
    idx = p.find("site-packages/")
    if idx >= 0:
        return p[idx + len("site-packages/"):]
    return p


def load_unique_findings(json_dir: Path, overlap_dir: Path):
    """Load unique-to-furqan and unique-to-bandit findings using overlap data."""
    raw_json = json_dir / "raw_json"
    bandit_json = json_dir / "bandit_json"

    # Load overlap pairs to identify which findings are NOT unique
    overlap_csv = overlap_dir / "overlap_by_package.csv"

    # Reload and re-decompose to get actual unique findings
    # (simpler: just reload all and subtract overlaps by file+line)
    from overlap_decomposition import decompose_package, normalize_path as np2

    all_unique_furqan = []
    all_unique_bandit = []

    for pkg in PACKAGES:
        ff = raw_json / f"{pkg}.json"
        bf = bandit_json / f"{pkg}.json"
        if not ff.exists():
            continue

        furqan = json.loads(ff.read_text())
        bandit = json.loads(bf.read_text()) if bf.exists() else []

        result = decompose_package(furqan, bandit, line_window=2)

        for f in result["unique_furqan"]:
            f["_package"] = pkg
            f["_tool"] = "furqan"
            all_unique_furqan.append(f)

        for b in result["unique_bandit"]:
            b["_package"] = pkg
            b["_tool"] = "bandit"
            all_unique_bandit.append(b)

    return all_unique_furqan, all_unique_bandit


def stratified_sample(findings: list, n: int, tool: str) -> list:
    """Draw a stratified random sample, proportional to rule category."""
    if tool == "furqan":
        by_cat = defaultdict(list)
        for f in findings:
            cat = RULE_CATEGORIES.get(f["rule"], "other")
            by_cat[cat].append(f)
    else:
        by_cat = defaultdict(list)
        for f in findings:
            by_cat[f["test_id"]].append(f)

    # Proportional allocation
    total = len(findings)
    sample = []
    for cat, items in by_cat.items():
        k = max(1, round(len(items) / total * n))
        k = min(k, len(items))
        sample.extend(random.sample(items, k))

    # Trim or pad to exact n
    if len(sample) > n:
        sample = random.sample(sample, n)
    elif len(sample) < n:
        remaining = [f for f in findings if f not in sample]
        extra = min(n - len(sample), len(remaining))
        sample.extend(random.sample(remaining, extra))

    return sample


def read_source_context(filepath: str, line: int, context: int = 3) -> str:
    """Read source code context around a finding."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        start = max(0, line - context - 1)
        end = min(len(lines), line + context)
        result = []
        for i in range(start, end):
            marker = ">>>" if i == line - 1 else "   "
            result.append(f"{marker} {i+1:4d} | {lines[i].rstrip()}")
        return "\n".join(result)
    except (OSError, IndexError):
        return f"(could not read {filepath}:{line})"


def classify_finding(finding: dict, tool: str) -> dict:
    """Read source and auto-classify where possible. Returns classification record."""
    if tool == "furqan":
        filepath = finding["path"]
        line = int(finding["line"])
        rule = finding["rule"]
        message = finding["message"]
        severity = finding["severity"]
    else:
        filepath = finding["filename"]
        line = int(finding["line_number"])
        rule = finding["test_id"]
        message = finding["issue_text"]
        severity = finding["issue_severity"]

    source = read_source_context(filepath, line)

    # Auto-classification heuristics
    auto_class = None
    confidence = None

    if tool == "furqan":
        if rule == "SI-001":
            auto_class = "HEALTH"
            confidence = "high"
        elif rule == "SI-004":
            auto_class = "HEALTH"
            confidence = "high"
        elif rule == "SI-006":
            auto_class = "HEALTH"
            confidence = "medium"
        elif rule in ("TB-005", "TB-006", "TB-015", "TB-016", "TB-017", "TB-018"):
            auto_class = "SAFETY"
            confidence = "medium"
        elif rule in ("MR-001",) and severity == "CRITICAL":
            auto_class = "SAFETY"
            confidence = "medium"
    else:
        if rule == "B101":
            auto_class = "HEALTH"
            confidence = "high"
        elif rule in ("B301", "B307", "B608", "B602"):
            auto_class = "SAFETY"
            confidence = "medium"

    return {
        "tool": tool,
        "package": finding.get("_package", ""),
        "rule": rule,
        "file": normalize_path(filepath),
        "line": line,
        "message": message,
        "severity": severity,
        "source_context": source,
        "auto_classification": auto_class or "REVIEW",
        "auto_confidence": confidence or "none",
        "manual_classification": "",  # to be filled by reviewer
        "notes": "",
    }


def main():
    parser = argparse.ArgumentParser(description="Precision study sampler")
    parser.add_argument("--json-dir", required=True)
    parser.add_argument("--out-dir", default=".")
    parser.add_argument("--sample-size", type=int, default=200,
                        help="Findings per tool to sample")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)
    json_dir = Path(args.json_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    import sys
    sys.path.insert(0, str(json_dir))

    print("Bismillah ir-Rahman ir-Rahim")
    print(f"Precision study: sampling {args.sample_size} findings per tool")
    print("=" * 70)

    unique_furqan, unique_bandit = load_unique_findings(json_dir, json_dir / "overlap")

    print(f"Unique to furqan: {len(unique_furqan):,}")
    print(f"Unique to bandit: {len(unique_bandit):,}")

    # Sample
    furqan_sample = stratified_sample(unique_furqan, args.sample_size, "furqan")
    bandit_sample = stratified_sample(unique_bandit, args.sample_size, "bandit")

    print(f"\nSampled: {len(furqan_sample)} furqan, {len(bandit_sample)} bandit")

    # Classify
    furqan_classified = [classify_finding(f, "furqan") for f in furqan_sample]
    bandit_classified = [classify_finding(f, "bandit") for f in bandit_sample]

    all_classified = furqan_classified + bandit_classified

    # Write CSV
    csv_path = out_dir / "precision_sample.csv"
    fieldnames = ["tool", "package", "rule", "file", "line", "message", "severity",
                   "auto_classification", "auto_confidence",
                   "manual_classification", "notes"]
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_classified)

    # Write detailed JSON with source context
    detail_path = out_dir / "precision_sample_detail.json"
    detail_path.write_text(json.dumps(all_classified, indent=2))

    # Auto-classification summary
    print("\n--- Auto-classification summary (furqan unique) ---")
    furqan_auto = Counter(c["auto_classification"] for c in furqan_classified)
    for cat, count in furqan_auto.most_common():
        print(f"  {cat:8s}: {count:3d} ({count/len(furqan_classified)*100:.1f}%)")

    print("\n--- Auto-classification summary (bandit unique) ---")
    bandit_auto = Counter(c["auto_classification"] for c in bandit_classified)
    for cat, count in bandit_auto.most_common():
        print(f"  {cat:8s}: {count:3d} ({count/len(bandit_classified)*100:.1f}%)")

    # Rule distribution in sample
    print("\n--- Furqan sample by rule ---")
    furqan_rules = Counter(c["rule"] for c in furqan_classified)
    for rule, count in furqan_rules.most_common(10):
        print(f"  {rule:8s}: {count:3d}")

    print("\n--- Bandit sample by rule ---")
    bandit_rules = Counter(c["rule"] for c in bandit_classified)
    for rule, count in bandit_rules.most_common(10):
        print(f"  {rule:8s}: {count:3d}")

    print(f"\nOutput: {csv_path}, {detail_path}")
    print("\nBismillah ir-Rahman ir-Rahim")


if __name__ == "__main__":
    main()

# Bismillah ir-Rahman ir-Rahim
