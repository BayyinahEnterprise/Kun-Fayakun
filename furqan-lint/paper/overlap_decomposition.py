# Bismillah ir-Rahman ir-Rahim
"""
Overlap decomposition: furqan-lint vs bandit findings matched by file + line.

Categorizes every finding as:
  - UNIQUE_FURQAN: no bandit finding within LINE_WINDOW on the same file
  - UNIQUE_BANDIT: no furqan finding within LINE_WINDOW on the same file
  - OVERLAP: both tools fire on the same file within LINE_WINDOW lines

Also produces a rule-pair co-occurrence matrix showing which furqan rules
overlap with which bandit rules.

Usage:
  python overlap_decomposition.py --json-dir paper/ --out-dir paper/overlap/
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

# Two findings "overlap" if they're on the same file within this many lines.
# 0 = exact line match only. 2 = within 2 lines (catches slight offset differences).
LINE_WINDOW = 2

PACKAGES = [
    "django", "flask", "fastapi", "tornado", "starlette",
    "requests", "httpx", "urllib3", "aiohttp", "sqlalchemy",
    "celery", "jinja2", "pydantic", "cryptography", "paramiko",
    "scrapy", "click", "rich", "typer", "boto3",
    "PIL", "werkzeug", "numpy", "pandas", "scipy",
]

# Known semantic rule mappings (furqan rule -> bandit test_id that detects similar pattern)
KNOWN_OVERLAPS = {
    # Exception handling
    "MR-001": ["B110"],          # bare except / try-except-pass
    "MR-005": ["B110"],          # empty except
    "MR-007": ["B110"],          # try-except-continue
    # Security
    "TB-005": ["B307"],          # eval()
    "TB-004": ["B307"],          # exec()
    "TB-006": ["B301", "B302", "B303", "B506"],  # pickle/yaml/shelve
    "TB-010": ["B105", "B106", "B107"],  # hardcoded passwords/binds
    "TB-011": ["B105", "B107"],  # hardcoded secret defaults
    "TB-012": ["B108"],          # /tmp paths
    "TB-013": ["B104"],          # bind 0.0.0.0
    "TB-014": ["B603"],          # debug mode (loose)
    "TB-015": ["B603", "B602"],  # subprocess/shell
    "TB-016": ["B605", "B606"],  # os.system/os.popen
    "TB-017": ["B602"],          # shell=True
    "TB-018": ["B608"],          # SQL injection
    "TB-021": ["B303", "B324"],  # insecure hash
    "TB-022": ["B501"],          # verify=False
    "TB-023": ["B502", "B503"],  # SSL no cert
    "TB-024": ["B502"],          # SSL no hostname
    "TB-025": ["B504"],          # SSLContext
    "TB-026": ["B311"],          # random for security
    # Assert
    "SI-006": ["B101"],          # assert usage
}

# Reverse: bandit -> furqan
BANDIT_TO_FURQAN = defaultdict(set)
for frule, btests in KNOWN_OVERLAPS.items():
    for bt in btests:
        BANDIT_TO_FURQAN[bt].add(frule)


def normalize_path(p: str) -> str:
    """Strip site-packages prefix for matching."""
    idx = p.find("site-packages/")
    if idx >= 0:
        return p[idx + len("site-packages/"):]
    return p


def load_findings(json_dir: Path):
    """Load all findings for all packages."""
    furqan_dir = json_dir / "raw_json"
    bandit_dir = json_dir / "bandit_json"

    all_furqan = {}
    all_bandit = {}

    for pkg in PACKAGES:
        ff = furqan_dir / f"{pkg}.json"
        bf = bandit_dir / f"{pkg}.json"
        if ff.exists():
            all_furqan[pkg] = json.loads(ff.read_text())
        if bf.exists():
            all_bandit[pkg] = json.loads(bf.read_text())

    return all_furqan, all_bandit


def decompose_package(furqan_findings: list, bandit_findings: list, line_window: int = 2):
    """Decompose one package's findings into unique/overlap categories."""
    # Index bandit by (normalized_path, line)
    bandit_index = defaultdict(list)
    for bf in bandit_findings:
        key = normalize_path(bf["filename"])
        line = int(bf["line_number"])
        bandit_index[key].append((line, bf))

    # Index furqan by (normalized_path, line)
    furqan_index = defaultdict(list)
    for ff in furqan_findings:
        key = normalize_path(ff["path"])
        line = int(ff["line"])
        furqan_index[key].append((line, ff))

    # Match furqan -> bandit
    furqan_matched = set()  # indices of matched furqan findings
    bandit_matched = set()  # indices of matched bandit findings
    overlaps = []  # (furqan_finding, bandit_finding) pairs
    rule_pairs = Counter()  # (furqan_rule, bandit_test_id) co-occurrence

    for fi, ff in enumerate(furqan_findings):
        fpath = normalize_path(ff["path"])
        fline = int(ff["line"])
        for bi, (bline, bf) in enumerate(
            [(int(b["line_number"]), b) for b in bandit_findings
             if normalize_path(b["filename"]) == fpath]
        ):
            if abs(fline - bline) <= line_window:
                # Find actual index in bandit_findings
                actual_bi = next(
                    i for i, b in enumerate(bandit_findings)
                    if b is bf
                )
                furqan_matched.add(fi)
                bandit_matched.add(actual_bi)
                overlaps.append((ff, bf))
                rule_pairs[(ff["rule"], bf["test_id"])] += 1
                break  # one match per furqan finding

    unique_furqan = [f for i, f in enumerate(furqan_findings) if i not in furqan_matched]
    unique_bandit = [b for i, b in enumerate(bandit_findings) if i not in bandit_matched]

    return {
        "unique_furqan": unique_furqan,
        "unique_bandit": unique_bandit,
        "overlaps": overlaps,
        "rule_pairs": rule_pairs,
        "furqan_total": len(furqan_findings),
        "bandit_total": len(bandit_findings),
    }


def main():
    parser = argparse.ArgumentParser(description="Overlap decomposition")
    parser.add_argument("--json-dir", required=True, help="Dir containing raw_json/ and bandit_json/")
    parser.add_argument("--out-dir", default=".", help="Output directory")
    parser.add_argument("--window", type=int, default=LINE_WINDOW, help="Line matching window")
    args = parser.parse_args()

    json_dir = Path(args.json_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    line_window = args.window

    print("Bismillah ir-Rahman ir-Rahim")
    print(f"Overlap decomposition (line window: {line_window})")
    print("=" * 80)

    all_furqan, all_bandit = load_findings(json_dir)

    # Per-package results
    rows = []
    total_unique_f = 0
    total_unique_b = 0
    total_overlap = 0
    total_f = 0
    total_b = 0
    all_rule_pairs = Counter()
    all_unique_furqan_rules = Counter()
    all_unique_bandit_rules = Counter()
    all_overlap_furqan_rules = Counter()

    for pkg in PACKAGES:
        if pkg not in all_furqan:
            continue

        furqan = all_furqan[pkg]
        bandit = all_bandit.get(pkg, [])

        result = decompose_package(furqan, bandit, line_window)

        uf = len(result["unique_furqan"])
        ub = len(result["unique_bandit"])
        ov = len(result["overlaps"])
        ft = result["furqan_total"]
        bt = result["bandit_total"]

        pct_unique_f = (uf / ft * 100) if ft > 0 else 0
        pct_overlap_f = (ov / ft * 100) if ft > 0 else 0

        rows.append({
            "package": pkg,
            "furqan_total": ft,
            "bandit_total": bt,
            "unique_furqan": uf,
            "unique_bandit": ub,
            "overlap": ov,
            "pct_unique_furqan": round(pct_unique_f, 1),
            "pct_overlap_furqan": round(pct_overlap_f, 1),
        })

        total_unique_f += uf
        total_unique_b += ub
        total_overlap += ov
        total_f += ft
        total_b += bt
        all_rule_pairs += result["rule_pairs"]

        for f in result["unique_furqan"]:
            all_unique_furqan_rules[f["rule"]] += 1
        for b in result["unique_bandit"]:
            all_unique_bandit_rules[b["test_id"]] += 1
        for ff, _ in result["overlaps"]:
            all_overlap_furqan_rules[ff["rule"]] += 1

        print(f"  {pkg:20s}  furqan={ft:5d}  bandit={bt:4d}  "
              f"unique_f={uf:5d} ({pct_unique_f:5.1f}%)  "
              f"overlap={ov:3d} ({pct_overlap_f:4.1f}%)  unique_b={ub:4d}")

    print("=" * 80)
    pct_uf = total_unique_f / total_f * 100 if total_f else 0
    pct_ov = total_overlap / total_f * 100 if total_f else 0
    print(f"TOTALS:  furqan={total_f:,}  bandit={total_b:,}")
    print(f"  Unique to furqan:  {total_unique_f:,} ({pct_uf:.1f}%)")
    print(f"  Overlap:           {total_overlap:,} ({pct_ov:.1f}%)")
    print(f"  Unique to bandit:  {total_unique_b:,}")

    # Write per-package CSV
    csv_path = out_dir / "overlap_by_package.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    # Write rule pair matrix
    print("\n--- Rule pair co-occurrences (furqan_rule x bandit_test) ---")
    pairs_path = out_dir / "rule_pairs.csv"
    with open(pairs_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["furqan_rule", "bandit_test", "count"])
        for (fr, bt), count in all_rule_pairs.most_common():
            writer.writerow([fr, bt, count])
            print(f"  {fr:8s} x {bt:6s} = {count:4d}")

    # Write unique furqan rules breakdown
    print("\n--- Unique-to-furqan rules (no bandit match at same location) ---")
    unique_path = out_dir / "unique_furqan_rules.csv"
    with open(unique_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["rule", "count", "pct_of_unique"])
        for rule, count in all_unique_furqan_rules.most_common():
            pct = count / total_unique_f * 100 if total_unique_f else 0
            writer.writerow([rule, count, round(pct, 1)])
            print(f"  {rule:8s}: {count:5d} ({pct:5.1f}%)")

    # Write unique bandit rules
    print("\n--- Unique-to-bandit rules ---")
    for rule, count in all_unique_bandit_rules.most_common():
        print(f"  {rule:8s}: {count:5d}")

    # Summary JSON
    summary = {
        "line_window": line_window,
        "packages": len(rows),
        "furqan_total": total_f,
        "bandit_total": total_b,
        "unique_furqan": total_unique_f,
        "unique_furqan_pct": round(pct_uf, 1),
        "overlap": total_overlap,
        "overlap_pct": round(pct_ov, 1),
        "unique_bandit": total_unique_b,
        "top_unique_furqan_rules": all_unique_furqan_rules.most_common(10),
        "top_rule_pairs": all_rule_pairs.most_common(10),
    }
    (out_dir / "overlap_summary.json").write_text(json.dumps(summary, indent=2))

    print(f"\nOutput: {csv_path}, {pairs_path}, {unique_path}, {out_dir / 'overlap_summary.json'}")
    print("\nBismillah ir-Rahman ir-Rahim")


if __name__ == "__main__":
    main()

# Bismillah ir-Rahman ir-Rahim
