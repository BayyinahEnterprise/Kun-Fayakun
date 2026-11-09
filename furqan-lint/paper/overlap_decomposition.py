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
    "TB-005": ["B307", "B102"],  # eval()/exec()
    # TB-004 is mutable default argument -- no bandit equivalent
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


def _is_semantic_pair(furqan_rule: str, bandit_test: str) -> bool:
    """Check if a furqan rule and bandit test detect semantically related patterns."""
    expected = KNOWN_OVERLAPS.get(furqan_rule, [])
    return bandit_test in expected


def _is_test_path(path: str) -> bool:
    """Check if a file path is a test file (same logic as scan_incomplete.py)."""
    parts = path.replace("\\", "/").split("/")
    basename = parts[-1] if parts else ""
    dir_parts = parts[:-1] if len(parts) > 1 else []
    return (
        basename.startswith("test_")
        or basename.endswith("_test.py")
        or basename == "conftest.py"
        or "tests" in dir_parts
        or "test" in dir_parts
    )


def decompose_package(furqan_findings: list, bandit_findings: list, line_window: int = 2):
    """Decompose one package's findings into unique/overlap categories.

    F6 fix: symmetric matching -- a bandit finding is matched if ANY furqan
    finding is in its window (not just the first one that claims it).
    F7 fix: overlaps classified as semantic (related rules) or coincidental.
    """
    # Build file-indexed lists for efficient lookup
    bandit_by_file = defaultdict(list)
    for bi, bf in enumerate(bandit_findings):
        bandit_by_file[normalize_path(bf["filename"])].append((bi, int(bf["line_number"]), bf))

    furqan_by_file = defaultdict(list)
    for fi, ff in enumerate(furqan_findings):
        furqan_by_file[normalize_path(ff["path"])].append((fi, int(ff["line"]), ff))

    furqan_matched = set()
    bandit_matched = set()
    overlaps_semantic = []
    overlaps_coincidental = []
    rule_pairs = Counter()

    # Forward pass: furqan -> bandit (marks both sides)
    for fi, ff in enumerate(furqan_findings):
        fpath = normalize_path(ff["path"])
        fline = int(ff["line"])
        for bi, bline, bf in bandit_by_file.get(fpath, []):
            if abs(fline - bline) <= line_window:
                furqan_matched.add(fi)
                bandit_matched.add(bi)  # F6: mark bandit side too
                pair = (ff, bf)
                is_semantic = _is_semantic_pair(ff["rule"], bf["test_id"])
                if is_semantic:
                    overlaps_semantic.append(pair)
                else:
                    overlaps_coincidental.append(pair)
                rule_pairs[(ff["rule"], bf["test_id"])] += 1

    # F6: Reverse pass -- mark any bandit finding co-located with furqan
    for bi, bf in enumerate(bandit_findings):
        if bi in bandit_matched:
            continue
        bpath = normalize_path(bf["filename"])
        bline = int(bf["line_number"])
        for fi, fline, ff in furqan_by_file.get(bpath, []):
            if abs(fline - bline) <= line_window:
                bandit_matched.add(bi)
                break

    unique_furqan = [f for i, f in enumerate(furqan_findings) if i not in furqan_matched]
    unique_bandit = [b for i, b in enumerate(bandit_findings) if i not in bandit_matched]

    # F8: test-path stratum
    unique_furqan_nontest = [f for f in unique_furqan if not _is_test_path(normalize_path(f["path"]))]
    unique_bandit_nontest = [b for b in unique_bandit if not _is_test_path(normalize_path(b["filename"]))]
    unique_furqan_test = [f for f in unique_furqan if _is_test_path(normalize_path(f["path"]))]
    unique_bandit_test = [b for b in unique_bandit if _is_test_path(normalize_path(b["filename"]))]

    return {
        "unique_furqan": unique_furqan,
        "unique_bandit": unique_bandit,
        "overlaps_semantic": overlaps_semantic,
        "overlaps_coincidental": overlaps_coincidental,
        "overlaps_total": overlaps_semantic + overlaps_coincidental,
        "rule_pairs": rule_pairs,
        "furqan_total": len(furqan_findings),
        "bandit_total": len(bandit_findings),
        # F8: test-path breakdown
        "unique_furqan_nontest": len(unique_furqan_nontest),
        "unique_furqan_test": len(unique_furqan_test),
        "unique_bandit_nontest": len(unique_bandit_nontest),
        "unique_bandit_test": len(unique_bandit_test),
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
    T = {"uf": 0, "ub": 0, "sem": 0, "coin": 0, "f": 0, "b": 0,
         "uf_nt": 0, "uf_t": 0, "ub_nt": 0, "ub_t": 0}
    all_rule_pairs = Counter()
    all_unique_furqan_rules = Counter()
    all_unique_bandit_rules = Counter()

    for pkg in PACKAGES:
        if pkg not in all_furqan:
            continue

        furqan = all_furqan[pkg]
        bandit = all_bandit.get(pkg, [])
        result = decompose_package(furqan, bandit, line_window)

        uf = len(result["unique_furqan"])
        ub = len(result["unique_bandit"])
        sem = len(result["overlaps_semantic"])
        coin = len(result["overlaps_coincidental"])
        ov = sem + coin
        ft = result["furqan_total"]
        bt = result["bandit_total"]

        pct_unique_f = (uf / ft * 100) if ft > 0 else 0

        rows.append({
            "package": pkg, "furqan_total": ft, "bandit_total": bt,
            "unique_furqan": uf, "unique_bandit": ub,
            "overlap_semantic": sem, "overlap_coincidental": coin,
            "overlap_total": ov,
            "pct_unique_furqan": round(pct_unique_f, 1),
            "unique_furqan_nontest": result["unique_furqan_nontest"],
            "unique_furqan_test": result["unique_furqan_test"],
            "unique_bandit_nontest": result["unique_bandit_nontest"],
            "unique_bandit_test": result["unique_bandit_test"],
        })

        T["uf"] += uf; T["ub"] += ub; T["sem"] += sem; T["coin"] += coin
        T["f"] += ft; T["b"] += bt
        T["uf_nt"] += result["unique_furqan_nontest"]
        T["uf_t"] += result["unique_furqan_test"]
        T["ub_nt"] += result["unique_bandit_nontest"]
        T["ub_t"] += result["unique_bandit_test"]
        all_rule_pairs += result["rule_pairs"]

        for f in result["unique_furqan"]:
            all_unique_furqan_rules[f["rule"]] += 1
        for b in result["unique_bandit"]:
            all_unique_bandit_rules[b["test_id"]] += 1

        print(f"  {pkg:20s}  f={ft:5d} b={bt:4d}  "
              f"uniq_f={uf:5d} ({pct_unique_f:5.1f}%)  "
              f"sem={sem:3d} coin={coin:3d}  uniq_b={ub:4d}")

    ov_total = T["sem"] + T["coin"]
    pct_uf = T["uf"] / T["f"] * 100 if T["f"] else 0
    pct_sem = T["sem"] / T["f"] * 100 if T["f"] else 0
    pct_coin = T["coin"] / T["f"] * 100 if T["f"] else 0

    print("=" * 80)
    print(f"TOTALS:  furqan={T['f']:,}  bandit={T['b']:,}")
    print(f"  Unique to furqan:       {T['uf']:,} ({pct_uf:.1f}%)")
    print(f"  Overlap (semantic):     {T['sem']:,} ({pct_sem:.1f}%)")
    print(f"  Overlap (coincidental): {T['coin']:,} ({pct_coin:.1f}%)")
    print(f"  Unique to bandit:       {T['ub']:,}")
    print(f"\n  Test-path breakdown (unique only):")
    print(f"    furqan: {T['uf_nt']:,} non-test, {T['uf_t']:,} test")
    print(f"    bandit: {T['ub_nt']:,} non-test, {T['ub_t']:,} test")

    # Write per-package CSV
    csv_path = out_dir / "overlap_by_package.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    # Write rule pair matrix
    print("\n--- Rule pair co-occurrences (semantic / coincidental) ---")
    pairs_path = out_dir / "rule_pairs.csv"
    with open(pairs_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["furqan_rule", "bandit_test", "count", "semantic"])
        for (fr, bt), count in all_rule_pairs.most_common():
            is_sem = _is_semantic_pair(fr, bt)
            writer.writerow([fr, bt, count, is_sem])
            tag = "SEM" if is_sem else "COI"
            print(f"  {fr:8s} x {bt:6s} = {count:4d}  [{tag}]")

    # Write unique furqan rules breakdown
    print("\n--- Unique-to-furqan rules ---")
    unique_path = out_dir / "unique_furqan_rules.csv"
    with open(unique_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["rule", "count", "pct_of_unique"])
        for rule, count in all_unique_furqan_rules.most_common():
            pct = count / T["uf"] * 100 if T["uf"] else 0
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
        "furqan_total": T["f"],
        "bandit_total": T["b"],
        "unique_furqan": T["uf"],
        "unique_furqan_pct": round(pct_uf, 1),
        "overlap_semantic": T["sem"],
        "overlap_coincidental": T["coin"],
        "overlap_total": ov_total,
        "overlap_semantic_pct": round(pct_sem, 1),
        "overlap_coincidental_pct": round(pct_coin, 1),
        "unique_bandit": T["ub"],
        "unique_furqan_nontest": T["uf_nt"],
        "unique_furqan_test": T["uf_t"],
        "unique_bandit_nontest": T["ub_nt"],
        "unique_bandit_test": T["ub_t"],
        "top_unique_furqan_rules": all_unique_furqan_rules.most_common(10),
        "top_rule_pairs": all_rule_pairs.most_common(10),
    }
    (out_dir / "overlap_summary.json").write_text(json.dumps(summary, indent=2))

    print(f"\nOutput: {csv_path}, {pairs_path}, {unique_path}, {out_dir / 'overlap_summary.json'}")
    print("\nBismillah ir-Rahman ir-Rahim")


if __name__ == "__main__":
    main()

# Bismillah ir-Rahman ir-Rahim
