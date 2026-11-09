# Bismillah ir-Rahman ir-Rahim
"""
Three-way overlap decomposition: furqan-lint vs bandit vs ruff.

For each furqan-lint finding, classify it as:
  - UNIQUE: no bandit or ruff finding within LINE_WINDOW on same file
  - BANDIT_ONLY: overlaps bandit but not ruff
  - RUFF_ONLY: overlaps ruff but not bandit
  - BOTH: overlaps both bandit and ruff
"""

import json
from pathlib import Path
from collections import Counter, defaultdict

LINE_WINDOW = 2
SITE_PACKAGES = "site-packages/"

PACKAGES = [
    "django", "flask", "fastapi", "tornado", "starlette",
    "requests", "httpx", "urllib3", "aiohttp", "sqlalchemy",
    "celery", "jinja2", "pydantic", "cryptography", "paramiko",
    "scrapy", "click", "rich", "typer", "boto3",
    "PIL", "werkzeug", "numpy", "pandas", "scipy",
]

def norm(p):
    idx = p.find(SITE_PACKAGES)
    return p[idx + len(SITE_PACKAGES):] if idx >= 0 else p

def index_by_file_line(findings, path_key, line_key):
    """Build {normalized_path: set of line numbers}."""
    idx = defaultdict(set)
    for f in findings:
        p = norm(f[path_key])
        if isinstance(f[line_key], dict):
            line = int(f[line_key].get("row", 0))
        else:
            line = int(f[line_key])
        idx[p].add(line)
    return idx

def has_neighbor(file_index, path, line, window):
    lines = file_index.get(path, set())
    return any(abs(line - l) <= window for l in lines)

def main():
    base = Path("/home/claude/kun-fayakun/furqan-lint/paper")

    print("Bismillah ir-Rahman ir-Rahim")
    print("Three-way decomposition: furqan-lint vs bandit vs ruff")
    print("=" * 80)

    totals = Counter()
    per_rule = defaultdict(Counter)
    rows = []

    for pkg in PACKAGES:
        ff = base / "raw_json" / f"{pkg}.json"
        bf = base / "bandit_json" / f"{pkg}.json"
        rf = base / "ruff_json" / f"{pkg}.json"

        if not ff.exists():
            continue

        furqan = json.loads(ff.read_text())
        bandit = json.loads(bf.read_text()) if bf.exists() else []
        ruff = json.loads(rf.read_text()) if rf.exists() else []

        bandit_idx = index_by_file_line(bandit, "filename", "line_number")
        ruff_idx = index_by_file_line(ruff, "filename", "location")

        pkg_counts = Counter()

        for finding in furqan:
            fpath = norm(finding["path"])
            fline = int(finding["line"])
            rule = finding["rule"]

            has_bandit = has_neighbor(bandit_idx, fpath, fline, LINE_WINDOW)
            has_ruff = has_neighbor(ruff_idx, fpath, fline, LINE_WINDOW)

            if has_bandit and has_ruff:
                cat = "BOTH"
            elif has_bandit:
                cat = "BANDIT_ONLY"
            elif has_ruff:
                cat = "RUFF_ONLY"
            else:
                cat = "UNIQUE"

            pkg_counts[cat] += 1
            totals[cat] += 1
            per_rule[rule][cat] += 1

        n = sum(pkg_counts.values())
        u = pkg_counts["UNIQUE"]
        pct = u / n * 100 if n else 0
        rows.append({
            "package": pkg, "total": n,
            "unique": u, "bandit_only": pkg_counts["BANDIT_ONLY"],
            "ruff_only": pkg_counts["RUFF_ONLY"], "both": pkg_counts["BOTH"],
            "pct_unique": round(pct, 1),
        })

        print(f"  {pkg:20s}  n={n:5d}  UNIQUE={u:5d} ({pct:5.1f}%)  "
              f"bandit={pkg_counts['BANDIT_ONLY']:4d}  "
              f"ruff={pkg_counts['RUFF_ONLY']:4d}  "
              f"both={pkg_counts['BOTH']:3d}")

    total_n = sum(totals.values())
    print("=" * 80)
    print(f"TOTALS (n={total_n:,}):")
    for cat in ["UNIQUE", "RUFF_ONLY", "BANDIT_ONLY", "BOTH"]:
        c = totals[cat]
        print(f"  {cat:12s}: {c:6,} ({c/total_n*100:.1f}%)")

    print(f"\nGenuinely unique (no overlap with either tool): {totals['UNIQUE']:,} ({totals['UNIQUE']/total_n*100:.1f}%)")
    print(f"Overlap with at least one tool: {total_n - totals['UNIQUE']:,} ({(total_n - totals['UNIQUE'])/total_n*100:.1f}%)")

    # Per-rule breakdown
    print("\n--- Per-rule three-way breakdown (top 15) ---")
    print(f"{'Rule':8s} {'Total':>6s} {'UNIQUE':>7s} {'%uniq':>6s} {'ruff':>5s} {'bandit':>7s} {'both':>5s}")
    rule_totals = {r: sum(cats.values()) for r, cats in per_rule.items()}
    for rule in sorted(rule_totals, key=rule_totals.get, reverse=True)[:15]:
        cats = per_rule[rule]
        t = rule_totals[rule]
        u = cats["UNIQUE"]
        print(f"  {rule:8s} {t:6d} {u:7d} {u/t*100:5.1f}% {cats['RUFF_ONLY']:5d} {cats['BANDIT_ONLY']:7d} {cats['BOTH']:5d}")

    # Save
    out = base / "overlap"
    summary = {
        "line_window": LINE_WINDOW,
        "tools": ["furqan-lint v2.1.0", "bandit 1.9.4", "ruff 0.16.9"],
        "total_furqan_findings": total_n,
        "unique_to_furqan": totals["UNIQUE"],
        "unique_pct": round(totals["UNIQUE"] / total_n * 100, 1),
        "ruff_only_overlap": totals["RUFF_ONLY"],
        "bandit_only_overlap": totals["BANDIT_ONLY"],
        "both_overlap": totals["BOTH"],
        "per_rule": {r: dict(cats) for r, cats in per_rule.items()},
    }
    (out / "three_way_summary.json").write_text(json.dumps(summary, indent=2))

    import csv
    with open(out / "three_way_by_package.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print(f"\nOutput: {out / 'three_way_summary.json'}, {out / 'three_way_by_package.csv'}")
    print("\nBismillah ir-Rahman ir-Rahim")

if __name__ == "__main__":
    main()

# Bismillah ir-Rahman ir-Rahim
