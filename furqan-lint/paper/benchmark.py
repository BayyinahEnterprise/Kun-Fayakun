# Bismillah ir-Rahman ir-Rahim
"""
Benchmark v2.1.1: furqan-lint vs bandit across 25 real-world Python packages.

Fixes from round-2 audit:
- Uses default Config() (excludes TB-001/002/003)
- Records bandit --version
- Outputs the shipped CSV schema (with severity columns)
- Fails loudly on errors
- Parameterized paths
"""

import csv
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, "/home/claude/kun-fayakun/src")

from kun_fayakun.furqan.checks.runner import lint_directory
from kun_fayakun.furqan.checks.finding import Severity

SITE_PACKAGES = Path("/usr/local/lib/python3.13/site-packages")

PACKAGES = [
    ("django", "Web framework"),
    ("flask", "Micro web framework"),
    ("fastapi", "Async web framework"),
    ("tornado", "Async networking/web"),
    ("starlette", "ASGI framework"),
    ("requests", "HTTP library"),
    ("httpx", "Async HTTP client"),
    ("urllib3", "HTTP client low-level"),
    ("aiohttp", "Async HTTP"),
    ("sqlalchemy", "SQL ORM"),
    ("celery", "Task queue"),
    ("jinja2", "Template engine"),
    ("pydantic", "Data validation"),
    ("cryptography", "Crypto library"),
    ("paramiko", "SSH library"),
    ("scrapy", "Web scraping"),
    ("click", "CLI framework"),
    ("rich", "Rich terminal"),
    ("typer", "CLI builder"),
    ("boto3", "AWS SDK"),
    ("PIL", "Image processing"),
    ("werkzeug", "WSGI utilities"),
    ("numpy", "Numerical computing"),
    ("pandas", "Data analysis"),
    ("scipy", "Scientific computing"),
]

def count_py_lines(pkg_path):
    total = 0
    for f in pkg_path.rglob("*.py"):
        try:
            total += len(f.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            pass
    return total

def count_py_files(pkg_path):
    return sum(1 for f in pkg_path.rglob("*.py") if f.is_file())

def run_bandit(pkg_path):
    result = subprocess.run(
        ["bandit", "-r", str(pkg_path), "-f", "json", "-q"],
        capture_output=True, text=True, timeout=300
    )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"bandit JSON parse failed on {pkg_path}: {result.stderr[:200]}")
    results = data.get("results", [])
    by_rule = Counter(r["test_id"] for r in results)
    return len(results), dict(by_rule), results

def run_furqan(pkg_path):
    # lint_directory now applies default Config() which excludes TB-001/002/003
    findings, _ = lint_directory(pkg_path)
    by_rule = Counter(f.rule for f in findings)
    by_severity = Counter(f.severity.value for f in findings)
    return len(findings), dict(by_rule), dict(by_severity), findings

def main():
    # Record tool versions
    bandit_ver = subprocess.run(["bandit", "--version"], capture_output=True, text=True).stdout.strip().split("\n")[0]
    print(f"Bismillah ir-Rahman ir-Rahim")
    print()
    print(f"furqan-lint v2.1.0 benchmark (rerun with default config)")
    print(f"bandit version: {bandit_ver}")
    print("=" * 70)

    rows = []
    all_furqan_findings = {}
    all_bandit_findings = {}

    for pkg_name, domain in PACKAGES:
        pkg_path = SITE_PACKAGES / pkg_name
        if not pkg_path.exists():
            print(f"  SKIP  {pkg_name} (not installed)", file=sys.stderr)
            continue

        py_files = count_py_files(pkg_path)
        py_lines = count_py_lines(pkg_path)

        furqan_total, furqan_rules, furqan_sev, furqan_raw = run_furqan(pkg_path)
        bandit_total, bandit_rules, bandit_raw = run_bandit(pkg_path)

        ratio = furqan_total / bandit_total if bandit_total > 0 else float("inf")

        row = {
            "package": pkg_name,
            "domain": domain,
            "py_files": py_files,
            "py_lines": py_lines,
            "furqan_v21": furqan_total,
            "bandit": bandit_total,
            "ratio": round(ratio, 1) if ratio != float("inf") else "inf",
            "critical": furqan_sev.get("CRITICAL", 0),
            "high": furqan_sev.get("HIGH", 0),
            "medium": furqan_sev.get("MEDIUM", 0),
            "low": furqan_sev.get("LOW", 0),
        }
        rows.append(row)
        all_furqan_findings[pkg_name] = furqan_raw
        all_bandit_findings[pkg_name] = bandit_raw

        ratio_str = f"{ratio:.1f}x" if ratio != float("inf") else "inf"
        print(f"  {pkg_name:20s}  furqan={furqan_total:5d}  bandit={bandit_total:4d}  "
              f"ratio={ratio_str:>6s}  C={furqan_sev.get('CRITICAL',0)} H={furqan_sev.get('HIGH',0)} "
              f"M={furqan_sev.get('MEDIUM',0)} L={furqan_sev.get('LOW',0)}")

    print()
    print("=" * 70)

    # Summary
    totals_furqan = sum(r["furqan_v21"] for r in rows)
    totals_bandit = sum(r["bandit"] for r in rows)
    total_files = sum(r["py_files"] for r in rows)
    total_lines = sum(r["py_lines"] for r in rows)
    ratios = [r["furqan_v21"] / r["bandit"] for r in rows if r["bandit"] > 0]

    import statistics
    print(f"Packages: {len(rows)}")
    print(f"Files: {total_files:,}  Lines: {total_lines:,}")
    print(f"furqan total: {totals_furqan:,}  bandit total: {totals_bandit:,}")
    print(f"Pooled ratio: {totals_furqan/totals_bandit:.2f}x")
    print(f"Median per-pkg ratio: {statistics.median(ratios):.1f}x")
    print(f"Mean per-pkg ratio: {statistics.mean(ratios):.1f}x")
    print(f"furqan > bandit: {sum(1 for r in rows if r['furqan_v21'] > r['bandit'])}/{len(rows)}")
    print(f"bandit > furqan: {sum(1 for r in rows if r['bandit'] > r['furqan_v21'])}/{len(rows)}")

    # Write CSV
    csv_path = "/home/claude/kun-fayakun/furqan-lint/paper/benchmark_v2.1.0.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nCSV: {csv_path}")

    # Write raw JSON per package
    json_dir = Path("/home/claude/kun-fayakun/furqan-lint/paper/raw_json")
    json_dir.mkdir(exist_ok=True)
    for pkg_name, findings in all_furqan_findings.items():
        data = [{"rule": f.rule, "path": f.path, "line": f.line, "col": f.col,
                 "message": f.message, "severity": f.severity.value,
                 "fix": f.fix.value if f.fix else None} for f in findings]
        (json_dir / f"{pkg_name}.json").write_text(json.dumps(data, indent=2))

    # Write bandit raw JSON
    bandit_json_dir = Path("/home/claude/kun-fayakun/furqan-lint/paper/bandit_json")
    bandit_json_dir.mkdir(exist_ok=True)
    for pkg_name, results in all_bandit_findings.items():
        (bandit_json_dir / f"{pkg_name}.json").write_text(json.dumps(results, indent=2))

    # Per-rule summary
    print("\n--- Per-rule totals (furqan) ---")
    all_rules = Counter()
    for findings in all_furqan_findings.values():
        for f in findings:
            all_rules[f.rule] += 1
    for rule, count in all_rules.most_common():
        print(f"  {rule}: {count} ({count/totals_furqan*100:.1f}%)")

    print()
    print("Bismillah ir-Rahman ir-Rahim")

if __name__ == "__main__":
    main()

# Bismillah ir-Rahman ir-Rahim
