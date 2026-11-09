# Bismillah ir-Rahman ir-Rahim
"""
Benchmark harness: furqan-lint vs bandit across 25 Python packages.

Two modes:
  --scan SITE_PACKAGES   Fresh scan of installed packages (writes CSV + JSON)
  --from-json JSON_DIR   Reconstruct CSV from archived raw JSON (offline replay)

All output paths are parameterized via --out-dir (default: current directory).
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

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

CSV_FIELDS = ["package", "domain", "py_files", "py_lines",
              "furqan_v21", "bandit", "ratio",
              "critical", "high", "medium", "low"]


def count_py_lines(pkg_path: Path) -> int:
    total = 0
    for f in pkg_path.rglob("*.py"):
        try:
            total += len(f.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            pass
    return total


def count_py_files(pkg_path: Path) -> int:
    return sum(1 for f in pkg_path.rglob("*.py") if f.is_file())


def run_bandit(pkg_path: Path) -> tuple[int, dict, list]:
    result = subprocess.run(
        ["bandit", "-r", str(pkg_path), "-f", "json", "-q"],
        capture_output=True, text=True, timeout=300,
    )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"bandit JSON parse failed on {pkg_path}: {result.stderr[:200]}")
    results = data.get("results", [])
    by_rule = Counter(r["test_id"] for r in results)
    return len(results), dict(by_rule), results


def run_furqan(pkg_path: Path):
    """Run furqan-lint. Import deferred so --from-json works without tree-sitter."""
    from kun_fayakun.furqan.checks.runner import lint_directory
    findings, _ = lint_directory(pkg_path)
    by_rule = Counter(f.rule for f in findings)
    by_severity = Counter(f.severity.value for f in findings)
    return len(findings), dict(by_rule), dict(by_severity), findings


def scan_mode(site_packages: Path, out_dir: Path, monorepo_src: Path | None):
    """Fresh scan of installed packages."""
    if monorepo_src:
        sys.path.insert(0, str(monorepo_src))

    bandit_ver = subprocess.run(
        ["bandit", "--version"], capture_output=True, text=True
    ).stdout.strip().split("\n")[0]
    python_ver = f"Python {sys.version.split()[0]}"

    print("Bismillah ir-Rahman ir-Rahim")
    print(f"furqan-lint v2.1.0 benchmark -- fresh scan")
    print(f"bandit: {bandit_ver}  python: {python_ver}")
    print("=" * 70)

    rows = []
    raw_json_dir = out_dir / "raw_json"
    bandit_json_dir = out_dir / "bandit_json"
    raw_json_dir.mkdir(parents=True, exist_ok=True)
    bandit_json_dir.mkdir(parents=True, exist_ok=True)

    versions = {"python": python_ver, "bandit": bandit_ver,
                "furqan-lint": "v2.1.0", "packages": {}}

    for pkg_name, domain in PACKAGES:
        pkg_path = site_packages / pkg_name
        if not pkg_path.exists():
            print(f"  SKIP  {pkg_name} (not installed)", file=sys.stderr)
            continue

        py_files = count_py_files(pkg_path)
        py_lines = count_py_lines(pkg_path)

        # Package version
        try:
            result = subprocess.run(
                [sys.executable, "-c",
                 f"import importlib.metadata; print(importlib.metadata.version('{pkg_name}'))"],
                capture_output=True, text=True, timeout=10,
            )
            pkg_ver = result.stdout.strip() or "unknown"
        except Exception:
            pkg_ver = "unknown"
        versions["packages"][pkg_name] = pkg_ver

        furqan_total, furqan_rules, furqan_sev, furqan_raw = run_furqan(pkg_path)
        bandit_total, bandit_rules, bandit_raw = run_bandit(pkg_path)

        # Write raw JSON
        furqan_data = [
            {"rule": f.rule, "path": f.path, "line": f.line, "col": f.col,
             "message": f.message, "severity": f.severity.value,
             "fix": f.fix.value if f.fix else None}
            for f in furqan_raw
        ]
        (raw_json_dir / f"{pkg_name}.json").write_text(json.dumps(furqan_data, indent=2))
        (bandit_json_dir / f"{pkg_name}.json").write_text(json.dumps(bandit_raw, indent=2))

        ratio = furqan_total / bandit_total if bandit_total > 0 else float("inf")
        row = {
            "package": pkg_name, "domain": domain,
            "py_files": py_files, "py_lines": py_lines,
            "furqan_v21": furqan_total, "bandit": bandit_total,
            "ratio": round(ratio, 1) if ratio != float("inf") else "inf",
            "critical": furqan_sev.get("CRITICAL", 0),
            "high": furqan_sev.get("HIGH", 0),
            "medium": furqan_sev.get("MEDIUM", 0),
            "low": furqan_sev.get("LOW", 0),
        }
        rows.append(row)
        ratio_str = f"{ratio:.1f}x" if ratio != float("inf") else "inf"
        print(f"  {pkg_name:20s}  furqan={furqan_total:5d}  bandit={bandit_total:4d}  ratio={ratio_str:>6s}")

    # Write CSV
    csv_path = out_dir / "benchmark_v2.1.0.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    # Write versions
    (out_dir / "versions.json").write_text(json.dumps(versions, indent=2))

    print(f"\nCSV: {csv_path}")
    print(f"Versions: {out_dir / 'versions.json'}")
    _print_summary(rows)


def from_json_mode(json_dir: Path, out_dir: Path):
    """Reconstruct CSV from archived raw JSON (offline replay)."""
    raw_json_dir = json_dir / "raw_json" if (json_dir / "raw_json").exists() else json_dir
    bandit_json_dir = json_dir / "bandit_json" if (json_dir / "bandit_json").exists() else json_dir

    print("Bismillah ir-Rahman ir-Rahim")
    print("Reconstructing CSV from archived JSON...")
    print("=" * 70)

    rows = []
    for pkg_name, domain in PACKAGES:
        furqan_file = raw_json_dir / f"{pkg_name}.json"
        bandit_file = bandit_json_dir / f"{pkg_name}.json"
        if not furqan_file.exists():
            print(f"  SKIP  {pkg_name} (no JSON)", file=sys.stderr)
            continue

        furqan_data = json.loads(furqan_file.read_text())
        bandit_data = json.loads(bandit_file.read_text()) if bandit_file.exists() else []

        furqan_total = len(furqan_data)
        bandit_total = len(bandit_data)
        sev = Counter(f["severity"] for f in furqan_data)
        ratio = furqan_total / bandit_total if bandit_total > 0 else float("inf")

        row = {
            "package": pkg_name, "domain": domain,
            "py_files": "", "py_lines": "",
            "furqan_v21": furqan_total, "bandit": bandit_total,
            "ratio": round(ratio, 1) if ratio != float("inf") else "inf",
            "critical": sev.get("CRITICAL", 0),
            "high": sev.get("HIGH", 0),
            "medium": sev.get("MEDIUM", 0),
            "low": sev.get("LOW", 0),
        }
        rows.append(row)
        ratio_str = f"{ratio:.1f}x" if ratio != float("inf") else "inf"
        print(f"  {pkg_name:20s}  furqan={furqan_total:5d}  bandit={bandit_total:4d}  ratio={ratio_str:>6s}")

    csv_path = out_dir / "benchmark_reconstructed.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nReconstructed CSV: {csv_path}")
    _print_summary(rows)


def _print_summary(rows):
    import statistics
    totals_f = sum(r["furqan_v21"] for r in rows)
    totals_b = sum(r["bandit"] for r in rows)
    ratios = [r["furqan_v21"] / r["bandit"] for r in rows if r["bandit"] > 0]
    print()
    print(f"furqan total: {totals_f:,}  bandit total: {totals_b:,}")
    print(f"Pooled ratio: {totals_f / totals_b:.2f}x")
    print(f"Median: {statistics.median(ratios):.1f}x  Mean: {statistics.mean(ratios):.1f}x  SD: {statistics.stdev(ratios):.1f}")
    print(f"furqan > bandit: {sum(1 for r in rows if r['furqan_v21'] > r['bandit'])}/{len(rows)}")
    print()
    print("Bismillah ir-Rahman ir-Rahim")


def main():
    parser = argparse.ArgumentParser(
        description="furqan-lint v2.1.0 benchmark harness",
        epilog="Bismillah ir-Rahman ir-Rahim",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scan", metavar="SITE_PACKAGES",
                       help="Fresh scan: path to site-packages directory")
    group.add_argument("--from-json", metavar="JSON_DIR",
                       help="Offline replay: path to directory with raw_json/ and bandit_json/")
    parser.add_argument("--out-dir", default=".",
                        help="Output directory for CSV, JSON, versions (default: .)")
    parser.add_argument("--monorepo-src", metavar="PATH",
                        help="Path to monorepo src/ for PYTHONPATH (--scan only)")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.scan:
        scan_mode(Path(args.scan), out_dir,
                  Path(args.monorepo_src) if args.monorepo_src else None)
    else:
        from_json_mode(Path(args.from_json), out_dir)


if __name__ == "__main__":
    main()

# Bismillah ir-Rahman ir-Rahim
