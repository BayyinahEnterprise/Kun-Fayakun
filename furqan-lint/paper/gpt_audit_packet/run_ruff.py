# Bismillah ir-Rahman ir-Rahim
"""Run ruff on the 25 benchmark packages and save raw JSON per package."""

import json
import subprocess
from pathlib import Path

SITE_PACKAGES = Path("/usr/local/lib/python3.13/site-packages")
OUT_DIR = Path("/home/claude/kun-fayakun/furqan-lint/paper/ruff_json")
OUT_DIR.mkdir(exist_ok=True)

PACKAGES = [
    "django", "flask", "fastapi", "tornado", "starlette",
    "requests", "httpx", "urllib3", "aiohttp", "sqlalchemy",
    "celery", "jinja2", "pydantic", "cryptography", "paramiko",
    "scrapy", "click", "rich", "typer", "boto3",
    "PIL", "werkzeug", "numpy", "pandas", "scipy",
]

# All ruff rules that have furqan-lint equivalents, plus S101 for assert
RUFF_RULES = "ANN401,BLE001,E722,FIX001,FIX002,PGH001,PGH002,PGH003,S101,S104,S105,S106,S107,S108,S110,S301,S302,S303,S307,S311,S324,S501,S602,S603,S605,S606,S608,TD001,TD002,TD003"

print("Bismillah ir-Rahman ir-Rahim")
print(f"Running ruff 0.16.9 with rules: {RUFF_RULES}")
print("=" * 70)

ruff_ver = subprocess.run(["ruff", "--version"], capture_output=True, text=True).stdout.strip()
print(f"ruff version: {ruff_ver}")

for pkg in PACKAGES:
    pkg_path = SITE_PACKAGES / pkg
    if not pkg_path.exists():
        print(f"  SKIP {pkg}")
        continue

    result = subprocess.run(
        ["ruff", "check", str(pkg_path),
         "--select", RUFF_RULES,
         "--output-format", "json",
         "--no-fix",
         "--quiet"],
        capture_output=True, text=True, timeout=120,
    )

    try:
        findings = json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        print(f"  ERROR {pkg}: JSON parse failed")
        findings = []

    (OUT_DIR / f"{pkg}.json").write_text(json.dumps(findings, indent=2))
    print(f"  {pkg:20s}: {len(findings):5d} findings")

print()
print("Bismillah ir-Rahman ir-Rahim")

# Bismillah ir-Rahman ir-Rahim
