# Bismillah ir-Rahman ir-Rahim
"""
Output formatters for furqan-lint findings.

Supports:
- text: human-readable terminal output (default)
- json: machine-readable JSON array
- sarif: SARIF v2.1.0 for GitHub Code Scanning / VS Code integration
"""

from __future__ import annotations

import json
import sys
from typing import List

from kun_fayakun.furqan.checks.finding import Finding, Severity


def format_text(findings: List[Finding], verbose: bool = False) -> str:
    """Format findings as human-readable terminal output."""
    if not findings:
        return ""

    lines: List[str] = []
    current_path = ""
    use_color = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

    severity_color = {
        Severity.CRITICAL: "\033[1;31m",
        Severity.HIGH: "\033[31m",
        Severity.MEDIUM: "\033[33m",
        Severity.LOW: "\033[36m",
    }
    reset = "\033[0m"

    for f in findings:
        if f.path != current_path:
            if current_path:
                lines.append("")
            current_path = f.path

        if use_color:
            color = severity_color.get(f.severity, "")
            line = (f"{f.path}:{f.line}:{f.col}: "
                    f"{color}{f.rule}{reset} [{f.severity.value}] {f.message}")
        else:
            line = str(f)

        lines.append(line)

        if verbose and f.detail:
            for detail_line in f.detail.split("\n"):
                lines.append(f"    {detail_line}")

        lines.append(f"    fix: {f.fix.value}")

    return "\n".join(lines)


def format_json(findings: List[Finding]) -> str:
    """Format findings as a JSON array."""
    records = []
    for f in findings:
        records.append({
            "rule": f.rule,
            "path": f.path,
            "line": f.line,
            "col": f.col,
            "message": f.message,
            "severity": f.severity.value,
            "fix": f.fix.value,
            "detail": f.detail,
        })
    return json.dumps(records, indent=2)


def format_sarif(findings: List[Finding]) -> str:
    """Format findings as SARIF v2.1.0.

    Compatible with:
    - GitHub Code Scanning (upload as SARIF)
    - VS Code SARIF Viewer extension
    - Azure DevOps
    """
    severity_to_sarif = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
    }

    # Build rule definitions
    rule_ids = sorted(set(f.rule for f in findings))
    rules = []
    rule_index = {}
    for idx, rule_id in enumerate(rule_ids):
        rule_index[rule_id] = idx
        # Find first finding with this rule for its message
        sample = next(f for f in findings if f.rule == rule_id)
        rules.append({
            "id": rule_id,
            "shortDescription": {"text": sample.message},
            "fullDescription": {"text": sample.detail or sample.message},
            "defaultConfiguration": {
                "level": severity_to_sarif.get(sample.severity, "warning"),
            },
            "properties": {
                "fix-category": sample.fix.value,
            },
        })

    # Build results
    results = []
    for f in findings:
        result = {
            "ruleId": f.rule,
            "ruleIndex": rule_index[f.rule],
            "level": severity_to_sarif.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.path,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": f.line,
                        "startColumn": f.col + 1,  # SARIF is 1-indexed
                    },
                },
            }],
            "properties": {
                "fix-category": f.fix.value,
            },
        }
        if f.detail:
            result["message"]["markdown"] = f.detail
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "furqan-lint",
                    "version": "2.0.0",
                    "informationUri": "https://github.com/BayyinahEnterprise/Kun-Fayakun",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


FORMATTERS = {
    "text": format_text,
    "json": format_json,
    "sarif": format_sarif,
}


# Bismillah ir-Rahman ir-Rahim
