#!/usr/bin/env python3
"""
Stage 2: Metadata Stripper
Parses outputs from CodeQL, Gitleaks, and SonarQube.
Strips ALL raw source code — only structured metadata forwarded to Gemini.
"""

import json
import argparse
from pathlib import Path
from datetime import datetime


def strip_codeql(path: str) -> list[dict]:
    try:
        data = json.load(open(path))
        if not isinstance(data, list):
            return []
        return [{
            "source":      "codeql",
            "rule_id":     f.get("rule_id", "UNKNOWN"),
            "title":       f.get("title", ""),
            "severity":    f.get("severity", "MEDIUM").upper(),
            "category":    f.get("category", "Security"),
            "file":        Path(f.get("file", "unknown")).name,
            "line":        f.get("line", 0),
            "description": f.get("description", "")[:300],
            "cwe":         f.get("cwe", "N/A"),
            "owasp":       f.get("owasp", "N/A"),
            "precision":   f.get("precision", "medium"),
        } for f in data]
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def strip_gitleaks(path: str) -> list[dict]:
    try:
        data = json.load(open(path))
        if not isinstance(data, list):
            return []
        findings = []
        for f in data:
            findings.append({
                "source":      "gitleaks",
                "rule_id":     f.get("RuleID", "UNKNOWN"),
                "title":       f"Exposed Secret: {f.get('Description', 'Credential')}",
                "severity":    "CRITICAL",
                "category":    "Secrets & Credentials",
                "file":        Path(f.get("File", "unknown")).name,
                "line":        f.get("StartLine", 0),
                "description": f.get("Description", ""),
                "cwe":         "CWE-798",
                "owasp":       "A07:2021 – Identification Failures",
                "precision":   "high",
                # Secret, Match, Entropy — deliberately excluded
            })
        return findings
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def strip_sonar(path: str) -> list[dict]:
    """
    Parse SonarQube issues API response.
    Drops: flows, textRange, messageFormattings, component paths with content.
    """
    SEV_MAP = {
        "BLOCKER":  "CRITICAL",
        "CRITICAL": "HIGH",
        "MAJOR":    "HIGH",
        "MINOR":    "MEDIUM",
        "INFO":     "LOW",
    }
    try:
        data = json.load(open(path))
        if not isinstance(data, list):
            return []
        findings = []
        for issue in data:
            # File — strip full path to just filename
            component = issue.get("component", "")
            file_name = Path(component.split(":")[-1]).name if ":" in component else component

            # Severity
            raw_sev  = issue.get("severity", "MAJOR")
            severity = SEV_MAP.get(raw_sev, "MEDIUM")

            # Security standards tags
            sec_standards = issue.get("securityStandards", [])
            cwe   = next((s for s in sec_standards if s.startswith("cwe:")), "N/A")
            owasp = next((s for s in sec_standards if "owasp" in s.lower()), "N/A")
            if cwe != "N/A":
                cwe = "CWE-" + cwe.replace("cwe:", "")

            findings.append({
                "source":      "sonarqube",
                "rule_id":     issue.get("rule", "UNKNOWN"),
                "title":       issue.get("message", "")[:150],
                "severity":    severity,
                "category":    issue.get("type", "VULNERABILITY"),
                "file":        file_name,
                "line":        issue.get("line", 0),
                "description": issue.get("message", "")[:300],
                "cwe":         cwe,
                "owasp":       owasp,
                "effort":      issue.get("effort", ""),
                "debt":        issue.get("debt", ""),
                # flows, textRange, code content — deliberately excluded
            })
        return findings
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def build_payload(findings: list[dict]) -> dict:
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: sev_order.get(x.get("severity", "LOW"), 99))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        s = f.get("severity", "LOW")
        if s in counts:
            counts[s] += 1

    sources = list({f["source"] for f in findings})

    return {
        "scan_metadata": {
            "timestamp":       datetime.utcnow().isoformat() + "Z",
            "total_findings":  len(findings),
            "severity_counts": counts,
            "sources_used":    sources,
        },
        "findings": findings
    }


def main():
    parser = argparse.ArgumentParser(description="Strip raw code from scanner outputs")
    parser.add_argument("--codeql",   default="./reports/codeql_findings.json")
    parser.add_argument("--gitleaks", default="./reports/gitleaks_findings.json")
    parser.add_argument("--sonar",    default="./reports/sonar_findings.json")
    parser.add_argument("--output",   default="./reports/sanitized_meta.json")
    args = parser.parse_args()

    codeql_f   = strip_codeql(args.codeql)
    gitleaks_f = strip_gitleaks(args.gitleaks)
    sonar_f    = strip_sonar(args.sonar)

    all_findings = codeql_f + gitleaks_f + sonar_f
    payload      = build_payload(all_findings)

    with open(args.output, "w") as f:
        json.dump(payload, f, indent=2)

    m = payload["scan_metadata"]
    print(f"  ✓ {m['total_findings']} findings sanitized")
    print(f"  ✓ CRITICAL={m['severity_counts']['CRITICAL']} "
          f"HIGH={m['severity_counts']['HIGH']} "
          f"MEDIUM={m['severity_counts']['MEDIUM']} "
          f"LOW={m['severity_counts']['LOW']}")
    print(f"  ✓ Sources: {', '.join(m['sources_used']) or 'none'}")
    print(f"  ✓ No source code in output — safe for AI")


if __name__ == "__main__":
    main()
