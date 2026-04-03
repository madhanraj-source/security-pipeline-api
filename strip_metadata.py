#!/usr/bin/env python3
"""
Stage 2: Metadata Stripper — v2
Parses: Semgrep + Trufflehog + Bearer CLI + Trivy + FossID
Strips ALL source code — only metadata forwarded to Gauss API.
"""

import json
import argparse
from pathlib import Path
from datetime import datetime, timezone


def strip_semgrep(path: str) -> list[dict]:
    SEV_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    try:
        data = json.load(open(path))
        findings = []
        for r in data.get("results", []):
            extra    = r.get("extra", {})
            meta     = extra.get("metadata", {})
            sev_raw  = extra.get("severity", "WARNING")
            severity = SEV_MAP.get(sev_raw.upper(), "MEDIUM")

            cwe_list = meta.get("cwe", [])
            if isinstance(cwe_list, str): cwe_list = [cwe_list]
            cwe = cwe_list[0] if cwe_list else "N/A"

            owasp_list = meta.get("owasp", [])
            if isinstance(owasp_list, str): owasp_list = [owasp_list]
            owasp = owasp_list[0] if owasp_list else "N/A"

            findings.append({
                "source":      "semgrep",
                "rule_id":     r.get("check_id", "UNKNOWN"),
                "title":       extra.get("message", r.get("check_id", ""))[:150],
                "severity":    severity,
                "category":    meta.get("category", "Security"),
                "file":        Path(r.get("path", "unknown")).name,
                "line":        r.get("start", {}).get("line", 0),
                "description": extra.get("message", "")[:300],
                "cwe":         cwe,
                "owasp":       owasp,
                "confidence":  meta.get("confidence", "medium"),
            })
        return findings
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def strip_trufflehog(path: str) -> list[dict]:
    try:
        data = json.load(open(path))
        if not isinstance(data, list): return []
        findings = []
        for f in data:
            src  = f.get("SourceMetadata", {}).get("Data", {})
            fi   = src.get("Filesystem", {})
            findings.append({
                "source":      "trufflehog",
                "rule_id":     f.get("DetectorName", "UNKNOWN"),
                "title":       f"Exposed Secret: {f.get('DetectorName', 'Credential')}",
                "severity":    "CRITICAL",
                "category":    "Secrets & Credentials",
                "file":        Path(fi.get("file", "unknown")).name,
                "line":        fi.get("line", 0),
                "description": f"Type: {f.get('DetectorType','')} — Verified: {f.get('Verified', False)}",
                "cwe":         "CWE-798",
                "owasp":       "A07:2021",
                "verified":    f.get("Verified", False),
            })
        return findings
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def strip_bearer(path: str) -> list[dict]:
    SEV_MAP = {"critical":"CRITICAL","high":"HIGH","medium":"MEDIUM","low":"LOW","warning":"MEDIUM"}
    try:
        data = json.load(open(path))
        raw  = data.get("findings", data.get("high", []) + data.get("medium", []) +
                        data.get("low", []) + data.get("critical", [])) if isinstance(data, dict) else data
        findings = []
        for f in raw:
            sev_raw  = f.get("severity", f.get("level", "medium"))
            severity = SEV_MAP.get(str(sev_raw).lower(), "MEDIUM")
            cwe_ids  = f.get("cwe_ids", f.get("cwe", []))
            if isinstance(cwe_ids, str): cwe_ids = [cwe_ids]
            cwe = f"CWE-{cwe_ids[0]}" if cwe_ids else "N/A"
            findings.append({
                "source":      "bearer",
                "rule_id":     f.get("rule_id", f.get("id", "UNKNOWN")),
                "title":       f.get("title", f.get("description", ""))[:150],
                "severity":    severity,
                "category":    f.get("category_groups", ["Security"])[0] if f.get("category_groups") else "Security",
                "file":        Path(f.get("filename", f.get("file", "unknown"))).name,
                "line":        f.get("line_number", f.get("line", 0)),
                "description": f.get("description", "")[:300],
                "cwe":         cwe,
                "owasp":       f.get("owasp_ids", ["N/A"])[0] if f.get("owasp_ids") else "N/A",
            })
        return findings
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def strip_trivy(path: str) -> list[dict]:
    SEV_MAP = {"CRITICAL":"CRITICAL","HIGH":"HIGH","MEDIUM":"MEDIUM","LOW":"LOW","UNKNOWN":"LOW"}
    try:
        data     = json.load(open(path))
        findings = []
        for result in data.get("Results", []):
            target = result.get("Target", "unknown")
            for vuln in result.get("Vulnerabilities") or []:
                sev = SEV_MAP.get(vuln.get("Severity","UNKNOWN").upper(), "LOW")
                findings.append({
                    "source":      "trivy",
                    "rule_id":     vuln.get("VulnerabilityID", "UNKNOWN"),
                    "title":       vuln.get("Title", vuln.get("VulnerabilityID", ""))[:150],
                    "severity":    sev,
                    "category":    "Dependency Vulnerability",
                    "file":        Path(target).name,
                    "line":        0,
                    "description": vuln.get("Description", "")[:300],
                    "cwe":         f"CVE: {vuln.get('VulnerabilityID','N/A')}",
                    "owasp":       "A06:2021",
                    "package":     vuln.get("PkgName", ""),
                    "version":     vuln.get("InstalledVersion", ""),
                    "fixed_in":    vuln.get("FixedVersion", "Not fixed yet"),
                })
        return findings
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def strip_fossid(path: str) -> list[dict]:
    try:
        data = json.load(open(path))
        if not isinstance(data, list): return []
        findings = []
        for f in data:
            findings.append({
                "source":      "fossid",
                "rule_id":     f.get("license_id", f.get("id", "UNKNOWN")),
                "title":       f"License Issue: {f.get('license_name', f.get('name', 'Unknown License'))}",
                "severity":    "HIGH" if f.get("is_copyleft") else "MEDIUM",
                "category":    "License Compliance",
                "file":        Path(f.get("file_path", f.get("file", "unknown"))).name,
                "line":        0,
                "description": f.get("description", f.get("license_name", ""))[:300],
                "cwe":         "N/A",
                "owasp":       "N/A",
                "license":     f.get("license_name", "Unknown"),
                "component":   f.get("component_name", ""),
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
        if s in counts: counts[s] += 1

    return {
        "scan_metadata": {
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "total_findings":  len(findings),
            "severity_counts": counts,
            "sources_used":    list({f["source"] for f in findings}),
        },
        "findings": findings
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--semgrep",    default="./reports/semgrep_findings.json")
    parser.add_argument("--trufflehog", default="./reports/trufflehog_findings.json")
    parser.add_argument("--bearer",     default="./reports/bearer_findings.json")
    parser.add_argument("--trivy",      default="./reports/trivy_findings.json")
    parser.add_argument("--fossid",     default="./reports/fossid_findings.json")
    parser.add_argument("--output",     default="./reports/sanitized_meta.json")
    args = parser.parse_args()

    all_f = (strip_semgrep(args.semgrep) +
             strip_trufflehog(args.trufflehog) +
             strip_bearer(args.bearer) +
             strip_trivy(args.trivy) +
             strip_fossid(args.fossid))

    payload = build_payload(all_f)
    json.dump(payload, open(args.output, "w"), indent=2)

    m = payload["scan_metadata"]
    print(f"  ✓ {m['total_findings']} findings sanitized")
    print(f"  ✓ CRITICAL={m['severity_counts']['CRITICAL']} HIGH={m['severity_counts']['HIGH']} "
          f"MEDIUM={m['severity_counts']['MEDIUM']} LOW={m['severity_counts']['LOW']}")
    print(f"  ✓ Sources: {', '.join(m['sources_used']) or 'none'}")
    print(f"  ✓ No source code in output")

if __name__ == "__main__":
    main()
