#!/usr/bin/env python3
"""
Stage 2: Metadata Stripper
Parses Semgrep + Trufflehog + Bearer CLI outputs.
Strips ALL source code — only metadata forwarded to Gauss API.
"""

import json
import argparse
from pathlib import Path
from datetime import datetime, timezone


def strip_semgrep(path: str) -> list[dict]:
    """Parse Semgrep JSON output — drop code snippets."""
    SEV_MAP = {
        "ERROR":   "HIGH",
        "WARNING": "MEDIUM",
        "INFO":    "LOW",
    }
    try:
        data = json.load(open(path))
        results = data.get("results", [])
        findings = []
        for r in results:
            extra   = r.get("extra", {})
            meta    = extra.get("metadata", {})
            sev_raw = extra.get("severity", "WARNING")
            severity = SEV_MAP.get(sev_raw.upper(), "MEDIUM")

            # Upgrade to CRITICAL if CWE is high severity
            cwe_list = meta.get("cwe", [])
            if isinstance(cwe_list, str):
                cwe_list = [cwe_list]
            cwe = cwe_list[0] if cwe_list else "N/A"

            owasp_list = meta.get("owasp", [])
            if isinstance(owasp_list, str):
                owasp_list = [owasp_list]
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
                # 'lines' code snippet — deliberately excluded
            })
        return findings
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def strip_trufflehog(path: str) -> list[dict]:
    """Parse Trufflehog JSON output — drop actual secret values."""
    try:
        data = json.load(open(path))
        if not isinstance(data, list):
            return []
        findings = []
        for f in data:
            source_meta = f.get("SourceMetadata", {}).get("Data", {})
            file_info   = source_meta.get("Filesystem", {})
            findings.append({
                "source":      "trufflehog",
                "rule_id":     f.get("DetectorName", "UNKNOWN"),
                "title":       f"Exposed Secret: {f.get('DetectorName', 'Credential')}",
                "severity":    "CRITICAL",
                "category":    "Secrets & Credentials",
                "file":        Path(file_info.get("file", "unknown")).name,
                "line":        file_info.get("line", 0),
                "description": f"Detector: {f.get('DetectorName','')} — Type: {f.get('DetectorType','')}",
                "cwe":         "CWE-798",
                "owasp":       "A07:2021",
                "verified":    f.get("Verified", False),
                # Raw, DecoderName, Redacted — deliberately excluded
            })
        return findings
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def strip_bearer(path: str) -> list[dict]:
    """Parse Bearer CLI JSON output — drop code snippets."""
    SEV_MAP = {
        "critical": "CRITICAL",
        "high":     "HIGH",
        "medium":   "MEDIUM",
        "low":      "LOW",
        "warning":  "MEDIUM",
    }
    try:
        data = json.load(open(path))
        # Bearer output can be dict with 'findings' or a list
        if isinstance(data, dict):
            raw_findings = data.get("findings", data.get("high", []) +
                                   data.get("medium", []) +
                                   data.get("low", []) +
                                   data.get("critical", []))
        else:
            raw_findings = data

        findings = []
        for f in raw_findings:
            # Handle both flat and nested structures
            sev_raw  = f.get("severity", f.get("level", "medium"))
            severity = SEV_MAP.get(str(sev_raw).lower(), "MEDIUM")

            cwe_ids  = f.get("cwe_ids", f.get("cwe", []))
            if isinstance(cwe_ids, str):
                cwe_ids = [cwe_ids]
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
                # source_code, code_extract — deliberately excluded
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
    parser.add_argument("--output",     default="./reports/sanitized_meta.json")
    args = parser.parse_args()

    semgrep_f    = strip_semgrep(args.semgrep)
    trufflehog_f = strip_trufflehog(args.trufflehog)
    bearer_f     = strip_bearer(args.bearer)
    all_f        = semgrep_f + trufflehog_f + bearer_f

    payload = build_payload(all_f)
    json.dump(payload, open(args.output, "w"), indent=2)

    m = payload["scan_metadata"]
    print(f"  ✓ {m['total_findings']} findings sanitized")
    print(f"  ✓ CRITICAL={m['severity_counts']['CRITICAL']} "
          f"HIGH={m['severity_counts']['HIGH']} "
          f"MEDIUM={m['severity_counts']['MEDIUM']} "
          f"LOW={m['severity_counts']['LOW']}")
    print(f"  ✓ Sources: {', '.join(m['sources_used']) or 'none'}")
    print(f"  ✓ No source code in output")


if __name__ == "__main__":
    main()
