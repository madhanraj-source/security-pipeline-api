#!/usr/bin/env python3
"""
Stage 3: Samsung Gauss API Analyzer
Sends findings in batches to avoid timeout.
Merges all batch results into one complete report.
"""

import json
import os
import hashlib
import argparse
import sys
import re
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("ERROR: pip install requests")
    sys.exit(1)

# ── Load .env ─────────────────────────────────────────────────
if os.path.exists(".env"):
    for line in open(".env", encoding="utf-8", errors="replace"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"'))

GAUSS_ENDPOINT   = os.environ.get("GAUSS_API_URL", "")
GAUSS_CLIENT_KEY = os.environ.get("GAUSS_CLIENT_KEY", "")
GAUSS_PASS_KEY   = os.environ.get("GAUSS_PASS_KEY", "")
GAUSS_MODEL_ID   = os.environ.get("GAUSS_MODEL_ID", "")
GAUSS_EMAIL      = os.environ.get("GAUSS_EMAIL", "")

BATCH_SIZE = 10  # findings per API call — small to avoid timeout

# ── Strict system prompt ──────────────────────────────────────
SYSTEM_PROMPT = """You are a senior application security engineer.

RULES — NO EXCEPTIONS:
1. Respond ONLY with a valid JSON object. Nothing before or after it.
2. No markdown, no backticks, no preamble, no text outside the JSON.
3. Every field in the schema MUST be present.
4. severity must be exactly: CRITICAL, HIGH, MEDIUM, or LOW
5. For each finding write detailed fix_steps and fix_code_example with BEFORE/AFTER.

Return EXACTLY this JSON schema:
{
  "report_title": "Security Analysis Report",
  "generated_at": "<ISO 8601>",
  "executive_summary": {
    "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
    "total_issues": 0,
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0,
    "key_risk_statement": "<1-2 sentences: most critical risk in plain language>",
    "immediate_action_required": false,
    "attack_surface_summary": "<1 sentence: what parts of the system are exposed>"
  },
  "findings": [
    {
      "id": "<rule_id from input>",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "source": "<codeql|gitleaks|sonarqube>",
      "title": "<short specific title>",
      "file": "<filename>",
      "line": 0,
      "category": "<security category>",
      "cwe": "<CWE-XXX or N/A>",
      "owasp": "<OWASP A0X:20XX or N/A>",
      "what_it_means": "<2-3 sentences plain language explanation>",
      "attack_scenario": "<1-2 sentences: realistic attacker exploit>",
      "business_impact": "<1 sentence: data or business risk>",
      "fix_summary": "<one sentence fix action>",
      "fix_steps": ["<step 1>", "<step 2>", "<step 3>"],
      "fix_code_example": "BEFORE: <vulnerable code> | AFTER: <secure code>",
      "references": ["<CWE or OWASP URL>"],
      "priority": 8
    }
  ],
  "recommendations": [
    {
      "area": "<security domain>",
      "action": "<specific actionable recommendation>",
      "rationale": "<why this matters>",
      "effort": "LOW|MEDIUM|HIGH"
    }
  ],
  "compliance_flags": {
    "owasp_top10_violations": ["<OWASP category>"],
    "cwe_references": ["<CWE-XXX>"]
  },
  "remediation_priority_order": ["<rule_id most critical>", "<rule_id second>"]
}"""


# ── Cache ─────────────────────────────────────────────────────
def cache_key(metadata: dict) -> str:
    stable = {"findings": [
        {k: v for k, v in f.items() if k != "timestamp"}
        for f in metadata.get("findings", [])
    ]}
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()[:16]

def load_cache(path: str, key: str) -> dict | None:
    try:
        cached = json.load(open(path))
        if cached.get("_cache_key") == key and not cached.get("parse_error"):
            print(f"  ✓ Cache hit [{key}] — reusing stable report")
            return cached
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return None

def save_cache(path: str, key: str, report: dict):
    report["_cache_key"] = key
    json.dump(report, open(path, "w"), indent=2)


# ── Single Gauss API batch call ───────────────────────────────
def call_gauss_batch(findings: list, batch_num: int, total_batches: int) -> dict | None:
    missing = [name for val, name in [
        (GAUSS_ENDPOINT,   "GAUSS_API_URL"),
        (GAUSS_CLIENT_KEY, "GAUSS_CLIENT_KEY"),
        (GAUSS_PASS_KEY,   "GAUSS_PASS_KEY"),
        (GAUSS_MODEL_ID,   "GAUSS_MODEL_ID"),
    ] if not val]

    if missing:
        for m in missing:
            print(f"ERROR: {m} not set in .env")
        sys.exit(1)

    user_message = (
        f"Analyze these security findings (batch {batch_num}/{total_batches}) "
        f"and return the JSON report.\n\n"
        f"FINDINGS:\n{json.dumps(findings, indent=2)}\n\n"
        "Return ONLY the JSON object. Start with { and end with }"
    )

    # Headers — from official Gauss API sample
    headers = {
        "Content-Type":           "application/json",
        "x-generative-ai-client": GAUSS_CLIENT_KEY,
        "x-openapi-token":        f"Bearer {GAUSS_PASS_KEY}",
    }
    if GAUSS_EMAIL:
        headers["x-generative-ai-user-email"] = GAUSS_EMAIL

    # Body — from official Gauss API sample
    body = {
        "modelIds":  [GAUSS_MODEL_ID],
        "contents":  [user_message],
        "llmConfig": {
            "max_new_tokens":     4096,
            "seed":               None,
            "top_k":              14,
            "top_p":              0.94,
            "temperature":        0.1,
            "repetition_penalty": 1.04
        },
        "isStream":     False,
        "systemPrompt": SYSTEM_PROMPT.strip()
    }

    api_url = f"{GAUSS_ENDPOINT}/openapi/chat/v1/messages"

    for attempt in range(3):
        try:
            resp = requests.post(api_url, headers=headers, json=body, timeout=90)
            resp.raise_for_status()
            return parse_response(resp.json())

        except requests.exceptions.Timeout:
            print(f"  ⚠ Timeout on attempt {attempt+1}/3 — retrying...")
            time.sleep(10)
        except requests.exceptions.HTTPError as e:
            print(f"  ERROR: HTTP {e.response.status_code}: {e.response.text[:300]}")
            return None
        except requests.exceptions.ConnectionError:
            print("  ERROR: Cannot connect to Gauss API.")
            return None

    print(f"  ⚠ Batch {batch_num} failed after 3 attempts — skipping")
    return None


def parse_response(raw: dict) -> dict | None:
    text = ""

    # Primary field from official Gauss sample
    if "content" in raw:
        content = raw["content"]
        if isinstance(content, str):
            text = content
        elif isinstance(content, list) and content:
            first = content[0]
            text = first if isinstance(first, str) else first.get("text", "")

    # Fallbacks
    if not text:
        for extractor in [
            lambda r: r["message"],
            lambda r: r["result"],
            lambda r: r["choices"][0]["message"]["content"],
        ]:
            try:
                val = extractor(raw)
                if val:
                    text = val
                    break
            except (KeyError, IndexError, TypeError):
                continue

    if not text:
        print(f"  ⚠ Empty response: {str(raw)[:200]}")
        return None

    # Strip markdown fences
    text = text.strip()
    text = re.sub(r'^```(?:json)?\s*', '', text, flags=re.MULTILINE)
    text = re.sub(r'\s*```$',          '', text, flags=re.MULTILINE)
    text = text.strip()

    # Extract JSON object
    match = re.search(r'\{[\s\S]*\}', text)
    if match:
        text = match.group()

    try:
        report = json.loads(text)
        return report
    except json.JSONDecodeError as e:
        print(f"  ⚠ JSON parse failed: {e} — preview: {text[:200]}")
        return None


# ── Main Gauss call with batching ─────────────────────────────
def call_gauss(metadata: dict) -> dict:
    # Sort by severity
    findings = metadata.get("findings", [])
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings = sorted(findings, key=lambda x: sev_order.get(x.get("severity","LOW"), 99))

    # Split into batches
    batches = [findings[i:i+BATCH_SIZE] for i in range(0, len(findings), BATCH_SIZE)]
    total_batches = len(batches)
    print(f"  → {len(findings)} findings split into {total_batches} batch(es) of {BATCH_SIZE}")

    all_findings = []
    base_report  = None

    for i, batch in enumerate(batches, 1):
        print(f"  → Batch {i}/{total_batches} ({len(batch)} findings)...")
        result = call_gauss_batch(batch, i, total_batches)

        if result is None:
            print(f"  ⚠ Batch {i} failed — skipping")
            continue

        if base_report is None:
            base_report = result

        all_findings.extend(result.get("findings", []))

        # Small delay between batches to avoid overloading API
        if i < total_batches:
            time.sleep(2)

    if base_report is None:
        print("ERROR: All batches failed")
        sys.exit(1)

    # Merge all findings into base report
    base_report["findings"] = all_findings

    # Recalculate counts from actual findings
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        s = f.get("severity", "LOW").upper()
        if s in counts:
            counts[s] += 1

    base_report["executive_summary"]["total_issues"]   = len(all_findings)
    base_report["executive_summary"]["critical_count"] = counts["CRITICAL"]
    base_report["executive_summary"]["high_count"]     = counts["HIGH"]
    base_report["executive_summary"]["medium_count"]   = counts["MEDIUM"]
    base_report["executive_summary"]["low_count"]      = counts["LOW"]

    print(f"  ✓ Total findings in report: {len(all_findings)}")
    return base_report


def error_report() -> dict:
    return {
        "report_title": "Security Analysis Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "parse_error":  True,
        "executive_summary": {
            "overall_risk": "UNKNOWN", "total_issues": 0,
            "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0,
            "key_risk_statement": "AI analysis failed. Check logs.",
            "immediate_action_required": False,
            "attack_surface_summary": "Unknown"
        },
        "findings": [], "recommendations": [],
        "compliance_flags": {"owasp_top10_violations": [], "cwe_references": []},
        "remediation_priority_order": []
    }


# ── Main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input",    default="./reports/sanitized_meta.json")
    parser.add_argument("--output",   default="./reports/ai_report.json")
    parser.add_argument("--cache",    default="./reports/.ai_cache.json")
    parser.add_argument("--no-cache", action="store_true")
    args = parser.parse_args()

    try:
        metadata = json.load(open(args.input))
    except FileNotFoundError:
        print(f"ERROR: {args.input} not found. Run scanner first.")
        sys.exit(1)

    total = metadata.get("scan_metadata", {}).get("total_findings", 0)

    if total == 0:
        print("  ✓ No findings — generating clean report")
        report = {
            "report_title": "Security Analysis Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "executive_summary": {
                "overall_risk": "LOW", "total_issues": 0,
                "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0,
                "key_risk_statement": "No security issues detected in this scan.",
                "immediate_action_required": False,
                "attack_surface_summary": "No exposed attack surface detected."
            },
            "findings": [],
            "recommendations": [{"area": "General", "action": "Continue regular security scanning.",
                                  "rationale": "Proactive scanning prevents future issues.",
                                  "effort": "LOW"}],
            "compliance_flags": {"owasp_top10_violations": [], "cwe_references": []},
            "remediation_priority_order": []
        }
    else:
        key    = cache_key(metadata)
        report = None
        if not args.no_cache:
            report = load_cache(args.cache, key)
        if report is None:
            report = call_gauss(metadata)
            save_cache(args.cache, key, report)
            print(f"  ✓ Cached [{key}]")

    json.dump(report, open(args.output, "w"), indent=2)
    risk      = report.get("executive_summary", {}).get("overall_risk", "UNKNOWN")
    total_out = len(report.get("findings", []))
    print(f"  ✓ Saved → {args.output}  |  Risk: {risk}  |  Findings: {total_out}")


if __name__ == "__main__":
    main()