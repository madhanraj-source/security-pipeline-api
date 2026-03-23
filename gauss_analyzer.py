#!/usr/bin/env python3
"""
Stage 3: Samsung Gauss API Analyzer
Asks Gauss ONLY for findings array per batch (no wrapper).
Builds the full report structure in Python.
This avoids truncation issues with large JSON schemas.
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

BATCH_SIZE = 5

# ── Minimal prompt — just ask for findings array ──────────────
SYSTEM_PROMPT = """You are a security engineer. Analyze findings and return ONLY a JSON array.

RULES:
1. Return ONLY a JSON array starting with [ and ending with ]
2. No markdown, no backticks, no explanation text
3. Each item must have exactly these fields:

[
  {
    "id": "<rule_id>",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "source": "<codeql|gitleaks|sonarqube>",
    "title": "<short title>",
    "file": "<filename>",
    "line": 0,
    "category": "<category>",
    "cwe": "<CWE-XXX or N/A>",
    "owasp": "<OWASP ref or N/A>",
    "what_it_means": "<2 sentences>",
    "attack_scenario": "<1 sentence>",
    "business_impact": "<1 sentence>",
    "fix_summary": "<1 sentence>",
    "fix_steps": ["<step 1>", "<step 2>"],
    "fix_code_example": "BEFORE: <bad> | AFTER: <good>",
    "priority": 5
  }
]"""

# ── Summary prompt — separate call for executive summary ──────
SUMMARY_PROMPT = """You are a security engineer. Given these security findings, return ONLY a JSON object.

RULES:
1. Return ONLY a JSON object starting with { and ending with }
2. No markdown, no backticks, no explanation

Return exactly:
{
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
  "key_risk_statement": "<2 sentences summarizing the most critical risks>",
  "immediate_action_required": true|false,
  "attack_surface_summary": "<1 sentence>",
  "owasp_top10_violations": ["<OWASP category>"],
  "cwe_references": ["<CWE-XXX>"],
  "recommendations": [
    {
      "area": "<domain>",
      "action": "<recommendation>",
      "rationale": "<why>",
      "effort": "LOW|MEDIUM|HIGH"
    }
  ]
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


# ── Extract text from Gauss response ─────────────────────────
def extract_text(raw: dict) -> str:
    text = ""

    # Regular Gauss model
    if raw.get("content"):
        content = raw["content"]
        if isinstance(content, str):
            text = content
        elif isinstance(content, list) and content:
            first = content[0]
            text = first if isinstance(first, str) else first.get("text", "")

    # Thinking model (GaussO-Whale-L-Think)
    if not text and raw.get("reasoningContent"):
        text = raw["reasoningContent"]

    # Generic fallbacks
    if not text:
        for k in ["message", "result", "response", "text"]:
            if raw.get(k):
                text = str(raw[k])
                break

    return text.strip()


# ── Single Gauss API call ─────────────────────────────────────
def gauss_call(prompt: str, user_msg: str, system: str) -> str | None:
    pass_key = GAUSS_PASS_KEY
    if not pass_key.startswith("Bearer"):
        pass_key = f"Bearer {pass_key}"

    headers = {
        "Content-Type":           "application/json",
        "x-generative-ai-client": GAUSS_CLIENT_KEY,
        "x-openapi-token":        pass_key,
    }
    if GAUSS_EMAIL:
        headers["x-generative-ai-user-email"] = GAUSS_EMAIL

    body = {
        "modelIds":  [GAUSS_MODEL_ID],
        "contents":  [user_msg],
        "llmConfig": {
            "max_new_tokens":     4096,
            "seed":               None,
            "top_k":              14,
            "top_p":              0.94,
            "temperature":        0.1,
            "repetition_penalty": 1.04
        },
        "isStream":     False,
        "systemPrompt": system
    }

    api_url = f"{GAUSS_ENDPOINT}/openapi/chat/v1/messages"

    for attempt in range(3):
        try:
            resp = requests.post(api_url, headers=headers, json=body, timeout=90)
            resp.raise_for_status()
            text = extract_text(resp.json())
            if text:
                return text
            print(f"  ⚠ Empty response attempt {attempt+1}/3")
            time.sleep(5)

        except requests.exceptions.Timeout:
            print(f"  ⚠ Timeout attempt {attempt+1}/3 — retrying...")
            time.sleep(10)
        except requests.exceptions.HTTPError as e:
            print(f"  ERROR: HTTP {e.response.status_code}: {e.response.text[:200]}")
            return None
        except requests.exceptions.ConnectionError:
            print("  ERROR: Cannot connect to Gauss API.")
            return None

    return None


# ── Parse JSON array from response ───────────────────────────
def parse_array(text: str) -> list:
    text = text.strip()
    text = re.sub(r'^```(?:json)?\s*', '', text, flags=re.MULTILINE)
    text = re.sub(r'\s*```$',          '', text, flags=re.MULTILINE)
    text = text.strip()

    # Find array
    match = re.search(r'\[[\s\S]*\]', text)
    if match:
        text = match.group()

    try:
        result = json.loads(text)
        if isinstance(result, list):
            return result
    except json.JSONDecodeError:
        pass

    # Try to extract individual objects from partial array
    objects = re.findall(r'\{[^{}]*\}', text, re.DOTALL)
    parsed = []
    for obj in objects:
        try:
            parsed.append(json.loads(obj))
        except json.JSONDecodeError:
            continue
    return parsed


# ── Parse JSON object from response ──────────────────────────
def parse_object(text: str) -> dict | None:
    text = text.strip()
    text = re.sub(r'^```(?:json)?\s*', '', text, flags=re.MULTILINE)
    text = re.sub(r'\s*```$',          '', text, flags=re.MULTILINE)
    text = text.strip()

    match = re.search(r'\{[\s\S]*\}', text)
    if match:
        text = match.group()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


# ── Main Gauss analysis ───────────────────────────────────────
def call_gauss(metadata: dict) -> dict:
    findings = metadata.get("findings", [])
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings = sorted(findings, key=lambda x: sev_order.get(x.get("severity","LOW"), 99))

    batches       = [findings[i:i+BATCH_SIZE] for i in range(0, len(findings), BATCH_SIZE)]
    total_batches = len(batches)
    print(f"  → {len(findings)} findings split into {total_batches} batch(es) of {BATCH_SIZE}")

    all_findings = []

    # ── Step 1: Get findings analysis per batch ───────────────
    for i, batch in enumerate(batches, 1):
        print(f"  → Batch {i}/{total_batches} ({len(batch)} findings)...")

        user_msg = (
            f"Analyze these {len(batch)} security findings and return the JSON array.\n\n"
            f"FINDINGS:\n{json.dumps(batch, indent=2)}\n\n"
            "Return ONLY the JSON array starting with [ and ending with ]"
        )

        text = gauss_call(SYSTEM_PROMPT, user_msg, SYSTEM_PROMPT)
        if text:
            parsed = parse_array(text)
            if parsed:
                all_findings.extend(parsed)
                print(f"  ✓ Batch {i}: {len(parsed)} findings analyzed")
            else:
                print(f"  ⚠ Batch {i}: could not parse response — using raw findings")
                all_findings.extend(batch)  # fallback: use original metadata
        else:
            print(f"  ⚠ Batch {i}: no response — using raw findings")
            all_findings.extend(batch)  # fallback: use original metadata

        if i < total_batches:
            time.sleep(2)

    # ── Step 2: Get executive summary (separate smaller call) ─
    print(f"  → Getting executive summary...")
    summary_input = {
        "total_findings": len(all_findings),
        "severity_counts": {
            "CRITICAL": sum(1 for f in all_findings if f.get("severity","").upper() == "CRITICAL"),
            "HIGH":     sum(1 for f in all_findings if f.get("severity","").upper() == "HIGH"),
            "MEDIUM":   sum(1 for f in all_findings if f.get("severity","").upper() == "MEDIUM"),
            "LOW":      sum(1 for f in all_findings if f.get("severity","").upper() == "LOW"),
        },
        "top_issues": [
            {"title": f.get("title",""), "severity": f.get("severity",""), "file": f.get("file","")}
            for f in all_findings[:10]
        ]
    }

    summary_msg = (
        f"Based on these security scan results, provide the summary JSON object.\n\n"
        f"SCAN SUMMARY:\n{json.dumps(summary_input, indent=2)}\n\n"
        "Return ONLY the JSON object starting with { and ending with }"
    )

    summary_text = gauss_call(SUMMARY_PROMPT, summary_msg, SUMMARY_PROMPT)
    summary_data = parse_object(summary_text) if summary_text else None

    # ── Step 3: Build final report ────────────────────────────
    counts = summary_input["severity_counts"]
    overall_risk = "LOW"
    if counts["CRITICAL"] > 0:  overall_risk = "CRITICAL"
    elif counts["HIGH"] > 0:    overall_risk = "HIGH"
    elif counts["MEDIUM"] > 0:  overall_risk = "MEDIUM"

    report = {
        "report_title": "Security Analysis Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "executive_summary": {
            "overall_risk":              summary_data.get("overall_risk", overall_risk) if summary_data else overall_risk,
            "total_issues":              len(all_findings),
            "critical_count":            counts["CRITICAL"],
            "high_count":                counts["HIGH"],
            "medium_count":              counts["MEDIUM"],
            "low_count":                 counts["LOW"],
            "key_risk_statement":        summary_data.get("key_risk_statement", "Security scan complete.") if summary_data else "Security scan complete.",
            "immediate_action_required": summary_data.get("immediate_action_required", counts["CRITICAL"] > 0) if summary_data else counts["CRITICAL"] > 0,
            "attack_surface_summary":    summary_data.get("attack_surface_summary", "") if summary_data else "",
        },
        "findings": all_findings,
        "recommendations": summary_data.get("recommendations", []) if summary_data else [],
        "compliance_flags": {
            "owasp_top10_violations": summary_data.get("owasp_top10_violations", []) if summary_data else [],
            "cwe_references":         summary_data.get("cwe_references", []) if summary_data else [],
        },
        "remediation_priority_order": [
            f.get("id", "") for f in all_findings[:5] if f.get("id")
        ]
    }

    print(f"  ✓ Report built — {len(all_findings)} findings, risk: {report['executive_summary']['overall_risk']}")
    return report


# ── Main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input",    default="./reports/sanitized_meta.json")
    parser.add_argument("--output",   default="./reports/ai_report.json")
    parser.add_argument("--cache",    default="./reports/.ai_cache.json")
    parser.add_argument("--no-cache", action="store_true")
    args = parser.parse_args()

    # Validate credentials
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