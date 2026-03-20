#!/usr/bin/env python3
"""
Stage 3: Samsung Gauss API Analyzer
Built from actual Gauss API reference script.
Sends sanitized metadata only — zero source code.
"""

import json
import os
import hashlib
import argparse
import sys
import re
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("ERROR: pip install requests")
    sys.exit(1)

# ── Load .env ─────────────────────────────────────────────────
if os.path.exists(".env"):
    for line in open(".env"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"'))

GAUSS_ENDPOINT   = os.environ.get("GAUSS_API_URL", "")
GAUSS_CLIENT_KEY = os.environ.get("GAUSS_CLIENT_KEY", "")
GAUSS_PASS_KEY   = os.environ.get("GAUSS_PASS_KEY", "")
GAUSS_MODEL_ID   = os.environ.get("GAUSS_MODEL_ID", "")
GAUSS_EMAIL      = os.environ.get("GAUSS_EMAIL", "")

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


# ── Gauss API call ────────────────────────────────────────────
def call_gauss(metadata: dict) -> dict:
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

    total = metadata.get("scan_metadata", {}).get("total_findings", 0)
    print(f"  → Calling Gauss API [{GAUSS_MODEL_ID}]")
    print(f"  → Sending {total} findings — zero source code")

    user_message = (
        "Analyze the following security scan results and return your JSON report.\n\n"
        "SCAN RESULTS:\n"
        f"{json.dumps(metadata, indent=2)}\n\n"
        "Return ONLY the JSON object. Start with { and end with }"
    )

    # ── Headers — from official Gauss API sample ──────────────
    headers = {
        "Content-Type":           "application/json",
        "x-generative-ai-client": GAUSS_CLIENT_KEY,
        "x-openapi-token":        GAUSS_PASS_KEY,
    }
    if GAUSS_EMAIL:
        headers["x-generative-ai-user-email"] = GAUSS_EMAIL

    # ── Body — from official Gauss API sample ─────────────────
    body = {
        "modelIds":  [GAUSS_MODEL_ID],
        "contents":  [user_message],        # list of strings
        "llmConfig": {
            "max_new_tokens":     8192,
            "seed":               None,
            "top_k":              14,
            "top_p":              0.94,
            "temperature":        0.1,      # low = consistent output
            "repetition_penalty": 1.04
        },
        "isStream":     False,
        "systemPrompt": SYSTEM_PROMPT.strip()
    }

    # ── Endpoint — from official Gauss API sample ─────────────
    api_url = f"{GAUSS_ENDPOINT}/openapi/chat/v1/messages"

    try:
        print(f"  → POST {api_url}")
        resp = requests.post(api_url, headers=headers, json=body, timeout=120)
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        print("ERROR: Gauss API timed out after 120s")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"ERROR: HTTP {e.response.status_code}: {e.response.text[:400]}")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print("ERROR: Cannot connect to Gauss API. Check GAUSS_API_URL and network.")
        sys.exit(1)

    return parse_response(resp.json())


def parse_response(raw: dict) -> dict:
    """
    Parse Gauss response.
    From official sample: response_data.get('content', 'No content in response')
    Primary field is 'content'
    """
    text = ""

    # Primary — official Gauss API response field
    if "content" in raw:
        content = raw["content"]
        if isinstance(content, str):
            text = content
        elif isinstance(content, list) and content:
            first = content[0]
            if isinstance(first, str):
                text = first
            elif isinstance(first, dict):
                text = first.get("text", "") or first.get("content", "")

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
        print(f"  ⚠ Empty response from Gauss: {str(raw)[:200]}")
        return error_report(str(raw))

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
        print("  ✓ Valid JSON report received from Gauss API")
        return report
    except json.JSONDecodeError as e:
        print(f"  ⚠ JSON parse failed: {e}")
        print(f"  Preview: {text[:300]}")
        return error_report(text)


def error_report(raw: str) -> dict:
    return {
        "report_title": "Security Analysis Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "parse_error":  True,
        "raw_response": raw[:2000],
        "executive_summary": {
            "overall_risk": "UNKNOWN", "total_issues": 0,
            "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0,
            "key_risk_statement": "AI response could not be parsed. Check raw_response field.",
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
            print(f"  ✓ Report cached [{key}]")

    json.dump(report, open(args.output, "w"), indent=2)
    risk      = report.get("executive_summary", {}).get("overall_risk", "UNKNOWN")
    total_out = len(report.get("findings", []))
    print(f"  ✓ Saved → {args.output}  |  Risk: {risk}  |  Findings: {total_out}")


if __name__ == "__main__":
    main()
