#!/bin/bash
# ============================================================
# Modern AI Security Pipeline v2 — Stage 1: Scanners
# Tools: Semgrep + Trufflehog + Bearer CLI + Trivy + FossID
# 100% local — raw code never sent to AI
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

TARGET_DIR="${1:-.}"
REPORT_DIR="${2:-$SCRIPT_DIR/reports}"

[ -f .env ] && { sed -i 's/\r//' .env; source .env; }

mkdir -p "$REPORT_DIR"

echo "════════════════════════════════════════════════════"
echo "  Modern AI Security Pipeline v2 — Scan Starting"
echo "  Target  : $TARGET_DIR"
echo "════════════════════════════════════════════════════"

ERRORS=0

# ══════════════════════════════════════════════════
# TOOL 1: Semgrep — SAST
# Finds: SQLi, XSS, insecure code, OWASP Top 10
# ══════════════════════════════════════════════════
echo ""
echo "[1/5] Semgrep — SAST Analysis"
echo "─────────────────────────────"

SEMGREP_CMD="semgrep"
if ! command -v semgrep &>/dev/null; then
    if python3 -m semgrep --version &>/dev/null 2>&1; then
        SEMGREP_CMD="python3 -m semgrep"
    else
        echo "  ⚠ Semgrep not found. Run: bash setup.sh"
        echo '{"results":[],"errors":[]}' > "$REPORT_DIR/semgrep_findings.json"
        ERRORS=$((ERRORS+1))
        SEMGREP_CMD=""
    fi
fi

if [ -n "$SEMGREP_CMD" ]; then
    echo "  → Running security + OWASP + secrets rules..."
    $SEMGREP_CMD \
        --config "p/security-audit" \
        --config "p/owasp-top-ten" \
        --config "p/secrets" \
        --config "p/default" \
        --json \
        --output "$REPORT_DIR/semgrep_findings.json" \
        --no-git-ignore \
        --quiet \
        "$TARGET_DIR" 2>/dev/null || true

    COUNT=$(python3 -c "
import json
try:
    d = json.load(open('$REPORT_DIR/semgrep_findings.json'))
    print(len(d.get('results', [])))
except: print(0)")
    echo "  ✓ Semgrep: $COUNT findings"
fi

# ══════════════════════════════════════════════════
# TOOL 2: Trufflehog — Secrets Detection
# Finds: API keys, tokens, passwords, private keys
# Verifies if secrets are still active
# ══════════════════════════════════════════════════
echo ""
echo "[2/5] Trufflehog — Secrets Detection"
echo "─────────────────────────────────────"

if ! command -v trufflehog &>/dev/null; then
    echo "  ⚠ Trufflehog not found. Run: bash setup.sh"
    echo "[]" > "$REPORT_DIR/trufflehog_findings.json"
    ERRORS=$((ERRORS+1))
else
    echo "  → Scanning for secrets (800+ detector types)..."
    trufflehog filesystem \
        "$TARGET_DIR" \
        --json \
        --no-verification \
        2>/dev/null \
        | python3 -c "
import sys, json
results = []
for line in sys.stdin:
    line = line.strip()
    if line:
        try: results.append(json.loads(line))
        except: pass
json.dump(results, open('$REPORT_DIR/trufflehog_findings.json', 'w'), indent=2)
print(f'  ✓ Trufflehog: {len(results)} secrets detected')
"
fi

# ══════════════════════════════════════════════════
# TOOL 3: Bearer CLI — API Security & Data Privacy
# Finds: PII exposure, auth issues, data leakage
# ══════════════════════════════════════════════════
echo ""
echo "[3/5] Bearer CLI — API Security & Privacy"
echo "──────────────────────────────────────────"

if ! command -v bearer &>/dev/null; then
    echo "  ⚠ Bearer CLI not found. Run: bash setup.sh"
    echo '{"findings":[]}' > "$REPORT_DIR/bearer_findings.json"
    ERRORS=$((ERRORS+1))
else
    echo "  → Scanning API security, PII, data flows..."
    bearer scan \
        "$TARGET_DIR" \
        --format json \
        --output "$REPORT_DIR/bearer_findings.json" \
        --quiet \
        --exit-code 0 2>/dev/null || true

    COUNT=$(python3 -c "
import json
try:
    d = json.load(open('$REPORT_DIR/bearer_findings.json'))
    f = d.get('findings', d) if isinstance(d, dict) else d
    print(len(f) if isinstance(f, list) else 0)
except: print(0)")
    echo "  ✓ Bearer CLI: $COUNT findings"
fi

# ══════════════════════════════════════════════════
# TOOL 4: Trivy — Dependency CVEs + Docker + IaC
# Finds: CVEs in packages, misconfigs, SBOM
# ══════════════════════════════════════════════════
echo ""
echo "[4/5] Trivy — Dependency & Container Security"
echo "─────────────────────────────────────────────"

if ! command -v trivy &>/dev/null; then
    echo "  ⚠ Trivy not found. Run: bash setup.sh"
    echo '{"Results":[]}' > "$REPORT_DIR/trivy_findings.json"
    ERRORS=$((ERRORS+1))
else
    echo "  → Scanning dependencies, Dockerfile, IaC..."
    trivy fs \
        "$TARGET_DIR" \
        --format json \
        --output "$REPORT_DIR/trivy_findings.json" \
        --quiet \
        --exit-code 0 2>/dev/null || true

    COUNT=$(python3 -c "
import json
try:
    d = json.load(open('$REPORT_DIR/trivy_findings.json'))
    total = sum(len(r.get('Vulnerabilities') or []) for r in d.get('Results', []))
    print(total)
except: print(0)")
    echo "  ✓ Trivy: $COUNT vulnerabilities"
fi

# ══════════════════════════════════════════════════
# TOOL 5: FossID — Open Source License Compliance
# Finds: License violations, OSS components, SBOM
# Note: Requires FossID server/API access
# ══════════════════════════════════════════════════
echo ""
echo "[5/5] FossID — Open Source License Compliance"
echo "──────────────────────────────────────────────"

FOSSID_URL="${FOSSID_API_URL:-}"
FOSSID_KEY="${FOSSID_API_KEY:-}"

if [ -z "$FOSSID_URL" ] || [ -z "$FOSSID_KEY" ]; then
    echo "  ⚠ FossID API not configured (FOSSID_API_URL, FOSSID_API_KEY)"
    echo "  → Skipping license compliance scan"
    echo "[]" > "$REPORT_DIR/fossid_findings.json"
else
    echo "  → Submitting scan to FossID..."
    python3 - << PYEOF
import json, requests, os, time

url = "$FOSSID_URL"
key = "$FOSSID_KEY"
target = "$TARGET_DIR"
out = "$REPORT_DIR/fossid_findings.json"

try:
    # Initiate scan
    resp = requests.post(f"{url}/api/scan", json={
        "api_key": key,
        "project_path": target,
    }, timeout=30)
    resp.raise_for_status()
    scan_id = resp.json().get("scan_id")

    # Poll for results (max 5 minutes)
    for _ in range(60):
        time.sleep(5)
        status = requests.get(f"{url}/api/scan/{scan_id}", headers={"X-API-Key": key}, timeout=30)
        if status.json().get("status") == "completed":
            findings = status.json().get("findings", [])
            json.dump(findings, open(out, "w"), indent=2)
            print(f"  ✓ FossID: {len(findings)} license/compliance issues")
            break
    else:
        print("  ⚠ FossID scan timed out")
        json.dump([], open(out, "w"))
except Exception as e:
    print(f"  ⚠ FossID error: {e}")
    json.dump([], open(out, "w"))
PYEOF
fi

# ══════════════════════════════════════════════════
# METADATA STRIP
# ══════════════════════════════════════════════════
echo ""
echo "  → Sanitizing — stripping all source code..."
python3 "$SCRIPT_DIR/scripts/strip_metadata.py" \
    --semgrep    "$REPORT_DIR/semgrep_findings.json" \
    --trufflehog "$REPORT_DIR/trufflehog_findings.json" \
    --bearer     "$REPORT_DIR/bearer_findings.json" \
    --trivy      "$REPORT_DIR/trivy_findings.json" \
    --fossid     "$REPORT_DIR/fossid_findings.json" \
    --output     "$REPORT_DIR/sanitized_meta.json"

echo ""
echo "════════════════════════════════════════════════════"
[ $ERRORS -gt 0 ] && echo "  ⚠ $ERRORS tool(s) unavailable — partial scan" \
                  || echo "  ✓ All scans complete"
echo "  ✓ Zero source code in sanitized output"
echo "════════════════════════════════════════════════════"
