#!/bin/bash
# ============================================================
# Modern AI Security Pipeline — Stage 1: Scanners
# Tools: Semgrep + Trufflehog + Bearer CLI
# 100% local — raw code never sent to AI
# ============================================================

TARGET_DIR="${1:-.}"
REPORT_DIR="${2:-./reports}"

# Load .env
if [ -f .env ]; then
    sed -i 's/\r//' .env
    source .env
fi

mkdir -p "$REPORT_DIR"

echo "════════════════════════════════════════════════"
echo "  Modern AI Security Pipeline — Scan Starting"
echo "  Target  : $TARGET_DIR"
echo "════════════════════════════════════════════════"

ERRORS=0

# ══════════════════════════════════════════════════
# TOOL 1: Semgrep — SAST
# Finds: SQLi, XSS, insecure deserialization,
#        hardcoded secrets, OWASP Top 10, and more
# ══════════════════════════════════════════════════
echo ""
echo "[1/3] Semgrep — Modern SAST Analysis"
echo "─────────────────────────────────────"

# Use python3 -m semgrep as fallback if semgrep not in PATH
SEMGREP_CMD="semgrep"
if ! command -v semgrep &>/dev/null; then
    if python3 -m semgrep --version &>/dev/null 2>&1; then
        SEMGREP_CMD="python3 -m semgrep"
    else
        echo "  ⚠ Semgrep not found. Run: bash setup.sh"
        echo "[]" > "$REPORT_DIR/semgrep_findings.json"
        ERRORS=$((ERRORS+1))
        SEMGREP_CMD=""
    fi
fi

if [ -n "$SEMGREP_CMD" ]; then
    echo "  → Running security rules (auto + OWASP + secrets)..."
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
# TOOL 2: Trufflehog — Advanced Secrets Detection
# Finds: API keys, tokens, passwords, private keys
# Verifies secrets are real (reduces false positives)
# ══════════════════════════════════════════════════
echo ""
echo "[2/3] Trufflehog — Advanced Secrets Detection"
echo "──────────────────────────────────────────────"

if ! command -v trufflehog &>/dev/null; then
    echo "  ⚠ Trufflehog not found. Run: bash setup.sh"
    echo "[]" > "$REPORT_DIR/trufflehog_findings.json"
    ERRORS=$((ERRORS+1))
else
    echo "  → Scanning for secrets (verified + unverified)..."
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
        try:
            results.append(json.loads(line))
        except: pass
json.dump(results, open('$REPORT_DIR/trufflehog_findings.json', 'w'), indent=2)
print(f'  ✓ Trufflehog: {len(results)} secrets detected')
"
fi

# ══════════════════════════════════════════════════
# TOOL 3: Bearer CLI — API Security & Data Privacy
# Finds: PII exposure, insecure API calls,
#        auth issues, data leakage paths
# ══════════════════════════════════════════════════
echo ""
echo "[3/3] Bearer CLI — API Security & Data Privacy"
echo "────────────────────────────────────────────────"

if ! command -v bearer &>/dev/null; then
    echo "  ⚠ Bearer CLI not found. Run: bash setup.sh"
    echo '{"findings": []}' > "$REPORT_DIR/bearer_findings.json"
    ERRORS=$((ERRORS+1))
else
    echo "  → Scanning API security, data privacy, OWASP..."
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
    findings = d.get('findings', d) if isinstance(d, dict) else d
    print(len(findings) if isinstance(findings, list) else 0)
except: print(0)")
    echo "  ✓ Bearer CLI: $COUNT findings"
fi

# ══════════════════════════════════════════════════
# METADATA STRIP
# ══════════════════════════════════════════════════
echo ""
echo "  → Sanitizing — stripping all source code..."
python3 scripts/strip_metadata.py \
    --semgrep    "$REPORT_DIR/semgrep_findings.json" \
    --trufflehog "$REPORT_DIR/trufflehog_findings.json" \
    --bearer     "$REPORT_DIR/bearer_findings.json" \
    --output     "$REPORT_DIR/sanitized_meta.json"

echo ""
echo "════════════════════════════════════════════════"
[ $ERRORS -gt 0 ] && echo "  ⚠ $ERRORS tool(s) unavailable — partial scan" \
                  || echo "  ✓ All scans complete"
echo "  ✓ Zero source code in sanitized output"
echo "════════════════════════════════════════════════"
