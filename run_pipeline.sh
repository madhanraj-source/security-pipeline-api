#!/bin/bash
# ============================================================
# Modern AI Security Pipeline
# Semgrep + Trufflehog + Bearer CLI → Gauss AI → Dashboard
# Usage: bash run_pipeline.sh /path/to/your/project
# ============================================================

TARGET="${1:-.}"
REPORT_DIR="./reports"

# Load .env
if [ ! -f .env ]; then
    echo "⚠ No .env file found."
    echo "  Run: cp .env.example .env  then fill in your keys."
    exit 1
fi
sed -i 's/\r//' .env
source .env

PORT="${DASHBOARD_PORT:-8501}"
START=$(date +%s)

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║       Modern AI Security Pipeline               ║"
echo "║  Semgrep + Trufflehog + Bearer → Gauss AI       ║"
echo "╚══════════════════════════════════════════════════╝"
echo "  Target : $TARGET"
echo ""

# ── Stage 1: Scan ─────────────────────────────────────────────
echo "▶ Stage 1/3 — Local Security Scans"
bash scripts/scanner.sh "$TARGET" "$REPORT_DIR"

# ── Stage 2: Gauss AI Analysis ────────────────────────────────
echo ""
echo "▶ Stage 2/3 — Samsung Gauss AI Analysis"
python3 scripts/gauss_analyzer.py \
    --input  "$REPORT_DIR/sanitized_meta.json" \
    --output "$REPORT_DIR/ai_report.json" \
    --cache  "$REPORT_DIR/.ai_cache.json"

# ── Stage 3: Dashboard ────────────────────────────────────────
echo ""
echo "▶ Stage 3/3 — Launching Dashboard"
pkill -f "streamlit run" 2>/dev/null || true
sleep 1

nohup streamlit run dashboard/dashboard.py \
    --server.port="$PORT" \
    --server.headless=true \
    --server.address=0.0.0.0 \
    -- --report "$(pwd)/$REPORT_DIR/ai_report.json" \
    > "$REPORT_DIR/dashboard.log" 2>&1 &

sleep 3

END=$(date +%s)
ELAPSED=$((END - START))

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║              Pipeline Complete ✓                ║"
echo "╚══════════════════════════════════════════════════╝"
python3 -c "
import json
try:
    r = json.load(open('$REPORT_DIR/ai_report.json'))
    s = r.get('executive_summary', {})
    print(f\"  Risk     : {s.get('overall_risk','UNKNOWN')}\")
    print(f\"  Issues   : {s.get('total_issues',0)} total  ({s.get('critical_count',0)} critical, {s.get('high_count',0)} high)\")
    stmt = s.get('key_risk_statement','')
    if stmt: print(f\"  Summary  : {stmt[:75]}\")
except Exception as e:
    print(f'  Could not read report: {e}')
" 2>/dev/null
echo "  Duration : ${ELAPSED}s"
echo "  Dashboard: http://localhost:${PORT}"
echo ""
