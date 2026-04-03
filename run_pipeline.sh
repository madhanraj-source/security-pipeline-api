#!/bin/bash
# ============================================================
# Modern AI Security Pipeline v2
# Semgrep + Trufflehog + Bearer + Trivy + FossID → Gauss AI
# Usage: bash run_pipeline.sh /path/to/your/project
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TARGET="${1:-.}"
REPORT_DIR="$SCRIPT_DIR/reports"

if [ ! -f .env ]; then
    echo "⚠ No .env file. Run: cp .env.example .env"
    exit 1
fi
sed -i 's/\r//' .env
source .env

PORT="${DASHBOARD_PORT:-8502}"
START=$(date +%s)

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║        Modern AI Security Pipeline v2              ║"
echo "║  Semgrep + Trufflehog + Bearer + Trivy + FossID    ║"
echo "║                  → Samsung Gauss AI                ║"
echo "╚══════════════════════════════════════════════════════╝"
echo "  Target : $TARGET"
echo ""

mkdir -p "$REPORT_DIR"

echo "▶ Stage 1/3 — Local Security Scans (5 tools)"
bash "$SCRIPT_DIR/scripts/scanner.sh" "$TARGET" "$REPORT_DIR"

echo ""
echo "▶ Stage 2/3 — Samsung Gauss AI Analysis"
python3 "$SCRIPT_DIR/scripts/gauss_analyzer.py" \
    --input  "$REPORT_DIR/sanitized_meta.json" \
    --output "$REPORT_DIR/ai_report.json" \
    --cache  "$REPORT_DIR/.ai_cache.json"

echo ""
echo "▶ Stage 3/3 — Launching Dashboard (port $PORT)"
pkill -f "streamlit run" 2>/dev/null || true
sleep 1

nohup streamlit run "$SCRIPT_DIR/dashboard/dashboard.py" \
    --server.port="$PORT" \
    --server.headless=true \
    --server.address=0.0.0.0 \
    -- --report "$REPORT_DIR/ai_report.json" \
    > "$REPORT_DIR/dashboard.log" 2>&1 &

sleep 3

END=$(date +%s)
ELAPSED=$((END - START))

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║                Pipeline Complete ✓                 ║"
echo "╚══════════════════════════════════════════════════════╝"
python3 -c "
import json
try:
    r = json.load(open('$REPORT_DIR/ai_report.json'))
    s = r.get('executive_summary', {})
    print(f\"  Risk     : {s.get('overall_risk','UNKNOWN')}\")
    print(f\"  Issues   : {s.get('total_issues',0)} total ({s.get('critical_count',0)} critical, {s.get('high_count',0)} high)\")
    stmt = s.get('key_risk_statement','')
    if stmt: print(f\"  Summary  : {stmt[:75]}\")
except: pass
" 2>/dev/null
echo "  Duration : ${ELAPSED}s"
echo "  Dashboard: http://localhost:${PORT}"
echo ""
