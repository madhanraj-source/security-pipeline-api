#!/bin/bash
# ============================================================
# AI Security Pipeline — Stage 1: Scanners
# Tools: Gitleaks + SonarQube
# Raw code never sent to AI.
# ============================================================

TARGET_DIR="${1:-.}"
REPORT_DIR="${2:-./reports}"

# Load .env
if [ -f .env ]; then
    sed -i 's/\r//' .env
    source .env
fi

SONAR_HOST="${SONAR_HOST_URL:-http://localhost:9000}"
SONAR_TOK="${SONAR_TOKEN:-}"
SONAR_KEY="${SONAR_PROJECT_KEY:-my-security-scan}"

mkdir -p "$REPORT_DIR"

echo "════════════════════════════════════════════════"
echo "  AI Security Pipeline — Scan Starting"
echo "  Target  : $TARGET_DIR"
echo "════════════════════════════════════════════════"

ERRORS=0

# ══════════════════════════════════════════════════
# TOOL 1: Gitleaks
# ══════════════════════════════════════════════════
echo ""
echo "[1/2] Gitleaks — Secrets & Credentials Detection"
echo "─────────────────────────────────────────────────"

if ! command -v gitleaks &>/dev/null; then
    echo "  ⚠ Gitleaks not found. Run: bash setup.sh"
    echo "[]" > "$REPORT_DIR/gitleaks_findings.json"
    ERRORS=$((ERRORS+1))
else
    gitleaks detect \
        --source "$TARGET_DIR" \
        --report-format json \
        --report-path "$REPORT_DIR/gitleaks_findings.json" \
        --redact \
        --no-git \
        --exit-code 0 2>/dev/null || true

    COUNT=$(python3 -c "
import json
try:
    d = json.load(open('$REPORT_DIR/gitleaks_findings.json'))
    print(len(d) if isinstance(d, list) else 0)
except: print(0)")
    echo "  ✓ Gitleaks: $COUNT secrets detected"
fi

# ══════════════════════════════════════════════════
# TOOL 2: SonarQube
# ══════════════════════════════════════════════════
echo ""
echo "[2/2] SonarQube — Code Quality & Security"
echo "──────────────────────────────────────────"

if ! command -v sonar-scanner &>/dev/null; then
    echo "  ⚠ SonarScanner not found. Run: bash setup.sh"
    echo "[]" > "$REPORT_DIR/sonar_findings.json"
    ERRORS=$((ERRORS+1))
elif [ -z "$SONAR_TOK" ]; then
    echo "  ⚠ SONAR_TOKEN not set in .env"
    echo "[]" > "$REPORT_DIR/sonar_findings.json"
    ERRORS=$((ERRORS+1))
else
    echo "  → Running SonarScanner..."
    ORIG_DIR="$(pwd)"
    cd "$TARGET_DIR"

    sonar-scanner \
        -Dsonar.projectKey="$SONAR_KEY" \
        -Dsonar.sources="." \
        -Dsonar.projectBaseDir="." \
        -Dsonar.host.url="$SONAR_HOST" \
        -Dsonar.token="$SONAR_TOK" \
        -Dsonar.scm.disabled=true \
        2>&1 | tee "$ORIG_DIR/$REPORT_DIR/sonar_output.log" \
              | grep -E "(INFO|WARN|ERROR|EXECUTION)" | tail -5

    cd "$ORIG_DIR"

    # Poll CE task until complete
    TASK_ID=$(grep -o 'ce/task?id=[a-z0-9-]*' "$REPORT_DIR/sonar_output.log" 2>/dev/null \
              | cut -d= -f2 | tail -1)

    if [ -n "$TASK_ID" ]; then
        echo "  → Polling CE task [$TASK_ID]..."
        for i in $(seq 1 24); do
            STATUS=$(curl -s -H "Authorization: Bearer $SONAR_TOK" \
                "$SONAR_HOST/api/ce/task?id=$TASK_ID" \
                | python3 -c "
import sys, json
try:
    print(json.load(sys.stdin).get('task',{}).get('status','UNKNOWN'))
except:
    print('UNKNOWN')
" 2>/dev/null)
            echo "  → Status: $STATUS ($i/24)..."
            if [ "$STATUS" = "SUCCESS" ]; then
                echo "  ✓ SonarQube analysis complete"
                break
            elif [ "$STATUS" = "FAILED" ] || [ "$STATUS" = "CANCELLED" ]; then
                echo "  ⚠ SonarQube CE task $STATUS"
                break
            fi
            sleep 5
        done
    else
        echo "  → Could not get task ID — waiting 15s..."
        sleep 15
    fi

    echo "  → Fetching issues + security hotspots..."
    python3 - << PYEOF
import json, requests

host      = "$SONAR_HOST"
tok       = "$SONAR_TOK"
key       = "$SONAR_KEY"
out       = "$REPORT_DIR/sonar_findings.json"
hdrs      = {"Authorization": f"Bearer {tok}"}
sonar_user = "$SONAR_USER"
sonar_pass = "$SONAR_PASSWORD"

EXCLUDE_EXT = (".css", ".min.js", ".min.css", ".map", ".scss", ".less")

try:
    # Regular issues
    resp = requests.get(
        f"{host}/api/issues/search",
        params={
            "componentKeys": key,
            "types":         "VULNERABILITY,BUG",
            "statuses":      "OPEN,CONFIRMED,REOPENED",
            "ps":            500,
        },
        headers=hdrs,
        timeout=30
    )
    issues = []
    if resp.status_code == 200:
        raw = resp.json().get("issues", [])
        issues = [
            i for i in raw
            if not any(i.get("component","").endswith(ext) for ext in EXCLUDE_EXT)
        ]
        skipped = len(raw) - len(issues)
        if skipped:
            print(f"  → Filtered {skipped} CSS/minified issues")
    else:
        print(f"  ⚠ Issues API: {resp.status_code}")

    # Security hotspots
    hotspots = []
    try:
        auth = (sonar_user, sonar_pass) if sonar_pass else None
        hr = requests.get(
            f"{host}/api/hotspots/search",
            params={"projectKey": key, "ps": 500},
            headers=hdrs if not auth else {},
            auth=auth,
            timeout=30
        )
        if hr.status_code == 200:
            for h in hr.json().get("hotspots", []):
                component = h.get("component", "")
                file_name = component.split(":")[-1] if ":" in component else component
                hotspots.append({
                    "rule":      h.get("ruleKey", "HOTSPOT"),
                    "message":   h.get("message", "Security hotspot requires review"),
                    "component": file_name,
                    "line":      h.get("line", 0),
                    "severity":  "HIGH",
                    "type":      "SECURITY_HOTSPOT",
                    "status":    h.get("status", "TO_REVIEW"),
                })
            print(f"  ✓ Security hotspots: {len(hotspots)} found")
        else:
            print(f"  ⚠ Hotspots API: {hr.status_code}")
    except Exception as he:
        print(f"  ⚠ Hotspots skipped: {he}")

    all_issues = issues + hotspots
    json.dump(all_issues, open(out, "w"), indent=2)
    print(f"  ✓ SonarQube: {len(issues)} issues + {len(hotspots)} hotspots")

except Exception as e:
    print(f"  ⚠ SonarQube error: {e}")
    json.dump([], open(out, "w"))
PYEOF
fi

# ══════════════════════════════════════════════════
# METADATA STRIP
# ══════════════════════════════════════════════════
echo ""
echo "  → Sanitizing — stripping all source code..."
python3 scripts/strip_metadata.py \
    --gitleaks "$REPORT_DIR/gitleaks_findings.json" \
    --sonar    "$REPORT_DIR/sonar_findings.json" \
    --output   "$REPORT_DIR/sanitized_meta.json"

echo ""
echo "════════════════════════════════════════════════"
[ $ERRORS -gt 0 ] && echo "  ⚠ $ERRORS tool(s) unavailable — partial scan" \
                  || echo "  ✓ All scans complete"
echo "  ✓ Zero source code in sanitized output"
echo "════════════════════════════════════════════════"
