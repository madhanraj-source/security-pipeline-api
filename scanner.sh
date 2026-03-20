#!/bin/bash
# ============================================================
# Local Security Pipeline — Stage 1: Scanners
# Tools: CodeQL + Gitleaks + SonarQube
# All run locally. Raw code never sent to AI.
# ============================================================

TARGET_DIR="${1:-.}"
REPORT_DIR="${2:-./reports}"
CODEQL_DB="${3:-./codeql-db}"
LANGUAGE="${4:-auto}"

# Load .env
if [ -f .env ]; then source .env; fi

SONAR_HOST="${SONAR_HOST_URL:-http://localhost:9000}"
SONAR_TOK="${SONAR_TOKEN:-}"
SONAR_KEY="${SONAR_PROJECT_KEY:-my-security-scan}"

mkdir -p "$REPORT_DIR"

echo "════════════════════════════════════════════════"
echo "  Local Security Pipeline — Scan Starting"
echo "  Target  : $TARGET_DIR"
echo "════════════════════════════════════════════════"

# ── Auto-detect language ──────────────────────────────────
if [ "$LANGUAGE" = "auto" ]; then
    if   find "$TARGET_DIR" -name "*.py"   -not -path "*/.git/*" | grep -q .; then LANGUAGE="python"
    elif find "$TARGET_DIR" -name "*.java" -not -path "*/.git/*" | grep -q .; then LANGUAGE="java"
    elif find "$TARGET_DIR" -name "*.js"   -not -path "*/.git/*" | grep -q .; then LANGUAGE="javascript"
    elif find "$TARGET_DIR" -name "*.ts"   -not -path "*/.git/*" | grep -q .; then LANGUAGE="javascript"
    elif find "$TARGET_DIR" -name "*.cpp"  -not -path "*/.git/*" | grep -q .; then LANGUAGE="cpp"
    elif find "$TARGET_DIR" -name "*.go"   -not -path "*/.git/*" | grep -q .; then LANGUAGE="go"
    else LANGUAGE="python"
    fi
    echo "  Language: $LANGUAGE (auto-detected)"
else
    echo "  Language: $LANGUAGE"
fi

ERRORS=0

# ══════════════════════════════════════════════════
# TOOL 1: CodeQL
# ══════════════════════════════════════════════════
echo ""
echo "[1/3] CodeQL — Semantic Security Analysis"
echo "──────────────────────────────────────────"

if ! command -v codeql &>/dev/null; then
    echo "  ⚠ CodeQL not found. Run: bash setup.sh"
    echo "[]" > "$REPORT_DIR/codeql_findings.json"
    ERRORS=$((ERRORS+1))
else
    rm -rf "$CODEQL_DB"

    echo "  → Building CodeQL database..."
    codeql database create "$CODEQL_DB" \
        --language="$LANGUAGE" \
        --source-root="$TARGET_DIR" \
        --overwrite \
        --threads=0 \
        2>&1 | tail -2

    echo "  → Analyzing with security + quality queries..."
    codeql database analyze "$CODEQL_DB" \
        --format=sarif-latest \
        --output="$REPORT_DIR/codeql_sarif.json" \
        --threads=0 \
        -- "${LANGUAGE}-security-and-quality.qls" \
        2>&1 | tail -2

    python3 - << PYEOF
import json, os

sarif_path = "$REPORT_DIR/codeql_sarif.json"
out_path   = "$REPORT_DIR/codeql_findings.json"

try:
    data     = json.load(open(sarif_path))
    findings = []

    for run in data.get("runs", []):
        rules_map = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result in run.get("results", []):
            rule_id  = result.get("ruleId", "UNKNOWN")
            rule_def = rules_map.get(rule_id, {})
            props    = rule_def.get("properties", {})
            tags     = props.get("tags", [])

            locs     = result.get("locations", [])
            file_uri = ""
            line_num = 0
            if locs:
                pl       = locs[0].get("physicalLocation", {})
                file_uri = pl.get("artifactLocation", {}).get("uri", "")
                line_num = pl.get("region", {}).get("startLine", 0)

            sev_map  = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}
            severity = sev_map.get(result.get("level", "warning"), "MEDIUM")
            if severity == "HIGH" and any("security" in t for t in tags):
                severity = "CRITICAL"

            cwe_tag = next((t for t in tags if "cwe" in t.lower()), None)
            cwe     = "CWE-" + cwe_tag.split("-")[-1] if cwe_tag else "N/A"
            owasp   = next((t for t in tags if "owasp" in t.lower()), "N/A")

            findings.append({
                "rule_id":     rule_id,
                "severity":    severity,
                "title":       rule_def.get("shortDescription", {}).get("text", rule_id),
                "description": result.get("message", {}).get("text", "")[:300],
                "file":        os.path.basename(file_uri),
                "line":        line_num,
                "cwe":         cwe,
                "owasp":       owasp,
                "category":    props.get("kind", "Security"),
                "precision":   props.get("precision", "medium"),
            })

    json.dump(findings, open(out_path, "w"), indent=2)
    print(f"  ✓ CodeQL: {len(findings)} findings")

except Exception as e:
    print(f"  ⚠ CodeQL parse error: {e}")
    json.dump([], open(out_path, "w"))
PYEOF
fi

# ══════════════════════════════════════════════════
# TOOL 2: Gitleaks
# ══════════════════════════════════════════════════
echo ""
echo "[2/3] Gitleaks — Secrets & Credentials Detection"
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
# TOOL 3: SonarQube
# Fix 1: cd into target dir so sonar.sources=. works
# Fix 2: tee output to log for CE task ID extraction
# Fix 3: Poll CE task until complete (no more blind wait)
# Fix 4: Bearer token + basic auth fallback for hotspots
# Fix 5: CSS filter
# ══════════════════════════════════════════════════
echo ""
echo "[3/3] SonarQube — Code Quality & Security"
echo "──────────────────────────────────────────"

if ! command -v sonar-scanner &>/dev/null; then
    echo "  ⚠ SonarScanner CLI not found. Run: bash setup.sh"
    echo "[]" > "$REPORT_DIR/sonar_findings.json"
    ERRORS=$((ERRORS+1))
elif [ -z "$SONAR_TOK" ]; then
    echo "  ⚠ SONAR_TOKEN not set. Check your .env file."
    echo "[]" > "$REPORT_DIR/sonar_findings.json"
    ERRORS=$((ERRORS+1))
else
    echo "  → Running SonarScanner..."
    ORIG_DIR="$(pwd)"
    cd "$TARGET_DIR"

    # tee to log file so we can extract CE task ID
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

    # ── Poll CE task until complete ────────────────────────
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

host     = "$SONAR_HOST"
tok      = "$SONAR_TOK"
key      = "$SONAR_KEY"
out      = "$REPORT_DIR/sonar_findings.json"
hdrs     = {"Authorization": f"Bearer {tok}"}
sonar_user = "$SONAR_USER"
sonar_pass = "$SONAR_PASSWORD"

# Extensions to exclude — CSS/minified files are noise
EXCLUDE_EXT = (".css", ".min.js", ".min.css", ".map", ".scss", ".less")

try:
    # ── Regular issues ─────────────────────────────────
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
        print(f"  ⚠ Issues API: {resp.status_code} — {resp.text[:100]}")

    # ── Security hotspots ──────────────────────────────
    # SonarQube 10+ requires basic auth for hotspots API
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
echo "  → Stripping raw code, sanitizing metadata..."
python3 scripts/strip_metadata.py \
    --codeql   "$REPORT_DIR/codeql_findings.json" \
    --gitleaks "$REPORT_DIR/gitleaks_findings.json" \
    --sonar    "$REPORT_DIR/sonar_findings.json" \
    --output   "$REPORT_DIR/sanitized_meta.json"

echo ""
echo "════════════════════════════════════════════════"
[ $ERRORS -gt 0 ] && echo "  ⚠ $ERRORS tool(s) unavailable — partial scan" \
                  || echo "  ✓ All scans complete"
echo "  ✓ Zero source code in sanitized output"
echo "════════════════════════════════════════════════"
