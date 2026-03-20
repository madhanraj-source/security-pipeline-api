#!/bin/bash
# ============================================================
# Local Security Pipeline — WSL2 Setup Script
# ============================================================

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

echo "════════════════════════════════════════════════════"
echo "  Local Security Pipeline — WSL2 Setup"
echo "════════════════════════════════════════════════════"

# ── Helper ────────────────────────────────────────────────
check_ok() { echo "  ✓ $1"; }
check_warn() { echo "  ⚠ $1"; }

# ── 1. System deps ────────────────────────────────────────
echo ""
echo "[0/4] Installing system dependencies..."
apt-get update -qq && apt-get install -y -qq wget curl unzip tar python3 python3-pip openjdk-17-jre-headless 2>/dev/null || true
check_ok "System deps ready"

# ── 2. CodeQL CLI ─────────────────────────────────────────
echo ""
echo "[1/4] CodeQL CLI..."

if command -v codeql &>/dev/null; then
    check_ok "Already installed: $(codeql --version 2>/dev/null | head -1)"
else
    # Correct tag format: codeql-bundle-v2.19.3 (NOT v2.19.3)
    CODEQL_VERSION="2.19.3"
    CODEQL_TAG="codeql-bundle-v${CODEQL_VERSION}"
    CODEQL_URL="https://github.com/github/codeql-action/releases/download/${CODEQL_TAG}/codeql-bundle-linux64.tar.gz"

    echo "  → Downloading CodeQL v${CODEQL_VERSION} (~1GB, may take a few minutes)..."
    echo "  → URL: $CODEQL_URL"

    # Use curl with progress bar, no set -e interference
    if curl -L --progress-bar "$CODEQL_URL" -o /tmp/codeql.tar.gz; then
        echo "  → Extracting..."
        mkdir -p "$HOME/.local/codeql-dist"
        tar -xzf /tmp/codeql.tar.gz -C "$HOME/.local/codeql-dist"
        ln -sf "$HOME/.local/codeql-dist/codeql/codeql" "$INSTALL_DIR/codeql"
        rm -f /tmp/codeql.tar.gz
        check_ok "CodeQL installed → $INSTALL_DIR/codeql"
    else
        check_warn "CodeQL download failed."
        echo ""
        echo "  Manual install steps:"
        echo "  1. Go to: https://github.com/github/codeql-action/releases"
        echo "  2. Download: codeql-bundle-linux64.tar.gz (under tag codeql-bundle-v2.19.3)"
        echo "  3. Run:"
        echo "     tar -xzf codeql-bundle-linux64.tar.gz -C ~/.local/codeql-dist"
        echo "     ln -sf ~/.local/codeql-dist/codeql/codeql ~/.local/bin/codeql"
    fi
fi

# ── 3. Gitleaks ───────────────────────────────────────────
echo ""
echo "[2/4] Gitleaks..."

if command -v gitleaks &>/dev/null; then
    check_ok "Already installed: $(gitleaks version 2>/dev/null)"
else
    GL_VERSION="8.18.4"
    GL_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GL_VERSION}/gitleaks_${GL_VERSION}_linux_x64.tar.gz"

    echo "  → Downloading Gitleaks v${GL_VERSION}..."
    if curl -L --progress-bar "$GL_URL" -o /tmp/gitleaks.tar.gz; then
        tar -xzf /tmp/gitleaks.tar.gz -C "$INSTALL_DIR" gitleaks
        chmod +x "$INSTALL_DIR/gitleaks"
        rm -f /tmp/gitleaks.tar.gz
        check_ok "Gitleaks installed"
    else
        check_warn "Gitleaks download failed."
        echo "  Manual: https://github.com/gitleaks/gitleaks/releases"
    fi
fi

# ── 4. SonarScanner CLI ───────────────────────────────────
echo ""
echo "[3/4] SonarScanner CLI..."

if command -v sonar-scanner &>/dev/null; then
    check_ok "Already installed"
else
    SONAR_VERSION="6.2.1.4610"
    SONAR_URL="https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_VERSION}-linux-x64.zip"

    echo "  → Downloading SonarScanner v${SONAR_VERSION}..."
    if curl -L --progress-bar "$SONAR_URL" -o /tmp/sonar.zip; then
        mkdir -p "$HOME/.local"
        unzip -q /tmp/sonar.zip -d "$HOME/.local/"
        SONAR_DIR="$HOME/.local/sonar-scanner-${SONAR_VERSION}-linux-x64"
        ln -sf "$SONAR_DIR/bin/sonar-scanner" "$INSTALL_DIR/sonar-scanner"
        rm -f /tmp/sonar.zip
        check_ok "SonarScanner installed"
    else
        check_warn "SonarScanner download failed."
        echo "  Manual: https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/scanners/sonarscanner/"
    fi
fi

# ── 5. Python deps ────────────────────────────────────────
echo ""
echo "[4/4] Python dependencies..."
pip install requests streamlit google-generativeai --break-system-packages -q
check_ok "requests, streamlit, google-generativeai installed"

# ── PATH ──────────────────────────────────────────────────
echo ""
echo "  → Adding $INSTALL_DIR to PATH..."
grep -qxF "export PATH=\"\$PATH:$INSTALL_DIR\"" ~/.bashrc || \
    echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> ~/.bashrc
export PATH="$PATH:$INSTALL_DIR"

# ── Verify ────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════"
echo "  Verification"
echo "════════════════════════════════════════════════════"

verify_tool() {
    local name="$1"
    local cmd="$2"
    if eval "$cmd" &>/dev/null; then
        echo "  ✅ $name — OK"
    else
        echo "  ❌ $name — not found (check warnings above)"
    fi
}

verify_tool "CodeQL"        "codeql --version"
verify_tool "Gitleaks"      "gitleaks version"
verify_tool "SonarScanner"  "sonar-scanner --version"
verify_tool "Python3"       "python3 --version"
verify_tool "Java"          "java -version"

echo ""
echo "════════════════════════════════════════════════════"
echo "  Next Steps"
echo "════════════════════════════════════════════════════"
echo "  1. source ~/.bashrc"
echo ""
echo "  2. cp .env.example .env"
echo "     → Add GEMINI_API_KEY  (https://aistudio.google.com/app/apikey)"
echo "     → Add SONAR_TOKEN     (SonarQube → Account → Security)"
echo "     → Set SONAR_PROJECT_KEY to your project key"
echo ""
echo "  3. bash run_pipeline.sh /path/to/your/project"
echo "════════════════════════════════════════════════════"
