#!/bin/bash
# ============================================================
# AI Security Pipeline — Setup (No sudo required)
# Installs: Gitleaks, SonarScanner, Python deps
# ============================================================

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

echo "════════════════════════════════════════════════════"
echo "  AI Security Pipeline — Setup"
echo "  Tools: Gitleaks + SonarScanner"
echo "════════════════════════════════════════════════════"

ok()   { echo "  ✅ $1"; }
warn() { echo "  ⚠  $1"; }
info() { echo "  →  $1"; }

download() {
    local url="$1" out="$2"
    if command -v curl &>/dev/null; then
        curl -L --progress-bar "$url" -o "$out"
    else
        wget -q --show-progress "$url" -O "$out"
    fi
}

# ── 1. System deps ────────────────────────────────────────────
echo ""
echo "[0/3] Checking system dependencies..."
if ! command -v python3 &>/dev/null; then
    warn "python3 not found — ask admin to install python3"
    exit 1
fi
ok "Python3: $(python3 --version)"

# ── 2. Python deps ────────────────────────────────────────────
echo ""
echo "[1/3] Python dependencies..."
pip3 install requests streamlit --user --quiet 2>&1 | tail -2
ok "requests + streamlit installed"

# ── 3. Gitleaks ───────────────────────────────────────────────
echo ""
echo "[2/3] Gitleaks..."

if command -v gitleaks &>/dev/null; then
    ok "Already installed: $(gitleaks version 2>/dev/null)"
else
    GL_VERSION="8.18.4"
    GL_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GL_VERSION}/gitleaks_${GL_VERSION}_linux_x64.tar.gz"
    info "Downloading Gitleaks v${GL_VERSION}..."
    if download "$GL_URL" /tmp/gitleaks.tar.gz; then
        tar -xzf /tmp/gitleaks.tar.gz -C "$INSTALL_DIR" gitleaks
        chmod +x "$INSTALL_DIR/gitleaks"
        rm -f /tmp/gitleaks.tar.gz
        ok "Gitleaks installed"
    else
        warn "Gitleaks download failed."
        echo "  Manual: https://github.com/gitleaks/gitleaks/releases"
    fi
fi

# ── 4. SonarScanner ───────────────────────────────────────────
echo ""
echo "[3/3] SonarScanner CLI..."

if command -v sonar-scanner &>/dev/null; then
    ok "Already installed"
else
    SONAR_VERSION="6.2.1.4610"
    SONAR_URL="https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_VERSION}-linux-x64.zip"
    info "Downloading SonarScanner v${SONAR_VERSION}..."
    if download "$SONAR_URL" /tmp/sonar.zip; then
        if command -v unzip &>/dev/null; then
            unzip -q /tmp/sonar.zip -d "$HOME/.local/"
        else
            python3 -c "import zipfile; zipfile.ZipFile(\"/tmp/sonar.zip\").extractall(\"$HOME/.local/\")"
        fi
        SONAR_DIR="$HOME/.local/sonar-scanner-${SONAR_VERSION}-linux-x64"
        ln -sf "$SONAR_DIR/bin/sonar-scanner" "$INSTALL_DIR/sonar-scanner"
        rm -f /tmp/sonar.zip
        ok "SonarScanner installed"
    else
        warn "SonarScanner download failed."
        echo "  Manual: https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/scanners/sonarscanner/"
    fi
fi

if ! command -v java &>/dev/null; then
    warn "Java not found — SonarScanner requires Java 17+"
    echo "  Ask admin: sudo apt-get install openjdk-17-jre-headless"
fi

# ── PATH ──────────────────────────────────────────────────────
echo ""
grep -qxF "export PATH=\"\$HOME/.local/bin:\$PATH\"" ~/.bashrc || \
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
export PATH="$HOME/.local/bin:$PATH"

# ── Verify ────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════"
echo "  Verification"
echo "════════════════════════════════════════════════════"
command -v gitleaks &>/dev/null && echo "  ✅ Gitleaks" || echo "  ❌ Gitleaks"
command -v sonar-scanner &>/dev/null && echo "  ✅ SonarScanner" || echo "  ❌ SonarScanner"
command -v python3 &>/dev/null && echo "  ✅ Python3" || echo "  ❌ Python3"
command -v java &>/dev/null && echo "  ✅ Java" || echo "  ❌ Java (needed for SonarScanner)"

echo ""
echo "════════════════════════════════════════════════════"
echo "  Next Steps"
echo "════════════════════════════════════════════════════"
echo "  1. source ~/.bashrc"
echo "  2. cp .env.example .env"
echo "     Fill in Gauss API keys + SonarQube token"
echo "  3. bash run_pipeline.sh /path/to/your/project"
echo "════════════════════════════════════════════════════"
