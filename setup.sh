#!/bin/bash
# ============================================================
# Modern AI Security Pipeline — Setup
# Installs: Semgrep + Trufflehog + Bearer CLI + Python deps
# No sudo required — installs to ~/.local/
# ============================================================

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

echo "════════════════════════════════════════════════════"
echo "  Modern AI Security Pipeline — Setup"
echo "  Tools: Semgrep + Trufflehog + Bearer CLI"
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

# ── Check prerequisites ───────────────────────────────────────
echo ""
echo "[0/4] Checking prerequisites..."

if ! command -v python3 &>/dev/null; then
    warn "python3 not found — ask admin to install python3"
    exit 1
fi
ok "Python3: $(python3 --version)"

# ── 1. Python deps ────────────────────────────────────────────
echo ""
echo "[1/4] Python dependencies..."
pip3 install semgrep requests streamlit --user --quiet 2>&1 | tail -3
ok "semgrep, requests, streamlit installed"

# ── 2. Trufflehog ─────────────────────────────────────────────
echo ""
echo "[2/4] Trufflehog — Advanced Secrets Detection..."

if command -v trufflehog &>/dev/null; then
    ok "Already installed: $(trufflehog --version 2>/dev/null | head -1)"
else
    TH_VERSION="3.63.7"
    TH_URL="https://github.com/trufflesecurity/trufflehog/releases/download/v${TH_VERSION}/trufflehog_${TH_VERSION}_linux_amd64.tar.gz"
    info "Downloading Trufflehog v${TH_VERSION}..."
    if download "$TH_URL" /tmp/trufflehog.tar.gz; then
        tar -xzf /tmp/trufflehog.tar.gz -C "$INSTALL_DIR" trufflehog
        chmod +x "$INSTALL_DIR/trufflehog"
        rm -f /tmp/trufflehog.tar.gz
        ok "Trufflehog installed"
    else
        warn "Trufflehog download failed."
        echo "  Manual: https://github.com/trufflesecurity/trufflehog/releases"
    fi
fi

# ── 3. Bearer CLI ─────────────────────────────────────────────
echo ""
echo "[3/4] Bearer CLI — API Security & Data Privacy..."

if command -v bearer &>/dev/null; then
    ok "Already installed: $(bearer version 2>/dev/null | head -1)"
else
    BEARER_VERSION="1.45.0"
    BEARER_URL="https://github.com/Bearer/bearer/releases/download/v${BEARER_VERSION}/bearer_${BEARER_VERSION}_linux_amd64.tar.gz"
    info "Downloading Bearer CLI v${BEARER_VERSION}..."
    if download "$BEARER_URL" /tmp/bearer.tar.gz; then
        tar -xzf /tmp/bearer.tar.gz -C "$INSTALL_DIR" bearer
        chmod +x "$INSTALL_DIR/bearer"
        rm -f /tmp/bearer.tar.gz
        ok "Bearer CLI installed"
    else
        warn "Bearer download failed."
        echo "  Manual: https://github.com/Bearer/bearer/releases"
    fi
fi

# ── 4. Semgrep verify ─────────────────────────────────────────
echo ""
echo "[4/4] Verifying Semgrep..."
if command -v semgrep &>/dev/null || python3 -m semgrep --version &>/dev/null 2>&1; then
    ok "Semgrep: $(semgrep --version 2>/dev/null || python3 -m semgrep --version 2>/dev/null)"
else
    warn "Semgrep not found in PATH — trying pip install..."
    pip3 install semgrep --user -q
    ok "Semgrep installed via pip"
fi

# ── PATH ──────────────────────────────────────────────────────
echo ""
grep -qxF "export PATH=\"\$HOME/.local/bin:\$PATH\"" ~/.bashrc || \
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
export PATH="$HOME/.local/bin:$PATH"

# ── Verify all ────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════"
echo "  Verification"
echo "════════════════════════════════════════════════════"

verify() {
    local name="$1" cmd="$2"
    if eval "$cmd" &>/dev/null; then
        echo "  ✅ $name"
    else
        echo "  ❌ $name — not found"
    fi
}

verify "Semgrep"     "semgrep --version"
verify "Trufflehog"  "trufflehog --version"
verify "Bearer CLI"  "bearer version"
verify "Python3"     "python3 --version"
verify "Streamlit"   "streamlit --version"

echo ""
echo "════════════════════════════════════════════════════"
echo "  Next Steps"
echo "════════════════════════════════════════════════════"
echo "  1. source ~/.bashrc"
echo "  2. cp .env.example .env"
echo "     Fill in your Gauss API keys"
echo "  3. bash run_pipeline.sh /path/to/your/project"
echo "════════════════════════════════════════════════════"
