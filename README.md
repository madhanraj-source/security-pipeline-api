# Modern AI Security Pipeline
## Semgrep + Trufflehog + Bearer CLI → Samsung Gauss API → Dashboard

---

## Why These Tools?

| Tool | Used By | What it finds |
|---|---|---|
| **Semgrep** | Dropbox, Slack, Netflix, Figma | SAST — SQLi, XSS, OWASP Top 10, logic flaws |
| **Trufflehog** | GitHub, GitLab | Secrets — API keys, tokens, passwords, private keys |
| **Bearer CLI** | Security-focused companies | API security — PII exposure, auth issues, data leakage |

---

## Quick Start

```bash
# 1. Install tools (run once)
bash setup.sh
source ~/.bashrc

# 2. Configure
cp .env.example .env
nano .env   # fill in Gauss API keys

# 3. Run
bash run_pipeline.sh /path/to/your/project

# 4. Dashboard → http://localhost:8501
```

---

## Pipeline Flow

```
Your Code (100% local — never sent to AI)
    │
    ├─ Semgrep      → SAST, OWASP Top 10, 3000+ security rules
    ├─ Trufflehog   → Secrets, credentials, API keys
    └─ Bearer CLI   → API security, data privacy, PII
         │
         ▼
    strip_metadata.py → strips ALL source code
         │  (only: file, line, rule, severity, CWE, description)
         ▼
    gauss_analyzer.py → Samsung Gauss API (batches of 3)
         │
         ▼
    dashboard.py → Streamlit UI with 3 separate sections:
                   🔎 Semgrep | 🔑 Trufflehog | 🛡️ Bearer CLI
```

---

## Language Support

| Language | Semgrep | Trufflehog | Bearer CLI |
|---|---|---|---|
| Python | ✅ Full | ✅ | ✅ Full |
| JavaScript/TypeScript | ✅ Full | ✅ | ✅ Full |
| Java | ✅ Full | ✅ | ✅ Full |
| Go | ✅ Full | ✅ | ✅ Full |
| Ruby | ✅ Full | ✅ | ✅ Full |
| PHP | ✅ Full | ✅ | ✅ Full |
| C/C++ | ✅ Full | ✅ | ⚠️ Limited |
| C# | ✅ Full | ✅ | ❌ |
| Rust | ✅ Full | ✅ | ❌ |

---

## .env Values

```bash
GAUSS_API_URL=https://YOUR_SAMSUNG_DOMAIN
GAUSS_CLIENT_KEY=your-client-key
GAUSS_PASS_KEY=Bearer your-token
GAUSS_MODEL_ID=your-model-id
GAUSS_EMAIL=your-email@samsung.com
DASHBOARD_PORT=8501
```

---

## Project Structure

```
modern-pipeline/
├── .env.example
├── setup.sh              ← installs Semgrep, Trufflehog, Bearer CLI
├── run_pipeline.sh       ← single command entry point
├── scripts/
│   ├── scanner.sh        ← runs all 3 scanners
│   ├── strip_metadata.py ← removes source code
│   └── gauss_analyzer.py ← Gauss API with batching + caching
├── dashboard/
│   └── dashboard.py      ← 3 separate tool sections
└── reports/
    ├── semgrep_findings.json
    ├── trufflehog_findings.json
    ├── bearer_findings.json
    ├── sanitized_meta.json
    ├── ai_report.json
    └── .ai_cache.json
```
