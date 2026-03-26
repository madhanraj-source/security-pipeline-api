# AI Security Pipeline — Office
## Gitleaks + SonarQube → Samsung Gauss API → Streamlit Dashboard

---

## Quick Start

```bash
# 1. Install tools (run once)
bash setup.sh
source ~/.bashrc

# 2. Configure credentials
cp .env.example .env
nano .env

# 3. Run
bash run_pipeline.sh /path/to/your/project

# 4. Open dashboard → http://localhost:8501
```

---

## Pipeline Flow

```
Your Code (local only — never sent to AI)
    │
    ├─ Gitleaks    → secrets, API keys, hardcoded credentials
    └─ SonarQube   → bugs, vulnerabilities + security hotspots
         │
         ▼
    strip_metadata.py → strips ALL source code from findings
         │  (only: file, line, rule_id, severity, CWE)
         ▼
    gauss_analyzer.py → Samsung Gauss API (batches of 3)
         │              temperature=0.1, SHA256 caching
         ▼
    ai_report.json    → structured report with fixes
         │
         ▼
    dashboard.py      → Streamlit UI at localhost:8501
                        Separated: Gitleaks | SonarQube sections
```

---

## Project Structure

```
security-pipeline/
├── .env.example              ← credentials template
├── .env                      ← your credentials (never commit)
├── setup.sh                  ← install tools (run once)
├── run_pipeline.sh           ← single command entry point
├── scripts/
│   ├── scanner.sh            ← Gitleaks + SonarQube
│   ├── strip_metadata.py     ← removes all source code
│   └── gauss_analyzer.py     ← Gauss API, batching, caching
├── dashboard/
│   └── dashboard.py          ← Streamlit UI
└── reports/                  ← auto-created on first run
    ├── gitleaks_findings.json
    ├── sonar_findings.json
    ├── sonar_output.log
    ├── sanitized_meta.json   ← what gets sent to Gauss (no code)
    ├── ai_report.json        ← final AI report
    └── .ai_cache.json
```

---

## .env Values

| Variable | Description |
|---|---|
| `GAUSS_API_URL` | Base URL e.g. `https://your-domain.samsung.com` |
| `GAUSS_CLIENT_KEY` | `x-generative-ai-client` header value |
| `GAUSS_PASS_KEY` | `Bearer your-token` |
| `GAUSS_MODEL_ID` | Your model ID string |
| `GAUSS_EMAIL` | `x-generative-ai-user-email` header value |
| `SONAR_HOST_URL` | `http://localhost:9000` |
| `SONAR_TOKEN` | SonarQube user token |
| `SONAR_PROJECT_KEY` | Must match exactly in SonarQube UI |
| `SONAR_USER` | SonarQube username (for hotspots API) |
| `SONAR_PASSWORD` | SonarQube password (for hotspots API) |
| `DASHBOARD_PORT` | Default `8501` |

---

## Dashboard Sections

```
📊 Executive Summary    → overall risk, counts
⚡ Fix These First      → top priority findings
📋 Compliance Flags     → OWASP + CWE references
🔑 Gitleaks Findings    → secrets & credentials
🔍 SonarQube Findings   → code security & hotspots
💡 Recommendations      → actionable next steps
```

---

## Run Options

```bash
# Run full pipeline
bash run_pipeline.sh /path/to/project

# Force fresh AI report (skip cache)
python3 scripts/gauss_analyzer.py --no-cache

# Dashboard only (reuse existing report)
streamlit run dashboard/dashboard.py --server.port 8501
```
