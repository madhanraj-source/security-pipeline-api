# AI Security Pipeline — Office
## CodeQL + Gitleaks + SonarQube → Samsung Gauss API → Streamlit Dashboard

---

## Quick Start

```bash
# 1. Install all tools (run once)
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

## Project Structure

```
office-pipeline/
├── .env.example              ← credentials template
├── .env                      ← your credentials (never commit this)
├── setup.sh                  ← install all tools (run once)
├── run_pipeline.sh           ← single command to run everything
├── scripts/
│   ├── scanner.sh            ← CodeQL + Gitleaks + SonarQube
│   ├── strip_metadata.py     ← strips ALL source code from findings
│   └── gauss_analyzer.py     ← Samsung Gauss API with strict JSON schema
├── dashboard/
│   └── dashboard.py          ← Streamlit UI
└── reports/                  ← auto-created on first run
    ├── codeql_sarif.json
    ├── codeql_findings.json
    ├── gitleaks_findings.json
    ├── sonar_findings.json
    ├── sonar_output.log
    ├── sanitized_meta.json   ← what gets sent to Gauss (no source code)
    ├── ai_report.json        ← final AI report
    └── .ai_cache.json
```

---

## .env Values

| Variable | Description |
|---|---|
| `GAUSS_API_URL` | Base URL e.g. `https://your-domain.samsung.com` |
| `GAUSS_CLIENT_KEY` | `x-generative-ai-client` header value |
| `GAUSS_PASS_KEY` | `x-openapi-token` header value |
| `GAUSS_MODEL_ID` | Your model ID string |
| `GAUSS_EMAIL` | `x-generative-ai-user-email` header value |
| `SONAR_HOST_URL` | `http://localhost:9000` |
| `SONAR_TOKEN` | SonarQube user token (not project token) |
| `SONAR_PROJECT_KEY` | Must match exactly in SonarQube UI |
| `SONAR_USER` | SonarQube username (for hotspots API) |
| `SONAR_PASSWORD` | SonarQube password (for hotspots API) |

---

## Run Options

```bash
# Auto-detect language (default)
bash run_pipeline.sh /path/to/project

# Specify language
bash run_pipeline.sh /path/to/project python
bash run_pipeline.sh /path/to/project java

# Force fresh AI report (skip cache)
python3 scripts/gauss_analyzer.py --no-cache

# Dashboard only (reuse existing report)
streamlit run dashboard/dashboard.py --server.port 8501
```

---

## Gauss API Request Format

```python
headers = {
    "x-generative-ai-client":       CLIENT_KEY,
    "x-openapi-token":               PASS_KEY,
    "x-generative-ai-user-email":    EMAIL,
}

body = {
    "modelIds":     [MODEL_ID],
    "contents":     ["your message string"],
    "llmConfig": {
        "max_new_tokens": 8192,
        "temperature":    0.1,
        "top_k":          14,
        "top_p":          0.94,
        "repetition_penalty": 1.04,
        "seed": None
    },
    "isStream":     False,
    "systemPrompt": "..."
}

# Response: response_data.get('content')
```
