#!/usr/bin/env python3
"""
Modern AI Security Pipeline v2 — Dashboard
Port: 8502
Severity-categorized findings from all 5 tools.
Each finding includes AI-generated fix with steps and code examples.
"""

import json
import sys
import re
from pathlib import Path

try:
    import streamlit as st
except ImportError:
    print("Install: pip install streamlit")
    sys.exit(1)

st.set_page_config(
    page_title="AI Security Report v2",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    [data-testid="stAppViewContainer"] { background: #0d1117; }
    [data-testid="stSidebar"]          { background: #161b22; }

    .sev-critical { background:#1a0008; border-left:4px solid #ff1744; padding:14px 18px; border-radius:8px; margin:6px 0; }
    .sev-high     { background:#1a0d00; border-left:4px solid #ff6d00; padding:14px 18px; border-radius:8px; margin:6px 0; }
    .sev-medium   { background:#1a1500; border-left:4px solid #ffd600; padding:14px 18px; border-radius:8px; margin:6px 0; }
    .sev-low      { background:#001a0d; border-left:4px solid #00e676; padding:14px 18px; border-radius:8px; margin:6px 0; }

    .step-item { background:#161b22; border-radius:6px; padding:8px 12px; margin:4px 0; font-size:13px; }
    .meta-pill { background:#21262d; color:#8b949e; padding:3px 9px; border-radius:10px; font-size:11px; margin:2px; display:inline-block; }
    .fix-box   { background:#0d2818; border:1px solid #1e4d2b; border-radius:6px; padding:12px; font-family:monospace; font-size:12.5px; white-space:pre-wrap; }

    .tool-semgrep    { background:#0d1b2e; border:1px solid #58a6ff33; border-radius:8px; padding:10px; }
    .tool-trufflehog { background:#1a0008; border:1px solid #ff174433; border-radius:8px; padding:10px; }
    .tool-bearer     { background:#130d1a; border:1px solid #b388ff33; border-radius:8px; padding:10px; }
    .tool-trivy      { background:#0d1a0d; border:1px solid #00e67633; border-radius:8px; padding:10px; }
    .tool-fossid     { background:#1a1500; border:1px solid #ffd60033; border-radius:8px; padding:10px; }
</style>
""", unsafe_allow_html=True)

SEV_COLOR = {"CRITICAL":"#ff1744","HIGH":"#ff6d00","MEDIUM":"#ffd600","LOW":"#00e676","UNKNOWN":"#8b949e"}
SEV_ICON  = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","UNKNOWN":"⚪"}
SEV_ORDER = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
STEP_NUMS = ["①","②","③","④","⑤","⑥","⑦","⑧","⑨","⑩"]

TOOLS = {
    "semgrep":    {"icon":"🔎","name":"Semgrep",    "color":"#58a6ff","desc":"SAST — Code security, OWASP Top 10"},
    "trufflehog": {"icon":"🔑","name":"Trufflehog", "color":"#ff1744","desc":"Secrets — API keys, tokens, credentials"},
    "bearer":     {"icon":"🛡️","name":"Bearer CLI",  "color":"#b388ff","desc":"API security — PII, data privacy, auth"},
    "trivy":      {"icon":"📦","name":"Trivy",       "color":"#00e676","desc":"Dependencies — CVEs, Dockerfile, IaC"},
    "fossid":     {"icon":"⚖️","name":"FossID",      "color":"#ffd600","desc":"License compliance — OSS, SBOM"},
}

# ── Load report ───────────────────────────────────────────────
REPORT_PATH = None
if len(sys.argv) > 1:
    try:
        i = sys.argv.index("--report")
        REPORT_PATH = sys.argv[i+1]
    except (ValueError, IndexError):
        pass

if not REPORT_PATH or not Path(REPORT_PATH).exists():
    script_dir = Path(__file__).parent.parent
    for c in [script_dir/"reports"/"ai_report.json",
              Path("./reports/ai_report.json"),
              Path("../reports/ai_report.json")]:
        if c.exists():
            REPORT_PATH = str(c)
            break

if not REPORT_PATH or not Path(REPORT_PATH).exists():
    st.error("Report not found. Run the pipeline first.")
    st.stop()

try:
    report = json.loads(Path(REPORT_PATH).read_text())
except json.JSONDecodeError:
    st.error("Report JSON is invalid.")
    st.stop()

summary    = report.get("executive_summary", {})
findings   = report.get("findings", [])
recs       = report.get("recommendations", [])
compliance = report.get("compliance_flags", {})
prio_order = report.get("remediation_priority_order", [])

# ── Sidebar ───────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔐 Security Pipeline v2")
    st.markdown("---")

    all_sevs = ["CRITICAL","HIGH","MEDIUM","LOW"]
    sel_sev  = st.multiselect("Severity", all_sevs, default=all_sevs)

    tool_names = sorted(set(f.get("source","unknown") for f in findings))
    sel_tools  = st.multiselect("Tool", tool_names, default=tool_names)

    view_mode = st.radio("View by", ["Severity", "Tool"])
    sort_by   = st.selectbox("Sort by", ["Severity","Priority","File"])

    st.markdown("---")
    show_steps = st.checkbox("Show fix steps",     value=True)
    show_code  = st.checkbox("Show code examples", value=True)
    st.markdown("---")

    if st.button("🔄 Reload"):
        st.rerun()

    ts = report.get("generated_at","")[:19].replace("T"," ")
    st.caption(f"Generated: {ts}")
    st.caption("Tools: Semgrep · Trufflehog · Bearer · Trivy · FossID")
    st.caption("AI: Samsung Gauss API")
    st.caption("⚠️ No source code sent to AI")

# ── Header ────────────────────────────────────────────────────
risk       = summary.get("overall_risk","UNKNOWN").upper()
risk_color = SEV_COLOR.get(risk,"#8b949e")
risk_icon  = SEV_ICON.get(risk,"⚪")

col_h, col_r = st.columns([3,1])
with col_h:
    st.title("🔐 AI Security Analysis Report")
    st.caption("Semgrep + Trufflehog + Bearer CLI + Trivy + FossID → Samsung Gauss API")
with col_r:
    st.markdown(f"""
    <div style="background:{risk_color}18; border:2px solid {risk_color}; border-radius:10px;
                padding:16px; text-align:center; margin-top:8px;">
        <div style="font-size:32px">{risk_icon}</div>
        <div style="color:{risk_color}; font-size:22px; font-weight:700">{risk}</div>
        <div style="color:#8b949e; font-size:11px">Overall Risk</div>
    </div>""", unsafe_allow_html=True)

st.markdown("---")
if summary.get("immediate_action_required"):
    st.error(f"🚨 **Immediate Action Required** — {summary.get('key_risk_statement','')}")
else:
    st.info(f"📋 {summary.get('key_risk_statement','Scan complete.')}")
if summary.get("attack_surface_summary"):
    st.warning(f"🎯 **Attack Surface:** {summary['attack_surface_summary']}")

# ── Severity metrics ──────────────────────────────────────────
m1,m2,m3,m4,m5 = st.columns(5)
with m1: st.metric("Total", summary.get("total_issues", len(findings)))
with m2:
    v = summary.get("critical_count",0)
    st.metric("🔴 Critical", v, delta=f"-{v}" if v else None, delta_color="inverse" if v else "off")
with m3:
    v = summary.get("high_count",0)
    st.metric("🟠 High", v, delta=f"-{v}" if v else None, delta_color="inverse" if v else "off")
with m4: st.metric("🟡 Medium", summary.get("medium_count",0))
with m5: st.metric("🟢 Low",    summary.get("low_count",0))

# ── Tool summary ──────────────────────────────────────────────
st.markdown("---")
st.markdown("**🛠️ Scanner Results**")
cols = st.columns(5)
for col, tool_key in zip(cols, ["semgrep","trufflehog","bearer","trivy","fossid"]):
    info  = TOOLS[tool_key]
    count = len([f for f in findings if f.get("source") == tool_key])
    crits = len([f for f in findings if f.get("source") == tool_key and f.get("severity") == "CRITICAL"])
    with col:
        st.markdown(
            f'<div style="background:{info["color"]}18; border:1px solid {info["color"]}44; '
            f'border-radius:8px; padding:12px; text-align:center;">'
            f'<div style="font-size:20px">{info["icon"]}</div>'
            f'<div style="color:{info["color"]}; font-weight:700; font-size:13px">{info["name"]}</div>'
            f'<div style="font-size:26px; font-weight:700; color:#fff">{count}</div>'
            f'<div style="color:#8b949e; font-size:10px">{info["desc"]}</div>'
            f'{"<div style=color:#ff1744;font-size:11px;margin-top:4px>" + str(crits) + " critical</div>" if crits else ""}'
            f'</div>', unsafe_allow_html=True)

# ── Fix these first ───────────────────────────────────────────
if prio_order:
    st.markdown("---")
    st.markdown("**⚡ Fix These First**")
    for i, rule_id in enumerate(prio_order[:5], 1):
        match = next((f for f in findings if f.get("id") == rule_id), None)
        if match:
            sev   = match.get("severity","LOW").upper()
            color = SEV_COLOR.get(sev,"#8b949e")
            tool  = TOOLS.get(match.get("source",""), {}).get("name", "")
            st.markdown(
                f'<div style="padding:8px 14px; background:#161b22; border-left:3px solid {color}; '
                f'border-radius:6px; margin:4px 0;">'
                f'<b style="color:{color}">#{i}</b> &nbsp; {SEV_ICON.get(sev,"")} {match.get("title",rule_id)} '
                f'<span class="meta-pill">{match.get("file","")}:{match.get("line","")}</span>'
                f'<span class="meta-pill">{tool}</span></div>',
                unsafe_allow_html=True)

# ── Compliance ────────────────────────────────────────────────
owasp_viols = compliance.get("owasp_top10_violations", [])
cwe_refs    = compliance.get("cwe_references", [])
if owasp_viols or cwe_refs:
    st.markdown("---")
    st.markdown("**📋 Compliance Flags**")
    cc1, cc2 = st.columns(2)
    with cc1:
        st.markdown("**OWASP Top 10 Violations**")
        for o in owasp_viols: st.markdown(f"- 🔸 `{o}`")
        if not owasp_viols: st.success("✅ No OWASP violations")
    with cc2:
        st.markdown("**CWE / CVE References**")
        for c in cwe_refs:
            digits = re.search(r'\d+', str(c))
            if digits and "CWE" in str(c):
                st.markdown(f"- [`{c}`](https://cwe.mitre.org/data/definitions/{digits.group()}.html)")
            else:
                st.markdown(f"- `{c}`")
        if not cwe_refs: st.success("✅ No references")


# ── Finding card renderer ─────────────────────────────────────
def render_finding(finding):
    sev      = finding.get("severity","LOW").upper()
    color    = SEV_COLOR.get(sev,"#8b949e")
    icon     = SEV_ICON.get(sev,"⚪")
    title    = finding.get("title","Unknown")
    file_    = finding.get("file","unknown")
    line_    = finding.get("line",0)
    rule_id  = finding.get("id", finding.get("rule_id",""))
    cwe      = finding.get("cwe","N/A")
    owasp    = finding.get("owasp","N/A")
    priority = finding.get("priority",0)
    source   = finding.get("source","")
    tool_info = TOOLS.get(source, {})

    with st.expander(f"{icon} [{sev}]  {title}  —  {file_}:{line_}", expanded=(sev=="CRITICAL")):
        col_l, col_r = st.columns([3,1])
        with col_l:
            what = finding.get("what_it_means","")
            if what:
                st.markdown("**🔎 What it means**")
                st.markdown(what)

            scenario = finding.get("attack_scenario","")
            if scenario:
                st.markdown("**🎯 Attack Scenario**")
                st.markdown(f"> {scenario}")

            impact = finding.get("business_impact","")
            if impact:
                st.markdown(f"**💼 Business Impact:** {impact}")

            st.markdown("---")
            fix_sum = finding.get("fix_summary","")
            if fix_sum:
                st.markdown(f"**✅ Fix:** {fix_sum}")

            # Special fields for Trivy
            if source == "trivy":
                pkg = finding.get("package","")
                ver = finding.get("version","")
                fix = finding.get("fixed_in","")
                if pkg:
                    st.markdown(f"**📦 Package:** `{pkg}` version `{ver}`")
                    st.markdown(f"**🔧 Fixed in:** `{fix}`" if fix != "Not fixed yet"
                                else "**🔧 Fixed in:** No fix available yet")

            # Special fields for FossID
            if source == "fossid":
                lic = finding.get("license","")
                comp = finding.get("component","")
                if lic:
                    st.markdown(f"**⚖️ License:** `{lic}`")
                if comp:
                    st.markdown(f"**📦 Component:** `{comp}`")

            if show_steps:
                steps = finding.get("fix_steps", [])
                if isinstance(steps, str):
                    steps = [s.strip() for s in steps.split("\n") if s.strip()]
                if steps:
                    st.markdown("**🔧 Fix Steps**")
                    for i, step in enumerate(steps, 1):
                        num = STEP_NUMS[i-1] if i <= len(STEP_NUMS) else str(i)
                        st.markdown(f'<div class="step-item">{num} &nbsp; {step}</div>',
                                    unsafe_allow_html=True)

            if show_code:
                code_ex = finding.get("fix_code_example","")
                if code_ex and code_ex not in ("N/A",""):
                    st.markdown("**💻 Code Fix Example**")
                    sep = next((s for s in ["| AFTER:", "\nAFTER:", " AFTER:"] if s in code_ex), None)
                    if sep:
                        parts  = code_ex.split(sep, 1)
                        before = parts[0].replace("BEFORE:","").strip()
                        after  = parts[1].strip()
                        b1, b2 = st.columns(2)
                        with b1:
                            st.markdown("🔴 **Before (vulnerable)**")
                            st.code(before, language="python")
                        with b2:
                            st.markdown("🟢 **After (secure)**")
                            st.code(after, language="python")
                    else:
                        clean = code_ex.replace("BEFORE:","").replace("AFTER:","\n# ✅ Secure:\n")
                        st.code(clean, language="python")

            refs = finding.get("references",[])
            if refs:
                st.markdown("**📚 References**")
                for ref in refs: st.markdown(f"- {ref}")

        with col_r:
            st.markdown(
                f'<div style="background:{color}18; border:1px solid {color}; border-radius:8px;'
                f'padding:14px; text-align:center; margin-bottom:10px;">'
                f'<div style="font-size:24px">{icon}</div>'
                f'<div style="color:{color}; font-weight:700; font-size:16px">{sev}</div>'
                f'</div>', unsafe_allow_html=True)

            if tool_info:
                st.markdown(
                    f'<div style="background:{tool_info.get("color","#8b949e")}18; border:1px solid '
                    f'{tool_info.get("color","#8b949e")}44; border-radius:6px; padding:6px; '
                    f'text-align:center; margin-bottom:8px;">'
                    f'{tool_info.get("icon","")} <b style="color:{tool_info.get("color","#8b949e")}">'
                    f'{tool_info.get("name","")}</b></div>',
                    unsafe_allow_html=True)

            def pill(label, value):
                return f'<div class="meta-pill" style="margin:3px 0;"><b>{label}:</b> {value}</div>'

            st.markdown(
                pill("Rule", f"<code>{rule_id}</code>") +
                pill("File", f"<code>{file_}</code>") +
                pill("Line", f"<code>{line_}</code>"),
                unsafe_allow_html=True)

            digits = re.search(r'\d+', str(cwe))
            if digits and "CWE" in str(cwe):
                st.markdown(f"🔗 [**{cwe}**](https://cwe.mitre.org/data/definitions/{digits.group()}.html)")
            else:
                st.markdown(f'<div class="meta-pill">ID: {cwe}</div>', unsafe_allow_html=True)

            st.markdown(f'<div class="meta-pill">OWASP: {owasp}</div>', unsafe_allow_html=True)
            if priority:
                st.progress(priority/10, text=f"Priority: {priority}/10")


# ── Filter and sort findings ──────────────────────────────────
filtered = [f for f in findings
            if f.get("severity","LOW").upper() in sel_sev
            and f.get("source","unknown") in sel_tools]

def do_sort(lst):
    if sort_by == "Severity":
        lst.sort(key=lambda x: SEV_ORDER.get(x.get("severity","LOW").upper(), 99))
    elif sort_by == "Priority":
        lst.sort(key=lambda x: -x.get("priority", 0))
    elif sort_by == "File":
        lst.sort(key=lambda x: x.get("file",""))
    return lst


# ══════════════════════════════════════════════════
# VIEW MODE A: BY SEVERITY
# ══════════════════════════════════════════════════
if view_mode == "Severity":
    for sev_level, sev_label, sev_color in [
        ("CRITICAL", "🔴 Critical",  "#ff1744"),
        ("HIGH",     "🟠 High",      "#ff6d00"),
        ("MEDIUM",   "🟡 Medium",    "#ffd600"),
        ("LOW",      "🟢 Low",       "#00e676"),
    ]:
        if sev_level not in sel_sev:
            continue

        sev_findings = do_sort([f for f in filtered if f.get("severity","").upper() == sev_level])
        if not sev_findings:
            continue

        st.markdown("---")
        st.markdown(
            f'<div style="color:{sev_color}; font-size:18px; font-weight:700; '
            f'margin:10px 0 4px; border-bottom:1px solid {sev_color}33; padding-bottom:6px;">'
            f'{sev_label} Severity — {len(sev_findings)} issue(s)</div>',
            unsafe_allow_html=True)

        for finding in sev_findings:
            render_finding(finding)


# ══════════════════════════════════════════════════
# VIEW MODE B: BY TOOL
# ══════════════════════════════════════════════════
else:
    for tool_key in ["semgrep","trufflehog","bearer","trivy","fossid"]:
        if tool_key not in sel_tools:
            continue
        info = TOOLS[tool_key]
        tool_findings = do_sort([f for f in filtered if f.get("source") == tool_key])

        st.markdown("---")
        st.markdown(
            f'<div style="color:{info["color"]}; font-size:18px; font-weight:700; '
            f'margin:10px 0 4px; border-bottom:1px solid {info["color"]}33; padding-bottom:6px;">'
            f'{info["icon"]} {info["name"]} — {len(tool_findings)} finding(s)</div>'
            f'<div style="color:#8b949e; font-size:12px; margin-bottom:10px;">{info["desc"]}</div>',
            unsafe_allow_html=True)

        if not tool_findings:
            st.success(f"✅ No issues from {info['name']}.")
        else:
            for finding in tool_findings:
                render_finding(finding)


# ── Recommendations ───────────────────────────────────────────
if recs:
    st.markdown("---")
    st.markdown("**💡 Recommendations**")
    for rec in recs:
        effort  = rec.get("effort","MEDIUM").upper()
        e_color = {"LOW":"#00e676","MEDIUM":"#ffd600","HIGH":"#ff6d00"}.get(effort,"#8b949e")
        e_icon  = {"LOW":"⚡","MEDIUM":"🔧","HIGH":"🏗️"}.get(effort,"🔧")
        c1, c2  = st.columns([5,1])
        with c1:
            st.markdown(f"**{rec.get('area','General')}**")
            st.markdown(rec.get("action",""))
            if rec.get("rationale"): st.caption(f"Why: {rec['rationale']}")
        with c2:
            st.markdown(
                f'<div style="color:{e_color}; text-align:center; padding-top:10px;">'
                f'{e_icon}<br><small>{effort}</small></div>', unsafe_allow_html=True)
        st.divider()

# ── Footer ────────────────────────────────────────────────────
st.markdown("""
<div style="text-align:center; color:#484f58; padding:30px 0 10px; font-size:12px;">
    Modern AI Security Pipeline v2 &nbsp;|&nbsp;
    Semgrep · Trufflehog · Bearer CLI · Trivy · FossID → Samsung Gauss API<br>
    <em>Source code is never transmitted. Only security metadata is analyzed by AI.</em>
</div>
""", unsafe_allow_html=True)
