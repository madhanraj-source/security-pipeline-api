#!/usr/bin/env python3
"""
Stage 4: Security Dashboard
Streamlit UI — reads ai_report.json, renders polished report
with full issue detail + fix steps + code examples.
Run: streamlit run dashboard.py --server.port 8501
"""

import json
import sys
from pathlib import Path
from datetime import datetime

try:
    import streamlit as st
except ImportError:
    print("Install: pip install streamlit")
    sys.exit(1)

# ── Page config ─────────────────────────────────────────────
st.set_page_config(
    page_title="Security Analysis Report",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Styling ──────────────────────────────────────────────────
st.markdown("""
<style>
    [data-testid="stAppViewContainer"] { background: #0d1117; }
    [data-testid="stSidebar"]          { background: #161b22; }

    .card-critical { border-left: 4px solid #ff1744; background: #1a0008; padding: 14px 18px; border-radius: 8px; margin: 8px 0; }
    .card-high     { border-left: 4px solid #ff6d00; background: #1a0d00; padding: 14px 18px; border-radius: 8px; margin: 8px 0; }
    .card-medium   { border-left: 4px solid #ffd600; background: #1a1500; padding: 14px 18px; border-radius: 8px; margin: 8px 0; }
    .card-low      { border-left: 4px solid #00e676; background: #001a0d; padding: 14px 18px; border-radius: 8px; margin: 8px 0; }

    .badge-critical { background:#ff1744; color:#fff; padding:3px 10px; border-radius:12px; font-size:11px; font-weight:700; }
    .badge-high     { background:#ff6d00; color:#fff; padding:3px 10px; border-radius:12px; font-size:11px; font-weight:700; }
    .badge-medium   { background:#ffd600; color:#000; padding:3px 10px; border-radius:12px; font-size:11px; font-weight:700; }
    .badge-low      { background:#00e676; color:#000; padding:3px 10px; border-radius:12px; font-size:11px; font-weight:700; }

    .fix-box   { background:#0d2818; border:1px solid #1e4d2b; border-radius:6px; padding:12px 14px; font-family:monospace; font-size:12.5px; line-height:1.6; white-space:pre-wrap; }
    .step-item { background:#161b22; border-radius:6px; padding:8px 12px; margin:4px 0; font-size:13px; }
    .meta-pill { background:#21262d; color:#8b949e; padding:3px 9px; border-radius:10px; font-size:11px; margin:2px; display:inline-block; }
    .section-title { color:#58a6ff; font-size:17px; font-weight:700; margin:22px 0 10px; border-bottom:1px solid #21262d; padding-bottom:6px; }
    .risk-banner { border-radius:10px; padding:20px; text-align:center; margin-bottom:8px; }
</style>
""", unsafe_allow_html=True)

# ── Constants ────────────────────────────────────────────────
SEV_COLOR = {"CRITICAL":"#ff1744","HIGH":"#ff6d00","MEDIUM":"#ffd600","LOW":"#00e676","UNKNOWN":"#8b949e"}
SEV_ICON  = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","UNKNOWN":"⚪"}
SEV_ORDER = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}

# ── Load report ──────────────────────────────────────────────
REPORT_PATH = "./reports/ai_report.json"
if len(sys.argv) > 1:
    try:
        i = sys.argv.index("--report")
        REPORT_PATH = sys.argv[i+1]
    except (ValueError, IndexError):
        pass

try:
    report = json.loads(Path(REPORT_PATH).read_text())
except FileNotFoundError:
    st.error(f"Report not found at `{REPORT_PATH}`. Run the pipeline first.")
    st.stop()
except json.JSONDecodeError:
    st.error("Report JSON is invalid.")
    st.stop()

summary    = report.get("executive_summary", {})
findings   = report.get("findings", [])
recs       = report.get("recommendations", [])
compliance = report.get("compliance_flags", {})
priority_order = report.get("remediation_priority_order", [])

# ── Sidebar ──────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔐 Security Pipeline")
    st.markdown("---")

    all_sevs = ["CRITICAL","HIGH","MEDIUM","LOW"]
    sel_sev  = st.multiselect("Severity Filter", all_sevs, default=all_sevs)

    cats       = sorted(set(f.get("category","General") for f in findings))
    sel_cats   = st.multiselect("Category Filter", cats, default=cats)

    sort_by    = st.selectbox("Sort by", ["Severity","Priority Score","File"])

    show_code  = st.checkbox("Show fix code examples", value=True)
    show_steps = st.checkbox("Show fix steps",         value=True)

    st.markdown("---")
    if st.button("🔄 Reload"):
        st.rerun()

    ts = report.get("generated_at","")[:19].replace("T"," ")
    st.caption(f"Report: {ts}")
    st.caption(f"Pipeline: CodeQL + Gitleaks + SonarQube → Groq")
    st.caption(f"⚠️ No source code sent to AI")

# ── Header ───────────────────────────────────────────────────
risk       = summary.get("overall_risk","UNKNOWN").upper()
risk_color = SEV_COLOR.get(risk, "#8b949e")
risk_icon  = SEV_ICON.get(risk, "⚪")

col_h, col_r = st.columns([3,1])
with col_h:
    st.title("🔐 Security Analysis Report")
    st.caption("Powered by CodeQL + Gitleaks + SonarQube → Samsung Gauss AI")
with col_r:
    st.markdown(f"""
    <div class="risk-banner" style="background:{risk_color}18; border:2px solid {risk_color};">
        <div style="font-size:32px">{risk_icon}</div>
        <div style="color:{risk_color};font-size:22px;font-weight:700">{risk}</div>
        <div style="color:#8b949e;font-size:11px">Overall Risk</div>
    </div>""", unsafe_allow_html=True)

# ── Alert banner ─────────────────────────────────────────────
st.markdown("---")
if summary.get("immediate_action_required"):
    st.error(f"🚨 **Immediate Action Required** — {summary.get('key_risk_statement','')}")
else:
    st.info(f"📋 {summary.get('key_risk_statement','Scan complete.')}")

if summary.get("attack_surface_summary"):
    st.warning(f"🎯 **Attack Surface:** {summary['attack_surface_summary']}")

# ── Metrics ──────────────────────────────────────────────────
m1,m2,m3,m4,m5 = st.columns(5)
with m1: st.metric("Total Issues", summary.get("total_issues", len(findings)))
with m2:
    v = summary.get("critical_count",0)
    st.metric("🔴 Critical", v, delta=f"-{v}" if v else None, delta_color="inverse" if v else "off")
with m3:
    v = summary.get("high_count",0)
    st.metric("🟠 High", v, delta=f"-{v}" if v else None, delta_color="inverse" if v else "off")
with m4: st.metric("🟡 Medium", summary.get("medium_count",0))
with m5: st.metric("🟢 Low",    summary.get("low_count",0))

# ── Remediation Order ─────────────────────────────────────────
if priority_order:
    st.markdown("---")
    st.markdown('<div class="section-title">⚡ Fix These First</div>', unsafe_allow_html=True)
    for i, rule_id in enumerate(priority_order[:5], 1):
        match = next((f for f in findings if f.get("id") == rule_id), None)
        if match:
            sev   = match.get("severity","LOW").upper()
            color = SEV_COLOR.get(sev,"#8b949e")
            st.markdown(
                f'<div style="padding:8px 14px; background:#161b22; border-left:3px solid {color}; '
                f'border-radius:6px; margin:4px 0;">'
                f'<b style="color:{color}">#{i}</b> &nbsp; {match.get("title",rule_id)} '
                f'<span class="meta-pill">{match.get("file","")}:{match.get("line","")}</span>'
                f'</div>',
                unsafe_allow_html=True
            )

# ── Compliance ────────────────────────────────────────────────
owasp_viols = compliance.get("owasp_top10_violations",[])
cwe_refs    = compliance.get("cwe_references",[])
if owasp_viols or cwe_refs:
    st.markdown("---")
    st.markdown('<div class="section-title">📋 Compliance Flags</div>', unsafe_allow_html=True)
    cc1, cc2 = st.columns(2)
    with cc1:
        st.markdown("**OWASP Top 10 Violations**")
        for o in owasp_viols:
            st.markdown(f"- 🔸 `{o}`")
        if not owasp_viols:
            st.success("✅ No OWASP violations")
    with cc2:
        st.markdown("**CWE References**")
        for c in cwe_refs:
            cid = c.replace("CWE-","") if "CWE-" in str(c) else c
            st.markdown(f"- [`{c}`](https://cwe.mitre.org/data/definitions/{cid}.html)")
        if not cwe_refs:
            st.success("✅ No CWE references")

# ── Findings ──────────────────────────────────────────────────
st.markdown("---")
st.markdown('<div class="section-title">🔍 Findings</div>', unsafe_allow_html=True)

filtered = [
    f for f in findings
    if f.get("severity","LOW").upper() in sel_sev
    and f.get("category","General") in sel_cats
]

if sort_by == "Severity":
    filtered.sort(key=lambda x: SEV_ORDER.get(x.get("severity","LOW").upper(), 99))
elif sort_by == "Priority Score":
    filtered.sort(key=lambda x: -x.get("priority", 0))
elif sort_by == "File":
    filtered.sort(key=lambda x: x.get("file",""))

if not filtered:
    st.success("✅ No findings match current filters.")
else:
    st.caption(f"Showing {len(filtered)} of {len(findings)} findings")

    for finding in filtered:
        sev      = finding.get("severity","LOW").upper()
        color    = SEV_COLOR.get(sev,"#8b949e")
        icon     = SEV_ICON.get(sev,"⚪")
        title    = finding.get("title","Unknown")
        file_    = finding.get("file","unknown")
        line_    = finding.get("line",0)
        rule_id  = finding.get("id","")
        cwe      = finding.get("cwe","N/A")
        owasp    = finding.get("owasp","N/A")
        priority = finding.get("priority", 0)

        # Expand CRITICAL issues by default
        with st.expander(f"{icon} [{sev}]  {title}  —  {file_}:{line_}", expanded=(sev=="CRITICAL")):

            col_l, col_r = st.columns([3, 1])

            with col_l:
                # What it means
                st.markdown("**🔎 What it means**")
                st.markdown(finding.get("what_it_means", "No description."))

                # Attack scenario
                scenario = finding.get("attack_scenario","")
                if scenario:
                    st.markdown("**🎯 Attack Scenario**")
                    st.markdown(f"> {scenario}")

                # Business impact
                impact = finding.get("business_impact","")
                if impact:
                    st.markdown(f"**💼 Business Impact:** {impact}")

                st.markdown("---")

                # Fix summary
                st.markdown(f"**✅ Fix:** {finding.get('fix_summary','See steps below.')}")

                # Fix steps — handle list or string
                if show_steps:
                    steps = finding.get("fix_steps", [])
                    if isinstance(steps, str):
                        steps = [s.strip() for s in steps.split("\n") if s.strip()]
                    if steps:
                        st.markdown("**🔧 Fix Steps**")
                        nums = ["①","②","③","④","⑤","⑥","⑦","⑧","⑨","⑩"]
                        for i, step in enumerate(steps, 1):
                            num = nums[i-1] if i <= len(nums) else str(i)
                            st.markdown(
                                f'<div class="step-item">{num} &nbsp; {step}</div>',
                                unsafe_allow_html=True
                            )

                # Code example — handle multiple BEFORE/AFTER formats
                if show_code:
                    code_ex = finding.get("fix_code_example", "")
                    if code_ex and code_ex not in ("N/A", "", None):
                        st.markdown("**💻 Code Fix Example**")
                        # Detect separator: "| AFTER:" or "\nAFTER:" or "AFTER:"
                        sep = None
                        for s in ["| AFTER:", "\nAFTER:", " AFTER:"]:
                            if s in code_ex:
                                sep = s
                                break
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
                            # Show as single code block
                            clean = code_ex.replace("BEFORE:","").replace("AFTER:","\n# ✅ Fixed:\n")
                            st.code(clean, language="python")

                # References
                refs = finding.get("references", [])
                if refs:
                    st.markdown("**📚 References**")
                    for ref in refs:
                        st.markdown(f"- {ref}")

            with col_r:
                st.markdown(
                    f'<div style="background:{color}18; border:1px solid {color}; border-radius:8px; '
                    f'padding:14px; text-align:center; margin-bottom:12px;">'
                    f'<div style="font-size:24px">{icon}</div>'
                    f'<div style="color:{color}; font-weight:700; font-size:16px">{sev}</div>'
                    f'</div>', unsafe_allow_html=True
                )

                def pill(label, value):
                    return f'<div class="meta-pill"><b>{label}:</b> {value}</div>'

                st.markdown(
                    pill("Rule", f"<code>{rule_id}</code>") +
                    pill("File", f"<code>{file_}</code>") +
                    pill("Line", f"<code>{line_}</code>") +
                    pill("Category", finding.get("category","General")),
                    unsafe_allow_html=True
                )

                # CWE link — extract only digits for URL
                import re as _re
                cwe_digits = _re.search(r'\d+', str(cwe))
                if cwe_digits and cwe != "N/A":
                    cwe_num = cwe_digits.group()
                    st.markdown(f"🔗 [**{cwe}**](https://cwe.mitre.org/data/definitions/{cwe_num}.html)")
                else:
                    st.markdown(f'<div class="meta-pill">CWE: {cwe}</div>', unsafe_allow_html=True)

                st.markdown(f'<div class="meta-pill">OWASP: {owasp}</div>', unsafe_allow_html=True)

                if priority:
                    st.progress(priority/10, text=f"Priority: {priority}/10")

# ── Recommendations ───────────────────────────────────────────
if recs:
    st.markdown("---")
    st.markdown('<div class="section-title">💡 Recommendations</div>', unsafe_allow_html=True)
    for rec in recs:
        effort  = rec.get("effort","MEDIUM").upper()
        e_color = {"LOW":"#00e676","MEDIUM":"#ffd600","HIGH":"#ff6d00"}.get(effort,"#8b949e")
        e_icon  = {"LOW":"⚡","MEDIUM":"🔧","HIGH":"🏗️"}.get(effort,"🔧")

        with st.container():
            c1, c2 = st.columns([5,1])
            with c1:
                st.markdown(f"**{rec.get('area','General')}**")
                st.markdown(rec.get("action",""))
                rationale = rec.get("rationale","")
                if rationale:
                    st.caption(f"Why: {rationale}")
            with c2:
                st.markdown(
                    f'<div style="color:{e_color}; text-align:center; padding-top:10px;">'
                    f'{e_icon}<br><small>{effort}</small></div>',
                    unsafe_allow_html=True
                )
            st.divider()

# ── Footer ────────────────────────────────────────────────────
st.markdown("""
<div style="text-align:center; color:#484f58; padding:30px 0 10px; font-size:12px;">
    AI Security Pipeline &nbsp;|&nbsp; CodeQL + Gitleaks + SonarQube → Samsung Gauss AI<br>
    <em>Source code is never transmitted. Only security metadata is analyzed.</em>
</div>
""", unsafe_allow_html=True)
