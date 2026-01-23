# app.py
import time
import streamlit as st
import pandas as pd
import json
import numpy as np
import os
import hashlib
import datetime

from source import (
    setup_analysis_environment,
    safe_extract_zip,
    discover_files,
    find_first_by_name,
    read_text_file,
    store_config_snapshot,
    scan_code_files_for_insecure_deserialization_and_consolidate,
    scan_code_for_insecure_deserialization_and_consolidate,
    detect_dependency_hallucinations,
    create_risk_scorecard,
    generate_sdlc_control_recommendations,
    generate_executive_summary,
    save_reports,
    create_evidence_manifest,
    bundle_artifacts_to_zip,
)

# -----------------------------
# UI Header
# -----------------------------
st.set_page_config(
    page_title="QuLab: Lab 12: AI Code-Generation Risk Analyzer", layout="wide")
st.sidebar.image("https://www.quantuniversity.com/assets/img/logo5.jpg")
st.sidebar.divider()
st.title("QuLab: Lab 12: AI Code-Generation Risk Analyzer")
st.divider()

# -----------------------------
# Defaults
# -----------------------------
DEFAULT_PYTHON_CODE = """import os
import subprocess
import pickle
import base64
import sqlite3

API_KEY = "sk_prod_12345" 
DEBUG_MODE = True
SECRET_PHRASE = "this_is_a_secret" 

def authenticate(password):
    if password == SECRET_PHRASE:
        print("Authentication successful.")
        return True
    return False

def execute_command(command):
    # Potential Command Injection
    subprocess.run(f"echo {command}", shell=True) # High: Use of shell=True with user input

def evaluate_expression(expr):
    # Unsafe eval/exec
    return eval(expr) 

def get_user_data(username):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Potential SQL Injection
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query) 
    user_data = cursor.fetchone()
    conn.close()
    return user_data

def process_serialized_data(encoded_data):
    # Insecure Deserialization
    data = base64.b64decode(encoded_data)
    obj = pickle.loads(data) 
    return obj

def process_request(request):
    user_input = request.get('input', '')
    if 'eval_code' in request:
        evaluate_expression(request['eval_code'])
    elif 'cmd' in request:
        execute_command(request['cmd'])
    elif 'username' in request:
        get_user_data(request['username'])
    elif 'serialized_data' in request:
        process_serialized_data(request['serialized_data'])

    # False positive suppression example: a string that looks like a secret but isn't
    user_id_prefix = "user_identifier_" + str(hash(user_input)) # Not a secret
    return {"status": "processed", "user_id_prefix": user_id_prefix}"""

DEFAULT_REQUIREMENTS_CONTENT = """flask==2.1.0
requests==2.28.1
unknown-package-malware==1.0.0 # This should be flagged
sqlalchemy==1.4.32"""

DEFAULT_ALLOWLIST_JSON = json.dumps({
    "flask": ["2.1.0", "2.2.0"],
    "requests": ["2.28.1", "2.29.0", "2.30.0"],
    "sqlalchemy": ["1.4.32", "2.0.0"]
}, indent=4)

DEFAULT_ALLOWLIST_JSON = json.dumps({
    "flask": ["2.1.0", "2.2.0"],
    "requests": ["2.28.1", "2.29.0", "2.30.0"],
    "sqlalchemy": ["1.4.32", "2.0.0"]
}, indent=4)


def render_static_findings_dashboard(
    analysis_done: bool,
    df_static_findings: pd.DataFrame,
    *,
    title: str = "Static Analysis Findings",
    default_group_by_file: bool = True,
):
    """
    Dashboard-style renderer for static findings (instead of st.dataframe).

    Usage:
        render_static_findings_dashboard(
            st.session_state.analysis_done,
            st.session_state.df_all_static_findings
        )
    """
    st.markdown(f"## {title}")

    if not analysis_done:
        st.warning("Run analysis first in '1. Code & Context Input'.")
        return

    if df_static_findings is None or df_static_findings.empty:
        st.info("No static analysis findings detected.")
        return

    df = df_static_findings.copy()

    # Ensure expected cols exist
    expected_cols = [
        "file_path", "risk_type", "severity", "confidence",
        "line_num", "code_snippet", "description", "remediation"
    ]
    for c in expected_cols:
        if c not in df.columns:
            df[c] = ""

    df["file_path"] = df["file_path"].fillna("")
    df["line_num"] = df["line_num"].fillna("")
    df["severity"] = df["severity"].fillna("")
    df["confidence"] = df["confidence"].fillna("")
    df["risk_type"] = df["risk_type"].fillna("")

    # KPI Row
    total = len(df)
    files_affected = int(df["file_path"].replace(
        "", np.nan).dropna().nunique())
    sev_counts = df["severity"].replace("", "Unknown").value_counts()
    top_sev = sev_counts.index[0] if len(sev_counts) else "Unknown"

    k1, k2, k3 = st.columns(3)
    k1.metric("Total Findings", total)
    k2.metric("Files Affected", files_affected)
    k3.metric("Most Common Severity", top_sev)

    st.markdown("---")

    # Charts
    c1, c2 = st.columns([1, 1])
    with c1:
        st.markdown("#### Findings by Severity")
        st.bar_chart(sev_counts)

    with c2:
        st.markdown("#### Findings by Risk Type")
        rt_counts = df["risk_type"].replace(
            "", "Unknown").value_counts().head(12)
        st.bar_chart(rt_counts)

    st.markdown("---")

    # Filters
    st.markdown("#### Filters")
    severity_options = ["All"] + \
        sorted([s for s in df["severity"].unique().tolist() if s])
    risk_type_options = [
        "All"] + sorted([t for t in df["risk_type"].unique().tolist() if t])
    file_options = ["All"] + \
        sorted([p for p in df["file_path"].unique().tolist() if p])

    f1, f2, f3 = st.columns([1, 1, 2])
    selected_sev = f1.selectbox(
        "Severity", severity_options, index=0, key="static_filter_severity")
    selected_type = f2.selectbox(
        "Risk Type", risk_type_options, index=0, key="static_filter_risktype")
    selected_file = f3.selectbox(
        "File Path", file_options, index=0, key="static_filter_filepath")

    dff = df.copy()
    if selected_sev != "All":
        dff = dff[dff["severity"] == selected_sev]
    if selected_type != "All":
        dff = dff[dff["risk_type"] == selected_type]
    if selected_file != "All":
        dff = dff[dff["file_path"] == selected_file]

    # Sort: Critical/High first-ish by manual mapping
    sev_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    conf_order = {"High": 3, "Medium": 2, "Low": 1}
    dff["_sev"] = dff["severity"].map(sev_order).fillna(0)
    dff["_conf"] = dff["confidence"].map(conf_order).fillna(0)
    dff = dff.sort_values(by=["_sev", "_conf"], ascending=False).drop(
        columns=["_sev", "_conf"]).reset_index(drop=True)

    st.caption(f"Showing {len(dff)} of {len(df)} findings.")

    st.markdown("---")

    # Card View
    st.markdown("#### Findings (Card View)")
    group_by_file = st.toggle(
        "Group by file", value=default_group_by_file, key="static_group_by_file")

    def badge(sev: str) -> str:
        return f"[{sev or 'Unknown'}]"

    if dff.empty:
        st.info("No findings match the selected filters.")
        return

    if group_by_file:
        grouped = dff.groupby(dff["file_path"].replace("", "— Unknown file —"))
        for file_path, g in grouped:
            st.markdown(f"##### {file_path}")
            for _, row in g.iterrows():
                title = f"{badge(row['severity'])} {row['risk_type']} • Line {row['line_num'] or 'N/A'}"
                with st.expander(title, expanded=False):
                    a, b = st.columns([1, 2])
                    a.write(f"**Severity:** {row['severity'] or 'Unknown'}")
                    a.write(
                        f"**Confidence:** {row['confidence'] or 'Unknown'}")
                    b.write(f"**Risk Type:** {row['risk_type'] or 'Unknown'}")
                    b.write(f"**Line:** {row['line_num'] or 'N/A'}")

                    if row["code_snippet"]:
                        st.markdown("**Code Snippet**")
                        st.code(str(row["code_snippet"]), language="python")

                    st.markdown("**Description**")
                    st.write(str(row["description"]))

                    st.markdown("**Remediation**")
                    st.write(str(row["remediation"]))
            st.markdown("---")
    else:
        for _, row in dff.iterrows():
            fname = os.path.basename(
                row["file_path"]) if row["file_path"] else "Unknown file"
            title = f"{badge(row['severity'])} {row['risk_type']} • {fname} • Line {row['line_num'] or 'N/A'}"
            with st.expander(title, expanded=False):
                st.write(f"**File:** {row['file_path'] or 'N/A'}")
                st.write(f"**Severity:** {row['severity'] or 'Unknown'}")
                st.write(f"**Confidence:** {row['confidence'] or 'Unknown'}")
                st.write(f"**Line:** {row['line_num'] or 'N/A'}")

                if row["code_snippet"]:
                    st.markdown("**Code Snippet**")
                    st.code(str(row["code_snippet"]), language="python")

                st.markdown("**Description**")
                st.write(str(row["description"]))

                st.markdown("**Remediation**")
                st.write(str(row["remediation"]))

    # Optional export
    csv_bytes = dff[expected_cols].to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download Filtered Static Findings (CSV)",
        data=csv_bytes,
        file_name="filtered_static_findings.csv",
        mime="text/csv",
        key="download_static_findings_csv"
    )


def compute_sha256_from_string(content: str) -> str:
    if not content:
        return ""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def save_uploaded_streamlit_file(uploaded_file, dest_path: str) -> str:
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    with open(dest_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return dest_path


def persist_text_inputs(report_path: str, python_code: str, requirements: str, allowlist_json_str: str) -> dict:
    """
    Persist textarea inputs as files so they appear in the artifact zip.
    """
    code_path = os.path.join(report_path, "pasted_code.py")
    req_path = os.path.join(report_path, "requirements.txt")
    allow_path = os.path.join(report_path, "dependency_allowlist.json")

    with open(code_path, "w", encoding="utf-8") as f:
        f.write(python_code or "")

    with open(req_path, "w", encoding="utf-8") as f:
        f.write(requirements or "")

    try:
        allow_obj = json.loads(allowlist_json_str or "{}")
    except json.JSONDecodeError:
        allow_obj = {}
    with open(allow_path, "w", encoding="utf-8") as f:
        json.dump(allow_obj, f, indent=4)

    return {"code_paths": [code_path], "requirements_path": req_path, "allowlist_path": allow_path}


# -----------------------------
# Session State
# -----------------------------
if "session_id" not in st.session_state or st.session_state.session_id is None:
    st.session_state.session_id, st.session_state.report_path = setup_analysis_environment()

st.session_state.setdefault("current_page", "Home")
st.session_state.setdefault("python_code", DEFAULT_PYTHON_CODE)
st.session_state.setdefault("requirements_content",
                            DEFAULT_REQUIREMENTS_CONTENT)
st.session_state.setdefault(
    "dependency_allowlist_json_str", DEFAULT_ALLOWLIST_JSON)

try:
    st.session_state.setdefault(
        "dependency_allowlist", json.loads(DEFAULT_ALLOWLIST_JSON))
except json.JSONDecodeError:
    st.session_state.setdefault("dependency_allowlist", {})

st.session_state.setdefault("generation_method", "Copilot")
st.session_state.setdefault("human_review_level", "Partial")
st.session_state.setdefault("analysis_done", False)

st.session_state.setdefault("df_all_static_findings", pd.DataFrame())
st.session_state.setdefault("df_dependency_findings", pd.DataFrame())
st.session_state.setdefault("df_consolidated_findings", pd.DataFrame())
st.session_state.setdefault("risk_summary_data", {})
st.session_state.setdefault("sdlc_recommendations_markdown", "")
st.session_state.setdefault("executive_summary_markdown", "")
st.session_state.setdefault("evidence_manifest_filepath", None)
st.session_state.setdefault("zip_archive_filepath", None)

# -----------------------------
# Sidebar Navigation
# -----------------------------
with st.sidebar:
    page_selection = st.selectbox(
        "Navigation",
        ["Home", "1. Code & Context Input", "2. Static Analysis Findings", "3. Dependency Analysis",
         "4. Consolidated Risk & Controls", "5. Report Export"],
        key="page_selector",
    )
    st.session_state.current_page = page_selection


# -----------------------------
# Pages
# -----------------------------
if st.session_state.current_page == "Home":

    st.markdown(
        f"## Introduction: Securing AI-Generated Code at InnovateTech Solutions")
    st.markdown(f"Alice plays a crucial role in maintaining the security posture of InnovateTech Solutions' applications. With the adoption of AI-powered code generation tools, her team must ensure AI-generated code adheres to strict secure coding standards before integration into critical systems.")
    st.markdown(f"Today, Alice received a Python API handler that was largely generated by Copilot. Before this code can proceed to the next SDLC stage, Alice will perform a thorough security review. Her objectives:")
    st.markdown(f"""- Detect hard-coded secrets
- Identify injection flaws (SQL/Command)
- Spot unsafe deserialization
- Verify dependencies against an allowlist
- Produce a consolidated, prioritized vulnerability report and remediation plan
""")
    st.markdown(f"This application simulates Alice's workflow using heuristic and AST-based static analysis, dependency verification, and a comprehensive vulnerability report for InnovateTech Solutions.")
    st.markdown(f"---")
    st.markdown(f"### Learning Objectives")
    st.markdown(f"By completing this lab, you will be able to:")
    st.markdown(f"""1. Identify common failure modes in AI-generated code.
2. Detect insecure patterns using static heuristics.
3. Flag dependency hallucinations and supply-chain risks.
4. Define SDLC control gates for AI-assisted development.
5. Produce audit-ready code-gen risk reports.""")

elif st.session_state.current_page == "1. Code & Context Input":

    st.markdown("## 1. Code & Context Input")

    st.markdown("### Upload Python Files (multiple) OR Upload a ZIP")
    uploaded_py_files = st.file_uploader(
        "Upload one or more .py files",
        type=["py"],
        accept_multiple_files=True,
        key="py_uploader"
    )

    uploaded_zip = st.file_uploader(
        "Or upload a .zip containing code + optional requirements.txt + dependency_allowlist.json",
        type=["zip"],
        accept_multiple_files=False,
        key="zip_uploader"
    )

    st.markdown("---")
    st.markdown("### Fallback: Paste Code (used only if no uploads)")
    st.session_state.python_code = st.text_area(
        "Python Code",
        value=st.session_state.python_code,
        height=250,
        key="python_code_input",
    )

    st.markdown(
        "### Dependency Context (used if ZIP does not include these files)")
    st.session_state.requirements_content = st.text_area(
        "Requirements.txt Content (Optional)",
        value=st.session_state.requirements_content,
        height=120,
        key="requirements_input",
    )

    st.session_state.dependency_allowlist_json_str = st.text_area(
        "Dependency Allowlist (JSON)",
        value=st.session_state.dependency_allowlist_json_str,
        height=180,
        key="allowlist_input",
    )

    try:
        st.session_state.dependency_allowlist = json.loads(
            st.session_state.dependency_allowlist_json_str)
    except json.JSONDecodeError:
        st.error("Invalid JSON in Dependency Allowlist. Please check the format.")
        st.session_state.dependency_allowlist = {}

    st.markdown("### Generation Context")
    generation_options = ["Copilot", "Claude", "Agent"]
    st.session_state.generation_method = st.selectbox(
        "AI Generation Method",
        generation_options,
        index=generation_options.index(st.session_state.generation_method)
        if st.session_state.generation_method in generation_options else 0,
        key="generation_method_selector",
    )

    review_options = ["None", "Partial", "Full"]
    st.session_state.human_review_level = st.selectbox(
        "Human Review Level",
        review_options,
        index=review_options.index(st.session_state.human_review_level)
        if st.session_state.human_review_level in review_options else 1,
        key="review_level_selector",
    )

    if st.button("Run Analysis", key="run_analysis_button"):
        with st.spinner("Running analysis..."):
            time.sleep(3)
            # Ensure environment exists
            if st.session_state.session_id is None or st.session_state.report_path is None:
                st.session_state.session_id, st.session_state.report_path = setup_analysis_environment()

            report_path = st.session_state.report_path
            uploads_dir = os.path.join(report_path, "uploads")
            extracted_dir = os.path.join(report_path, "extracted_zip")
            os.makedirs(uploads_dir, exist_ok=True)

            code_paths = []
            requirements_content = None
            allowlist_obj = None
            requirements_fp = None
            allowlist_fp = None

            # ---- Path A: ZIP upload ----
            if uploaded_zip is not None:
                zip_path = os.path.join(uploads_dir, uploaded_zip.name)
                save_uploaded_streamlit_file(uploaded_zip, zip_path)

                safe_extract_zip(zip_path, extracted_dir)

                # discover .py files
                code_paths = discover_files(extracted_dir, exts=(".py",))

                # optional: pull requirements + allowlist from zip if present
                requirements_fp = find_first_by_name(
                    extracted_dir, "requirements.txt")
                allowlist_fp = find_first_by_name(
                    extracted_dir, "dependency_allowlist.json")

                if requirements_fp and os.path.exists(requirements_fp):
                    requirements_content = read_text_file(requirements_fp)
                if allowlist_fp and os.path.exists(allowlist_fp):
                    try:
                        allowlist_obj = json.loads(
                            read_text_file(allowlist_fp))
                    except json.JSONDecodeError:
                        allowlist_obj = {}

                if not code_paths:
                    st.error(
                        "ZIP uploaded, but no .py files were found inside it.")
                    st.stop()

            # ---- Path B: multiple .py uploads ----
            elif uploaded_py_files:
                for f in uploaded_py_files:
                    dest = os.path.join(uploads_dir, f.name)
                    save_uploaded_streamlit_file(f, dest)
                    code_paths.append(dest)

            # ---- Path C: fallback to textarea ----
            else:
                if not st.session_state.python_code.strip():
                    st.warning(
                        "Please upload code files/zip OR paste Python code.")
                    st.stop()

                persisted = persist_text_inputs(
                    report_path,
                    st.session_state.python_code,
                    st.session_state.requirements_content,
                    st.session_state.dependency_allowlist_json_str,
                )
                code_paths = persisted["code_paths"]
                requirements_fp = persisted["requirements_path"]
                allowlist_fp = persisted["allowlist_path"]
                requirements_content = st.session_state.requirements_content
                allowlist_obj = st.session_state.dependency_allowlist

            # If ZIP did not provide deps, use textarea deps
            if requirements_content is None:
                requirements_content = st.session_state.requirements_content
            if allowlist_obj is None:
                allowlist_obj = st.session_state.dependency_allowlist

            # If we still don't have allowlist (bad JSON), force empty dict
            if not isinstance(allowlist_obj, dict):
                allowlist_obj = {}

            # Store config snapshot (multi-file aware)
            store_config_snapshot(
                report_path=report_path,
                run_id=st.session_state.session_id,
                code_filepaths=code_paths,
                requirements_filepath=requirements_fp,
                allowlist_filepath=allowlist_fp,
                ai_generation_method=st.session_state.generation_method,
                human_review_level=st.session_state.human_review_level,
                extra={
                    "num_code_files": len(code_paths),
                    "uploaded_zip": uploaded_zip.name if uploaded_zip else None,
                    "uploaded_py_files": [f.name for f in uploaded_py_files] if uploaded_py_files else None,
                    "requirements_hash_sha256_from_textarea": compute_sha256_from_string(st.session_state.requirements_content),
                    "allowlist_hash_sha256_from_textarea": compute_sha256_from_string(st.session_state.dependency_allowlist_json_str),
                }
            )

            # ---- 1) Static Analysis across all code files ----
            if len(code_paths) == 1:
                code_str = read_text_file(code_paths[0])
                st.session_state.df_all_static_findings = pd.DataFrame(
                    [dict(f, file_path=code_paths[0])
                     for f in scan_code_for_insecure_deserialization_and_consolidate(code_str)]
                )
            else:
                st.session_state.df_all_static_findings = scan_code_files_for_insecure_deserialization_and_consolidate(
                    code_paths)

            # ---- 2) Dependency Analysis ----
            dep_findings = detect_dependency_hallucinations(
                requirements_content or "", allowlist_obj)
            st.session_state.df_dependency_findings = pd.DataFrame(
                dep_findings)

            dep_json_path = os.path.join(
                report_path, "dependency_findings.json")
            st.session_state.df_dependency_findings.to_json(
                dep_json_path, orient="records", indent=4)

            # ---- 3) Risk Scoring ----
            st.session_state.df_consolidated_findings, st.session_state.risk_summary_data = create_risk_scorecard(
                st.session_state.df_all_static_findings,
                st.session_state.df_dependency_findings,
            )

            # ---- 4) SDLC + Executive ----
            st.session_state.sdlc_recommendations_markdown = generate_sdlc_control_recommendations(
                st.session_state.risk_summary_data
            )
            st.session_state.executive_summary_markdown = generate_executive_summary(
                st.session_state.session_id,
                st.session_state.risk_summary_data,
                st.session_state.sdlc_recommendations_markdown,
            )

            # ---- 5) Save reports ----
            save_reports(
                report_path=report_path,
                run_id=st.session_state.session_id,
                df_consolidated=st.session_state.df_consolidated_findings,
                risk_summary=st.session_state.risk_summary_data,
                sdlc_md=st.session_state.sdlc_recommendations_markdown,
                exec_md=st.session_state.executive_summary_markdown,
            )

            # ---- 6) Evidence + ZIP ----
            st.session_state.evidence_manifest_filepath = create_evidence_manifest(
                report_path)
            st.session_state.zip_archive_filepath = bundle_artifacts_to_zip(
                report_path, st.session_state.session_id)

            st.session_state.analysis_done = True
            st.success(
                f"Analysis complete! Processed {len(code_paths)} code file(s).")

elif st.session_state.current_page == "2. Static Analysis Findings":
    st.markdown("## 2. Static Analysis Findings")
    if st.session_state.analysis_done:
        render_static_findings_dashboard(
            st.session_state.analysis_done,
            st.session_state.df_all_static_findings,
            title="2. Static Analysis Findings"
        )
    else:
        st.warning("Run analysis first in '1. Code & Context Input'.")

elif st.session_state.current_page == "3. Dependency Analysis":
    st.markdown("## 3. Dependency Analysis")
    if st.session_state.analysis_done:
        if not st.session_state.df_dependency_findings.empty:
            cols = ["risk_type", "severity", "confidence", "package", "version",
                    "line_in_requirements_txt", "description", "remediation"]
            cols = [
                c for c in cols if c in st.session_state.df_dependency_findings.columns]
            st.dataframe(st.session_state.df_dependency_findings[cols])
        else:
            st.info("No dependency issues detected.")
    else:
        st.warning("Run analysis first in '1. Code & Context Input'.")

elif st.session_state.current_page == "4. Consolidated Risk & Controls":
    st.markdown("## 4. Consolidated Risk & Controls")
    if st.session_state.analysis_done:
        if not st.session_state.df_consolidated_findings.empty:
            st.markdown("### Risk Summary")
            for k, v in st.session_state.risk_summary_data.items():
                st.markdown(f"- **{k.replace('_', ' ').title()}**: {v}")

            df = st.session_state.df_consolidated_findings.copy()

            # ---- Normalize / ensure expected columns exist ----
            for c in ["file_path", "risk_type", "severity", "confidence", "risk_score", "line_num", "package", "code_snippet", "description", "remediation"]:
                if c not in df.columns:
                    df[c] = ""

            df["file_path"] = df["file_path"].fillna("")
            df["package"] = df["package"].fillna("")
            df["line_num"] = df["line_num"].fillna("")
            df["risk_score"] = pd.to_numeric(
                df["risk_score"], errors="coerce").fillna(0.0)

            # ---- KPI Row ----
            total_findings = len(df)
            highest_sev = st.session_state.risk_summary_data.get(
                "highest_severity_overall", "None")
            max_risk = float(df["risk_score"].max()
                             ) if total_findings > 0 else 0.0
            files_affected = int(df["file_path"].replace(
                "", np.nan).dropna().nunique())

            k1, k2, k3, k4 = st.columns(4)
            k1.metric("Total Findings", total_findings)
            k2.metric("Highest Severity", highest_sev)
            k3.metric("Max Risk Score", f"{max_risk:.2f}")
            k4.metric("Files Affected", files_affected)

            st.markdown("---")

            # ---- Charts Row ----
            c1, c2 = st.columns([1, 1])

            with c1:
                st.markdown("#### Findings by Severity")
                sev_counts = df["severity"].replace(
                    "", "Unknown").value_counts()
                st.bar_chart(sev_counts)

            with c2:
                st.markdown("#### Findings by Risk Type")
                rt_counts = df["risk_type"].replace(
                    "", "Unknown").value_counts().head(12)
                st.bar_chart(rt_counts)

            st.markdown("---")

            # ---- Filters ----
            st.markdown("#### Filters")

            severity_options = [
                "All"] + sorted([s for s in df["severity"].unique().tolist() if s])
            risk_type_options = [
                "All"] + sorted([t for t in df["risk_type"].unique().tolist() if t])
            file_options = [
                "All"] + sorted([p for p in df["file_path"].unique().tolist() if p])

            f1, f2, f3 = st.columns([1, 1, 2])
            selected_sev = f1.selectbox("Severity", severity_options, index=0)
            selected_type = f2.selectbox(
                "Risk Type", risk_type_options, index=0)
            selected_file = f3.selectbox("File Path", file_options, index=0)

            # apply filters
            df_filtered = df.copy()
            if selected_sev != "All":
                df_filtered = df_filtered[df_filtered["severity"]
                                          == selected_sev]
            if selected_type != "All":
                df_filtered = df_filtered[df_filtered["risk_type"]
                                          == selected_type]
            if selected_file != "All":
                df_filtered = df_filtered[df_filtered["file_path"]
                                          == selected_file]

            # Sort high-risk first
            df_filtered = df_filtered.sort_values(
                by="risk_score", ascending=False).reset_index(drop=True)

            st.caption(
                f"Showing {len(df_filtered)} of {len(df)} findings (sorted by risk score).")

            st.markdown("---")

            # ---- Findings as Cards (Expander Dashboard) ----
            st.markdown("#### Findings (Card View)")

            if df_filtered.empty:
                st.info("No findings match the selected filters.")
            else:
                # Optional: group by file
                group_by_file = st.toggle("Group by file", value=True)

                def severity_badge(sev: str) -> str:
                    # simple text badge (no custom CSS required)
                    return f"[{sev}]"

                if group_by_file:
                    # group findings by file_path (dependencies may have empty file_path)
                    grouped = df_filtered.groupby(df_filtered["file_path"].replace(
                        "", "— No file (dependency finding) —"))
                    for file_path, g in grouped:
                        st.markdown(f"##### {file_path}")
                        for i, row in g.iterrows():
                            title = f"{severity_badge(row['severity'])} {row['risk_type']} • Risk {row['risk_score']:.2f} • Line {row['line_num'] or 'N/A'} • Package {row['package'] or 'N/A'}"
                            with st.expander(title, expanded=False):
                                # Show key info in a compact layout
                                a, b, c = st.columns([1, 1, 2])
                                a.write(f"**Severity:** {row['severity']}")
                                b.write(f"**Confidence:** {row['confidence']}")
                                c.write(
                                    f"**Risk Score:** {row['risk_score']:.2f}")

                                if row["code_snippet"]:
                                    st.markdown("**Code Snippet**")
                                    st.code(
                                        str(row["code_snippet"]), language="python")

                                st.markdown("**Description**")
                                st.write(str(row["description"]))

                                st.markdown("**Remediation**")
                                st.write(str(row["remediation"]))
                        st.markdown("---")
                else:
                    for i, row in df_filtered.iterrows():
                        title = f"{severity_badge(row['severity'])} {row['risk_type']} • Risk {row['risk_score']:.2f} • {os.path.basename(row['file_path']) if row['file_path'] else 'Dependency/No file'}"
                        with st.expander(title, expanded=False):
                            st.write(f"**File:** {row['file_path'] or 'N/A'}")
                            st.write(f"**Line:** {row['line_num'] or 'N/A'}")
                            st.write(f"**Package:** {row['package'] or 'N/A'}")
                            st.write(
                                f"**Severity:** {row['severity']} | **Confidence:** {row['confidence']} | **Risk:** {row['risk_score']:.2f}")

                            if row["code_snippet"]:
                                st.markdown("**Code Snippet**")
                                st.code(str(row["code_snippet"]),
                                        language="python")

                            st.markdown("**Description**")
                            st.write(str(row["description"]))

                            st.markdown("**Remediation**")
                            st.write(str(row["remediation"]))

            st.markdown("### SDLC Control Recommendations")
            st.markdown(st.session_state.sdlc_recommendations_markdown)
        else:
            st.info("No vulnerabilities detected.")
    else:
        st.warning("Run analysis first in '1. Code & Context Input'.")

elif st.session_state.current_page == "5. Report Export":
    st.markdown("## 5. Report Export")
    if st.session_state.analysis_done:
        with st.container(border=True):
            st.markdown(st.session_state.executive_summary_markdown)

        st.markdown("### Download ZIP")
        if st.session_state.zip_archive_filepath and os.path.exists(st.session_state.zip_archive_filepath):
            with open(st.session_state.zip_archive_filepath, "rb") as fp:
                st.download_button(
                    label=f"Download All Reports (Session_{st.session_state.session_id}.zip)",
                    data=fp,
                    file_name=f"Session_{st.session_state.session_id}.zip",
                    mime="application/zip",
                    key="download_all_zip",
                )

        st.markdown("---")
        st.markdown("### Individual Files")
        output_files = {
            "code_findings.json": "application/json",
            "dependency_findings.json": "application/json",
            "risk_scorecard.json": "application/json",
            "sdlc_control_recommendations.md": "text/markdown",
            "session12_executive_summary.md": "text/markdown",
            "config_snapshot.json": "application/json",
            "evidence_manifest.json": "application/json",
        }
        for filename, mime_type in output_files.items():
            filepath = os.path.join(st.session_state.report_path, filename)
            if os.path.exists(filepath):
                with open(filepath, "rb") as fp:
                    st.download_button(
                        label=f"Download {filename}",
                        data=fp,
                        file_name=filename,
                        mime=mime_type,
                        key=f"download_{filename.replace('.', '_')}",
                    )
            else:
                st.info(f"Not generated yet: {filename}")
    else:
        st.warning("Run analysis first in '1. Code & Context Input'.")

# License
st.caption('''
---
## QuantUniversity License

© QuantUniversity 2025
This notebook was created for **educational purposes only** and is **not intended for commercial use**.

- You **may not copy, share, or redistribute** this notebook **without explicit permission** from QuantUniversity.
- You **may not delete or modify this license cell** without authorization.
- This notebook was generated using **QuCreate**, an AI-powered assistant.
- Content generated by AI may contain **hallucinated or incorrect information**. Please **verify before using**.

All rights reserved. For permissions or commercial licensing, contact: info@qusandbox.com
''')
