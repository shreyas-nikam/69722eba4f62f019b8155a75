import streamlit as st
import pandas as pd
import json
import os
import io
import hashlib
import datetime
from source import * 

# Standard QuLab Header
st.set_page_config(page_title="QuLab: Lab 12: AI Code-Generation Risk Analyzer", layout="wide")
st.sidebar.image("https://www.quantuniversity.com/assets/img/logo5.jpg")
st.sidebar.divider()
st.title("QuLab: Lab 12: AI Code-Generation Risk Analyzer")
st.divider()

# --- Defaults from Specification ---
DEFAULT_PYTHON_CODE = """
import os
import subprocess
import pickle
import base64
import sqlite3

API_KEY = "sk_prod_12345" # Critical: Hardcoded API key
DEBUG_MODE = True
SECRET_PHRASE = "this_is_a_secret" # Critical: Another hardcoded secret

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
    return eval(expr) # Critical: Unsafe use of eval

def get_user_data(username):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Potential SQL Injection
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query) # Critical: Unsafe string concatenation in SQL query
    user_data = cursor.fetchone()
    conn.close()
    return user_data

def process_serialized_data(encoded_data):
    # Insecure Deserialization
    data = base64.b64decode(encoded_data)
    obj = pickle.loads(data) # Critical: Insecure use of pickle.loads
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
    return {"status": "processed", "user_id_prefix": user_id_prefix}

# Example usage (for testing)
if __name__ == '__main__':
    # Simulating a request
    example_request = {
        'eval_code': '2 + 2',
        'cmd': 'ls -la',
        'username': "admin' OR '1'='1",
        'serialized_data': base64.b64encode(pickle.dumps({'name': 'test'})).decode('utf-8'),
        'input': 'some_input'
    }
    process_request(example_request)
    print(f"API Key: {API_KEY}")
    authenticate("wrong_password")
"""

DEFAULT_REQUIREMENTS_CONTENT = """
flask==2.1.0
requests==2.28.1
unknown-package-malware==1.0.0 # This should be flagged
sqlalchemy==1.4.32
"""

DEFAULT_ALLOWLIST_JSON = json.dumps({
    "flask": ["2.1.0", "2.2.0"],
    "requests": ["2.28.1", "2.29.0", "2.30.0"],
    "sqlalchemy": ["1.4.32", "2.0.0"]
}, indent=4)

# --- Helper Functions ---
def compute_sha256_from_string(content):
    if not content:
        return ""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

# --- Session State Initialization ---
if 'session_id' not in st.session_state or st.session_state.session_id is None:
    # Initialize environment once
    st.session_state.session_id, st.session_state.report_path = setup_analysis_environment()

st.session_state.setdefault('current_page', 'Home')
st.session_state.setdefault('python_code', DEFAULT_PYTHON_CODE)
st.session_state.setdefault('requirements_content', DEFAULT_REQUIREMENTS_CONTENT)
st.session_state.setdefault('dependency_allowlist_json_str', DEFAULT_ALLOWLIST_JSON)

try:
    st.session_state.setdefault('dependency_allowlist', json.loads(DEFAULT_ALLOWLIST_JSON))
except json.JSONDecodeError:
    st.session_state.setdefault('dependency_allowlist', {})

st.session_state.setdefault('generation_method', 'Copilot')
st.session_state.setdefault('human_review_level', 'Partial')
st.session_state.setdefault('analysis_done', False)
st.session_state.setdefault('df_all_static_findings', pd.DataFrame())
st.session_state.setdefault('df_dependency_findings', pd.DataFrame())
st.session_state.setdefault('df_consolidated_findings', pd.DataFrame())
st.session_state.setdefault('risk_summary_data', {})
st.session_state.setdefault('sdlc_recommendations_markdown', '')
st.session_state.setdefault('executive_summary_markdown', '')
st.session_state.setdefault('config_snapshot', {})
st.session_state.setdefault('evidence_manifest_filepath', None)
st.session_state.setdefault('zip_archive_filepath', None)

# --- Sidebar Navigation ---
with st.sidebar:
    page_selection = st.selectbox(
        "Navigation",
        [
            "Home",
            "1. Code & Context Input",
            "2. Static Analysis Findings",
            "3. Dependency Analysis",
            "4. Consolidated Risk & Controls",
            "5. Report Export"
        ],
        key="page_selector"
    )
    st.session_state.current_page = page_selection

st.markdown(f"# LAB 12 — AI Code-Generation Risk Analyzer")
st.markdown(f"**Secure SDLC Controls for Copilot, Claude, Agents, Tool Calling, and MCP**")
st.markdown(f"---")

# --- Page Logic ---

if st.session_state.current_page == "Home":
    st.markdown(f"## Welcome, Alice!")
    st.markdown(f"Persona: **Alice, an AppSec Engineer** at InnovateTech Solutions.")
    st.markdown(f"---")
    st.markdown(f"## Introduction: Securing AI-Generated Code at InnovateTech Solutions")
    st.markdown(f"Alice plays a crucial role in maintaining the security posture of InnovateTech Solutions' applications. With the adoption of AI-powered code generation tools, her team must ensure AI-generated code adheres to strict secure coding standards before integration into critical systems.")
    st.markdown(f"Today, Alice received a Python API handler that was largely generated by Copilot. Before this code can proceed to the next SDLC stage, Alice will perform a thorough security review. Her objectives:")
    st.markdown(f"- Detect hard-coded secrets")
    st.markdown(f"- Identify injection flaws (SQL/Command)")
    st.markdown(f"- Spot unsafe deserialization")
    st.markdown(f"- Verify dependencies against an allowlist")
    st.markdown(f"- Produce a consolidated, prioritized vulnerability report and remediation plan")
    st.markdown(f"This application simulates Alice's workflow using heuristic and AST-based static analysis, dependency verification, and a comprehensive vulnerability report for InnovateTech Solutions.")
    st.markdown(f"---")
    st.markdown(f"### Learning Objectives")
    st.markdown(f"By completing this lab, you will be able to:")
    st.markdown(f"1. Identify common failure modes in AI-generated code.")
    st.markdown(f"2. Detect insecure patterns using static heuristics.")
    st.markdown(f"3. Flag dependency hallucinations and supply-chain risks.")
    st.markdown(f"4. Define SDLC control gates for AI-assisted development.")
    st.markdown(f"5. Produce audit-ready code-gen risk reports.")

elif st.session_state.current_page == "1. Code & Context Input":
    st.markdown(f"## 1. Code & Context Input")
    st.markdown(f"Alice sets up the analysis by providing the AI-generated code and defining the generation context. This ensures a comprehensive security review tailored to the specific code artifacts.")
    st.markdown(f"### AI-Generated Python Code (`sample_insecure_code.py`)")
    st.markdown(f"Paste or upload your Python code here. This is the primary artifact Alice will analyze for security vulnerabilities.")

    st.session_state.python_code = st.text_area(
        "Python Code",
        value=st.session_state.python_code,
        height=400,
        key="python_code_input"
    )

    st.markdown(f"### Dependency Context")
    st.markdown(f"Provide the `requirements.txt` content (optional) and the `dependency_allowlist.json`. This helps Alice detect dependency hallucinations and supply-chain risks.")

    st.session_state.requirements_content = st.text_area(
        "Requirements.txt Content (Optional)",
        value=st.session_state.requirements_content,
        height=150,
        key="requirements_input"
    )

    st.session_state.dependency_allowlist_json_str = st.text_area(
        "Dependency Allowlist (JSON)",
        value=st.session_state.dependency_allowlist_json_str,
        height=200,
        key="allowlist_input"
    )
    
    # Update parsed allowlist and handle errors
    try:
        st.session_state.dependency_allowlist = json.loads(st.session_state.dependency_allowlist_json_str)
    except json.JSONDecodeError:
        st.error("Invalid JSON in Dependency Allowlist. Please check the format.")
        st.session_state.dependency_allowlist = {} 

    st.markdown(f"### Generation Context")
    st.markdown(f"Specify the AI method used to generate the code and the level of human review already applied. This context helps tailor security expectations.")

    generation_options = ["Copilot", "Claude", "Agent"]
    st.session_state.generation_method = st.selectbox(
        "AI Generation Method",
        generation_options,
        index=generation_options.index(st.session_state.generation_method) if st.session_state.generation_method in generation_options else 0,
        key="generation_method_selector"
    )

    review_options = ["None", "Partial", "Full"]
    st.session_state.human_review_level = st.selectbox(
        "Human Review Level",
        review_options,
        index=review_options.index(st.session_state.human_review_level) if st.session_state.human_review_level in review_options else 1,
        key="review_level_selector"
    )

    if st.button("Run Analysis", key="run_analysis_button"):
        if not st.session_state.python_code:
            st.warning("Please provide Python code to analyze.")
        else:
            with st.spinner("Running analysis... This might take a moment."):
                # Ensure run_id and report_path are set
                if st.session_state.session_id is None or st.session_state.report_path is None:
                    st.session_state.session_id, st.session_state.report_path = setup_analysis_environment()

                # 1. Update config snapshot
                st.session_state.config_snapshot = {
                    "run_id": st.session_state.session_id,
                    "timestamp": datetime.datetime.now().isoformat(),
                    "ai_generation_method": st.session_state.generation_method,
                    "human_review_level": st.session_state.human_review_level,
                    "code_hash_sha256": compute_sha256_from_string(st.session_state.python_code),
                    "requirements_hash_sha256": compute_sha256_from_string(st.session_state.requirements_content),
                    "allowlist_hash_sha256": compute_sha256_from_string(st.session_state.dependency_allowlist_json_str),
                }
                config_snapshot_filepath = os.path.join(st.session_state.report_path, "config_snapshot.json")
                with open(config_snapshot_filepath, "w") as f:
                    json.dump(st.session_state.config_snapshot, f, indent=4)

                # 2. Static Analysis
                st.session_state.df_all_static_findings = pd.DataFrame(scan_code_for_insecure_deserialization(st.session_state.python_code))

                # 3. Dependency Analysis
                st.session_state.df_dependency_findings = pd.DataFrame(detect_dependency_hallucinations(st.session_state.requirements_content, st.session_state.dependency_allowlist))
                
                # Persist dependency findings
                dependency_findings_filepath = os.path.join(st.session_state.report_path, "dependency_findings.json")
                st.session_state.df_dependency_findings.to_json(dependency_findings_filepath, orient="records", indent=4)

                # 4. Risk Scoring
                st.session_state.df_consolidated_findings, st.session_state.risk_summary_data = create_risk_scorecard(
                    st.session_state.df_all_static_findings,
                    st.session_state.df_dependency_findings
                )
                
                # Persist consolidated findings and risk scorecard
                consolidated_findings_filepath = os.path.join(st.session_state.report_path, "code_findings.json")
                st.session_state.df_consolidated_findings.to_json(consolidated_findings_filepath, orient="records", indent=4)
                
                risk_scorecard_filepath = os.path.join(st.session_state.report_path, "risk_scorecard.json")
                with open(risk_scorecard_filepath, "w") as f:
                    json.dump(st.session_state.risk_summary_data, f, indent=4)

                # 5. SDLC Control Recommendations & Executive Summary
                st.session_state.sdlc_recommendations_markdown = generate_sdlc_control_recommendations(st.session_state.risk_summary_data, st.session_state.df_consolidated_findings)
                sdlc_recommendations_filepath = os.path.join(st.session_state.report_path, "sdlc_control_recommendations.md")
                with open(sdlc_recommendations_filepath, "w") as f:
                    f.write(st.session_state.sdlc_recommendations_markdown)

                st.session_state.executive_summary_markdown = generate_executive_summary(st.session_state.session_id, st.session_state.risk_summary_data)
                executive_summary_filepath = os.path.join(st.session_state.report_path, "session12_executive_summary.md")
                with open(executive_summary_filepath, "w") as f:
                    f.write(st.session_state.executive_summary_markdown)

                # 6. Artifact Management
                st.session_state.evidence_manifest_filepath = create_evidence_manifest(st.session_state.report_path)
                st.session_state.zip_archive_filepath = bundle_artifacts_to_zip(st.session_state.report_path, st.session_state.session_id)

                st.session_state.analysis_done = True
                st.success("Analysis complete! See findings in the navigation sidebar.")

elif st.session_state.current_page == "2. Static Analysis Findings":
    st.markdown(f"## 2. Static Analysis Findings")
    st.markdown(f"Alice reviews the results of the heuristic and AST-based static analysis. This section highlights common insecure patterns like hard-coded secrets, unsafe execution calls, and injection vulnerabilities within the AI-generated code.")
    if st.session_state.analysis_done:
        if not st.session_state.df_all_static_findings.empty:
            st.markdown(f"### Identified Code Vulnerabilities")
            st.dataframe(st.session_state.df_all_static_findings[['risk_type', 'severity', 'confidence', 'line_num', 'code_snippet', 'description', 'remediation']])
        else:
            st.info("No static analysis findings detected in the provided code.")
    else:
        st.warning("Please run the analysis from the '1. Code & Context Input' page to see static analysis findings.")

elif st.session_state.current_page == "3. Dependency Analysis":
    st.markdown(f"## 3. Dependency Hallucination Detection")
    st.markdown(f"AI-generated code can sometimes hallucinate dependencies or suggest unapproved versions, posing supply-chain risks. Alice verifies declared dependencies against an approved allowlist to identify unknown or suspicious packages.")
    if st.session_state.analysis_done:
        if not st.session_state.df_dependency_findings.empty:
            st.markdown(f"### Dependency-Related Issues")
            st.dataframe(st.session_state.df_dependency_findings[['risk_type', 'severity', 'confidence', 'package', 'version', 'line_in_requirements_txt', 'description', 'remediation']])
        else:
            st.info("No dependency-related issues detected. All dependencies are approved and using allowed versions.")
    else:
        st.warning("Please run the analysis from the '1. Code & Context Input' page to see dependency findings.")

elif st.session_state.current_page == "4. Consolidated Risk & Controls":
    st.markdown(f"## 4. Consolidated Risk Scorecard & SDLC Controls")
    st.markdown(f"Alice needs a consolidated view of all findings, prioritized by risk, to guide remediation efforts. This section presents an overall risk summary and specific SDLC control recommendations based on the analysis.")
    if st.session_state.analysis_done:
        if not st.session_state.df_consolidated_findings.empty:
            st.markdown(f"### Overall Risk Summary")
            for key, value in st.session_state.risk_summary_data.items():
                st.markdown(f"- **{key.replace('_', ' ').title()}**: {value}")

            st.markdown(f"### Risk Score Calculation")
            st.markdown(f"Each finding's risk score is calculated as a product of its severity and confidence weights:")
            st.markdown(r"$$ \text{Risk Score} = \text{Severity Weight} \times \text{Confidence Weight} $$")
            st.markdown(r"where $\text{Severity Weight}$ is mapped as: Critical = 4, High = 3, Medium = 2, Low = 1.")
            st.markdown(r"and $\text{Confidence Weight}$ is mapped as: High = 1.0, Medium = 0.75, Low = 0.5.")
            st.markdown(f"### Consolidated Vulnerabilities (Sorted by Risk Score)")
            st.dataframe(st.session_state.df_consolidated_findings[[
                'risk_type', 'severity', 'confidence', 'risk_score',
                'line_num', 'package', 'code_snippet', 'description', 'remediation'
            ]])

            st.markdown(f"### SDLC Control Recommendations")
            st.markdown(f"Based on the identified risks, the following SDLC controls are recommended to integrate into InnovateTech Solutions' development pipeline:")
            st.markdown(st.session_state.sdlc_recommendations_markdown)
        else:
            st.info("No vulnerabilities detected in the AI-generated code or dependencies to generate a risk scorecard or SDLC controls.")
    else:
        st.warning("Please run the analysis from the '1. Code & Context Input' page to see the consolidated risk scorecard and SDLC controls.")

elif st.session_state.current_page == "5. Report Export":
    st.markdown(f"## 5. Report Export")
    st.markdown(f"For auditability and integration with other security systems, Alice generates a complete set of reports and an evidence manifest. All artifacts are hashed and bundled into a single ZIP archive.")
    if st.session_state.analysis_done:
        st.markdown(f"### Executive Summary")
        st.markdown(st.session_state.executive_summary_markdown)

        st.markdown(f"### Download Analysis Artifacts")
        st.markdown(f"All generated reports and evidence for session `{st.session_state.session_id}` are available for download:")

        # Download button for the full zip archive
        if st.session_state.zip_archive_filepath and os.path.exists(st.session_state.zip_archive_filepath):
            with open(st.session_state.zip_archive_filepath, "rb") as fp:
                st.download_button(
                    label=f"Download All Reports (Session_{st.session_state.session_id}.zip)",
                    data=fp,
                    file_name=f"Session_{st.session_state.session_id}.zip",
                    mime="application/zip",
                    key="download_all_zip"
                )

        st.markdown(f"---")
        st.markdown(f"### Individual Report Files")
        st.markdown(f"You can also download individual files generated during the analysis:")

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
                        key=f"download_{filename.replace('.', '_')}"
                    )
            else:
                st.info(f"File not yet generated: {filename}")

    else:
        st.warning("Please run the analysis from the '1. Code & Context Input' page to generate reports for export.")
