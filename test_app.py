
from streamlit.testing.v1 import AppTest
import unittest.mock as mock
import pandas as pd
import json
import os
import sys

# Mock return values for source functions
MOCK_STATIC_FINDINGS = [
    {'risk_type': 'Hardcoded Secret', 'severity': 'Critical', 'confidence': 'High', 'line_num': 7, 'code_snippet': 'API_KEY = "sk_prod_12345"', 'description': 'Hardcoded API key detected.', 'remediation': 'Store API key in environment variables or a secure secret management system.'},
    {'risk_type': 'Unsafe Eval', 'severity': 'Critical', 'confidence': 'High', 'line_num': 24, 'code_snippet': 'return eval(expr)', 'description': 'Unsafe use of eval() detected, potentially leading to arbitrary code execution.', 'remediation': 'Avoid eval(); use ast.literal_eval for safe expression evaluation or implement a custom, safe parser.'},
]

MOCK_DEPENDENCY_FINDINGS = [
    {'risk_type': 'Unknown Package', 'severity': 'High', 'confidence': 'High', 'package': 'unknown-package-malware', 'version': '1.0.0', 'line_in_requirements_txt': 4, 'description': 'Package not found in allowlist or known malicious.', 'remediation': 'Investigate package; remove if unauthorized or malicious. Only use approved dependencies.'}
]

MOCK_RISK_SUMMARY = {
    "total_findings": 3,
    "critical_findings": 2,
    "high_findings": 1,
    "medium_findings": 0,
    "low_findings": 0,
    "overall_risk_score": 11.0,
    "static_analysis_findings_count": 2,
    "dependency_analysis_findings_count": 1
}

MOCK_CONSOLIDATED_FINDINGS_DATA = [
    {'risk_type': 'Hardcoded Secret', 'severity': 'Critical', 'confidence': 'High', 'risk_score': 4.0, 'line_num': 7, 'package': None, 'code_snippet': 'API_KEY = "sk_prod_12345"', 'description': 'Hardcoded API key detected.', 'remediation': 'Store API key in environment variables or a secure secret management system.'},
    {'risk_type': 'Unsafe Eval', 'severity': 'Critical', 'confidence': 'High', 'risk_score': 4.0, 'line_num': 24, 'package': None, 'code_snippet': 'return eval(expr)', 'description': 'Unsafe use of eval() detected, potentially leading to arbitrary code execution.', 'remediation': 'Avoid eval(); use ast.literal_eval for safe expression evaluation or implement a custom, safe parser.'},
    {'risk_type': 'Unknown Package', 'severity': 'High', 'confidence': 'High', 'risk_score': 3.0, 'line_num': None, 'package': 'unknown-package-malware', 'code_snippet': None, 'description': 'Package not found in allowlist or known malicious.', 'remediation': 'Investigate package; remove if unauthorized or malicious. Only use approved dependencies.'}
]
MOCK_CONSOLIDATED_FINDINGS = pd.DataFrame(MOCK_CONSOLIDATED_FINDINGS_DATA)

MOCK_SDLC_RECOMMENDATIONS = "Mock SDLC recommendations markdown."
MOCK_EXECUTIVE_SUMMARY = "Mock Executive Summary markdown."
MOCK_SESSION_ID = "test_session_123"
MOCK_REPORT_PATH = "/tmp/test_reports/test_session_123" # This directory will not actually be created due to mocks

# --- Mocking the 'source' module and OS interactions ---
class MockSource:
    def setup_analysis_environment():
        return MOCK_SESSION_ID, MOCK_REPORT_PATH
    def scan_code_for_insecure_deserialization(code):
        if "API_KEY" in code:
            return MOCK_STATIC_FINDINGS
        return []
    def detect_dependency_hallucinations(requirements, allowlist):
        if "unknown-package-malware" in requirements:
            return MOCK_DEPENDENCY_FINDINGS
        return []
    def create_risk_scorecard(static_findings_df, dependency_findings_df):
        if static_findings_df.empty and dependency_findings_df.empty:
            return pd.DataFrame(), {}
        return MOCK_CONSOLIDATED_FINDINGS, MOCK_RISK_SUMMARY
    def generate_sdlc_control_recommendations(risk_summary, consolidated_findings):
        if not consolidated_findings.empty:
            return MOCK_SDLC_RECOMMENDATIONS
        return "No specific recommendations as no findings were detected."
    def generate_executive_summary(session_id, risk_summary):
        if risk_summary:
            return MOCK_EXECUTIVE_SUMMARY
        return "Executive Summary: No risks detected."
    def create_evidence_manifest(report_path):
        return os.path.join(report_path, "evidence_manifest.json")
    def bundle_artifacts_to_zip(report_path, session_id):
        return os.path.join(report_path, f"Session_{session_id}.zip")
    def compute_sha256_from_string(content):
        return "mock_sha256_hash"

# Temporarily add MockSource to sys.modules under the name 'source'
# This ensures that when app.py does `from source import *`, it imports from our mock.
sys.modules['source'] = MockSource

# Default constants from the app code
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


# --- Test Functions ---

# Decorator to apply common patches for all tests
def patch_all(func):
    @mock.patch("os.makedirs")
    @mock.patch("os.path.exists", return_value=True) # Assume files exist for download buttons, etc.
    @mock.patch("builtins.open", mock.mock_open(read_data="dummy file content")) # Mock file reads/writes
    @mock.patch("hashlib.sha256")
    @mock.patch("datetime.datetime")
    def wrapper(mock_dt, mock_sha256, mock_open, mock_exists, mock_makedirs):
        mock_dt.now.return_value = mock.MagicMock(isoformat=lambda: '2026-01-22T15:00:00.000000') # Consistent timestamp
        mock_sha256.return_value.hexdigest.return_value = "mock_sha256_hash" # Consistent hash
        return func()
    return wrapper

@patch_all
def test_home_page():
    at = AppTest.from_file("app.py").run()
    assert at.title[0].value == "QuLab: Lab 12: AI Code-Generation Risk Analyzer"
    assert "Welcome, Alice!" in at.markdown[4].value
    assert "Introduction: Securing AI-Generated Code at InnovateTech Solutions" in at.markdown[6].value
    assert "Learning Objectives" in at.markdown[11].value

@patch_all
def test_code_context_input_defaults():
    at = AppTest.from_file("app.py").run()
    at.selectbox[0].set_value("1. Code & Context Input").run()

    assert at.text_area[0].value == DEFAULT_PYTHON_CODE
    assert at.text_area[1].value == DEFAULT_REQUIREMENTS_CONTENT
    assert at.text_area[2].value == DEFAULT_ALLOWLIST_JSON
    assert at.selectbox[1].value == "Copilot"
    assert at.selectbox[2].value == "Partial"

@patch_all
def test_run_analysis_success():
    at = AppTest.from_file("app.py").run()
    at.selectbox[0].set_value("1. Code & Context Input").run()

    # Ensure code and requirements trigger findings for comprehensive test
    at.text_area[0].set_value("def my_func(): API_KEY = 'secret'").run()
    at.text_area[1].set_value("unknown-package-malware==1.0.0").run()
    at.button[0].click().run()

    assert at.success[0].value == "Analysis complete! See findings in the navigation sidebar."
    assert at.session_state["analysis_done"] is True
    assert not at.session_state["df_all_static_findings"].empty
    assert not at.session_state["df_dependency_findings"].empty
    assert not at.session_state["df_consolidated_findings"].empty
    assert at.session_state["risk_summary_data"] == MOCK_RISK_SUMMARY

@patch_all
def test_run_analysis_no_code():
    at = AppTest.from_file("app.py").run()
    at.selectbox[0].set_value("1. Code & Context Input").run()

    at.text_area[0].set_value("").run() # Clear code input
    at.button[0].click().run()

    assert at.warning[0].value == "Please provide Python code to analyze."
    assert at.session_state["analysis_done"] is False

@patch_all
def test_run_analysis_invalid_allowlist_json():
    at = AppTest.from_file("app.py").run()
    at.selectbox[0].set_value("1. Code & Context Input").run()

    at.text_area[2].set_value("not a valid json").run() # Provide invalid JSON
    at.button[0].click().run()

    assert at.error[0].value == "Invalid JSON in Dependency Allowlist. Please check the format."
    assert at.session_state["dependency_allowlist"] == {}
    # Analysis still proceeds with default/empty allowlist if JSON is invalid
    assert at.success[0].value == "Analysis complete! See findings in the navigation sidebar."
    assert at.session_state["analysis_done"] is True


@patch_all
def test_static_analysis_findings_page_no_analysis():
    at = AppTest.from_file("app.py").run()
    at.selectbox[0].set_value("2. Static Analysis Findings").run()

    assert at.warning[0].value == "Please run the analysis from the '1. Code & Context Input' page to see static analysis findings."

@patch_all
def test_static_analysis_findings_page_with_findings():
    at = AppTest.from_file("app.py").run()
    at.selectbox[0].set_value("1. Code & Context Input").run()
    at.text_area[0].set_value("API_KEY = 'secret'").run() # Ensure code triggers static findings
    at.button[0].click().run() # Run analysis

    at.selectbox[0].set_value("2. Static Analysis Findings").run()

    assert not at.session_state["df_all_static_findings"].empty
    assert at.dataframe[0].row(0)._cells[0].value == MOCK_STATIC_FINDINGS[0]['risk_type']
    assert at.dataframe[0].row(1)._cells[0].value == MOCK_STATIC_FINDINGS[1]['risk_type']

@patch_all
def test_static_analysis_findings_page_no_actual_findings():
    with mock.patch.object(sys.modules['source'], 'scan_code_for_insecure_deserialization', return_value=[]):
        at = AppTest.from_file("app.py").run()
        at.selectbox[0].set_value("1. Code & Context Input").run()
        at.text_area[0].set_value("def safe_code(): pass").run() # Code with no findings
        at.button[0].click().run()

        at.selectbox[0].set_value("2. Static Analysis Findings").run()
        assert at.info[0].value == "No static analysis findings detected in the provided code."

@patch_all
def test_dependency_analysis_page_no_analysis():
    at = AppTest.from_file("app.py").run()
    at.selectbox[0].set_value("3. Dependency Analysis").run()

    assert at.warning[0].value == "Please run the analysis from the '1. Code & Context Input' page to see dependency findings."

@patch_all
def test_dependency_analysis_page_with_findings():
    at = AppTest.from_file("app.py").run()
    at.selectbox[0].set_value("1. Code & Context Input").run()
    at.text_area[1].set_value("unknown-package-malware==1.0.0").run() # Ensure requirements trigger dependency findings
    at.button[0].click().run() # Run analysis

    at.selectbox[0].set_value("3. Dependency Analysis").run()

    assert not at.session_state["df_dependency_findings"].empty
    assert at.dataframe[0].row(0)._cells[0].value == MOCK_DEPENDENCY_FINDINGS[0]['risk_type']

@patch_all
def test_dependency_analysis_page_no_actual_findings():
    with mock.patch.object(sys.modules['source'], 'detect_dependency_hallucinations', return_value=[]):
        at = AppTest.from_file("app.py").run()
        at.selectbox[0].set_value("1. Code & Context Input").run()
        at.text_area[1].set_value("flask==2.1.0").run() # Safe requirements
        at.button[0].click().run()

        at.selectbox[0].set_value("3. Dependency Analysis").run()
        assert at.info[0].value == "No dependency-related issues detected. All dependencies are approved and using allowed versions."

@patch_all
def test_consolidated_risk_page_no_analysis():
    at = AppTest.from_file("app.py").run()
    at.selectbox[0].set_value("4. Consolidated Risk & Controls").run()

    assert at.warning[0].value == "Please run the analysis from the '1. Code & Context Input' page to see the consolidated risk scorecard and SDLC controls."

@patch_all
def test_consolidated_risk_page_with_findings():
    at = AppTest.from_file("app.py").run()
    at.selectbox[0].set_value("1. Code & Context Input").run()
    at.text_area[0].set_value("API_KEY = 'secret'").run() # Ensure code triggers static findings
    at.text_area[1].set_value("unknown-package-malware==1.0.0").run() # Ensure requirements trigger dependency findings
    at.button[0].click().run() # Run analysis

    at.selectbox[0].set_value("4. Consolidated Risk & Controls").run()

    assert at.markdown[6].value.startswith("- **Total Findings**: 3") # Check risk summary
    assert at.markdown[7].value.startswith("- **Critical Findings**: 2")
    assert not at.session_state["df_consolidated_findings"].empty
    assert at.dataframe[0].row(0)._cells[0].value == MOCK_CONSOLIDATED_FINDINGS_DATA[0]['risk_type']
    assert at.markdown[16].value == MOCK_SDLC_RECOMMENDATIONS # Check SDLC recommendations markdown

@patch_all
def test_consolidated_risk_page_no_actual_findings():
    with mock.patch.object(sys.modules['source'], 'scan_code_for_insecure_deserialization', return_value=[]), \
         mock.patch.object(sys.modules['source'], 'detect_dependency_hallucinations', return_value=[]), \
         mock.patch.object(sys.modules['source'], 'create_risk_scorecard', return_value=(pd.DataFrame(), {})):
        at = AppTest.from_file("app.py").run()
        at.selectbox[0].set_value("1. Code & Context Input").run()
        at.text_area[0].set_value("def safe_code(): pass").run()
        at.text_area[1].set_value("flask==2.1.0").run()
        at.button[0].click().run()

        at.selectbox[0].set_value("4. Consolidated Risk & Controls").run()
        assert at.info[0].value == "No vulnerabilities detected in the AI-generated code or dependencies to generate a risk scorecard or SDLC controls."

@patch_all
def test_report_export_page_no_analysis():
    at = AppTest.from_file("app.py").run()
    at.selectbox[0].set_value("5. Report Export").run()

    assert at.warning[0].value == "Please run the analysis from the '1. Code & Context Input' page to generate reports for export."

@patch_all
def test_report_export_page_after_analysis():
    at = AppTest.from_file("app.py").run()
    at.selectbox[0].set_value("1. Code & Context Input").run()
    at.text_area[0].set_value("API_KEY = 'secret'").run() # Ensure code triggers static findings
    at.text_area[1].set_value("unknown-package-malware==1.0.0").run() # Ensure requirements trigger dependency findings
    at.button[0].click().run() # Run analysis

    at.selectbox[0].set_value("5. Report Export").run()

    assert at.markdown[3].value == MOCK_EXECUTIVE_SUMMARY
    assert at.download_button[0].label == f"Download All Reports (Session_{MOCK_SESSION_ID}.zip)"
    # Check individual file download buttons
    output_files = [
        "code_findings.json",
        "dependency_findings.json",
        "risk_scorecard.json",
        "sdlc_control_recommendations.md",
        "session12_executive_summary.md",
        "config_snapshot.json",
        "evidence_manifest.json",
    ]
    for i, filename in enumerate(output_files):
        # +1 because the first download button is for the zip archive
        assert at.download_button[i+1].label == f"Download {filename}"
