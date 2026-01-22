import ast
import re
import json
import os
import zipfile
import hashlib
import pandas as pd
import datetime
import uuid
from IPython.display import display
def setup_analysis_environment(base_report_dir="reports/session12"):
    """
    Sets up the output directory for analysis artifacts.
    Generates a unique run_id for the current analysis session.
    """
    run_id = f"{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{str(uuid.uuid4())[:8]}"
    report_path = os.path.join(base_report_dir, run_id)
    os.makedirs(report_path, exist_ok=True)
    print(f"Analysis reports will be saved to: {report_path}")
    return run_id, report_path


def create_sample_files(run_id, report_path):
    """
    Creates sample files required for the analysis in the report_path.
    In a real scenario, these would be uploaded or fetched from source control or CI artifacts.
    """
    # Create sample_insecure_code.py (AI-generated style with intentional flaws)
    sample_code_content = """
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
    code_filepath = os.path.join(report_path, "sample_insecure_code.py")
    with open(code_filepath, "w") as f:
        f.write(sample_code_content)
    print(f"Created {code_filepath}")

    # Create sample requirements.txt
    requirements_content = """
flask==2.1.0
requests==2.28.1
unknown-package-malware==1.0.0 # This should be flagged
sqlalchemy==1.4.32
"""
    requirements_filepath = os.path.join(report_path, "requirements.txt")
    with open(requirements_filepath, "w") as f:
        f.write(requirements_content)
    print(f"Created {requirements_filepath}")

    # Create dependency_allowlist.json
    allowlist_content = {
        "flask": ["2.1.0", "2.2.0"],
        "requests": ["2.28.1", "2.29.0", "2.30.0"],
        "sqlalchemy": ["1.4.32", "2.0.0"]
    }
    allowlist_filepath = os.path.join(report_path, "dependency_allowlist.json")
    with open(allowlist_filepath, "w") as f:
        json.dump(allowlist_content, f, indent=4)
    print(f"Created {allowlist_filepath}")

    return code_filepath, requirements_filepath, allowlist_filepath


# Execute setup and file creation immediately to validate functions
run_id, report_path = setup_analysis_environment()
code_filepath, requirements_filepath, allowlist_filepath = create_sample_files(run_id, report_path)

# Load file contents
with open(code_filepath, 'r') as f:
    python_code = f.read()
with open(requirements_filepath, 'r') as f:
    requirements_content = f.read()
with open(allowlist_filepath, 'r') as f:
    dependency_allowlist = json.load(f)

# Store configuration snapshot
config_snapshot = {
    "run_id": run_id,
    "code_filepath": code_filepath,
    "requirements_filepath": requirements_filepath,
    "allowlist_filepath": allowlist_filepath,
    "timestamp": datetime.datetime.now().isoformat(),
    "git_commit": "N/A",
    "ai_generation_method": "Copilot",
    "human_review_level": "Partial"
}
with open(os.path.join(report_path, "config_snapshot.json"), "w") as f:
    json.dump(config_snapshot, f, indent=4)

print("\n--- Loaded Artifacts ---")
print(f"AI-generated Python Code (first 100 chars):\n{python_code[:100]}...")
print(f"\nRequirements Content:\n{requirements_content.strip()}")
print(f"\nDependency Allowlist:\n{json.dumps(dependency_allowlist, indent=2)}")
class VulnerabilityDetector(ast.NodeVisitor):
    """
    AST visitor to detect various insecure patterns in Python code.
    """
    def __init__(self, code_lines):
        self.findings = []
        self.code_lines = code_lines
        self.formatted_vars = set()  # Track variables built via f-strings/concat/format

    def _add_finding(self, risk_type, severity, confidence, line_num, code_snippet, description, remediation):
        """Helper to add a finding to the list."""
        self.findings.append({
            "risk_type": risk_type,
            "severity": severity,
            "confidence": confidence,
            "line_num": line_num,
            "code_snippet": (code_snippet or '').strip(),
            "description": description,
            "remediation": remediation
        })

    def visit_Assign(self, node):
        # Track variables constructed with formatting (for later injection checks)
        def is_formatted_value(val):
            return (
                isinstance(val, ast.JoinedStr) or  # f-string
                isinstance(val, ast.BinOp) or      # concatenation
                (isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute) and val.func.attr == 'format')
            )
        try:
            if is_formatted_value(node.value):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self.formatted_vars.add(t.id)
        except Exception:
            pass
        self.generic_visit(node)

    def visit_Call(self, node):
        """Detects calls to unsafe functions like eval/exec."""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in ["eval", "exec"]:
                line_num = getattr(node, 'lineno', 1)
                self._add_finding(
                    risk_type="Unsafe_Execution",
                    severity="Critical",
                    confidence="High",
                    line_num=line_num,
                    code_snippet=self.code_lines[line_num - 1] if line_num - 1 < len(self.code_lines) else '',
                    description=f"Direct call to unsafe function '{func_name}'. This can lead to arbitrary code execution if user-controlled input is passed.",
                    remediation="Avoid using eval/exec with untrusted input. Consider safer alternatives like ast.literal_eval for parsing literals, or a strict allowlist/sandbox approach if dynamic execution is unavoidable."
                )
        self.generic_visit(node)

    def detect_hardcoded_secrets(self, code_string):
        """
        Detects hard-coded secrets by scanning Assign/AnnAssign nodes with string constants
        where the variable name indicates sensitive content.
        """
        try:
            tree = ast.parse(code_string)
        except SyntaxError:
            return

        sensitive_keywords = re.compile(r"(api|secret|token|passwd|password|key)", re.IGNORECASE)
        benign_names = re.compile(r"^(debug|user_id_prefix|some_id|test|placeholder)$", re.IGNORECASE)

        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                # Determine targets
                targets = []
                if isinstance(node, ast.Assign):
                    targets = [t for t in node.targets if isinstance(t, ast.Name)]
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    targets = [node.target]

                value_node = node.value if hasattr(node, 'value') else None
                if not targets or not isinstance(value_node, ast.Constant) or not isinstance(value_node.value, str):
                    continue

                for t in targets:
                    var_name = t.id
                    if benign_names.search(var_name):
                        continue
                    if sensitive_keywords.search(var_name):
                        literal = value_node.value
                        if len(literal) >= 8:  # heuristic length threshold
                            line_num = getattr(node, 'lineno', 1)
                            severity = "Critical" if re.search(r"(api|token|secret|key|passwd|password)", var_name, re.IGNORECASE) else "High"
                            self._add_finding(
                                risk_type="Secrets_Hardcoded",
                                severity=severity,
                                confidence="High",
                                line_num=line_num,
                                code_snippet=self.code_lines[line_num - 1] if line_num - 1 < len(self.code_lines) else '',
                                description=f"Hard-coded secret detected in variable '{var_name}'.",
                                remediation="Store secrets in environment variables, a dedicated secret manager (AWS Secrets Manager, HashiCorp Vault), or an encrypted configuration. Avoid committing secrets to version control."
                            )

    def get_findings(self):
        return self.findings


def scan_code_for_secrets_and_unsafe_calls(python_code):
    """Orchestrates static analysis for secrets and unsafe function calls."""
    code_lines = python_code.splitlines()
    tree = ast.parse(python_code)

    detector = VulnerabilityDetector(code_lines)
    detector.visit(tree)  # Visit AST for eval/exec and track formatted vars
    detector.detect_hardcoded_secrets(python_code)  # AST-based secret detection

    return detector.get_findings()


# --- Execution ---
print("--- Scanning for Hardcoded Secrets and Unsafe Execution ---")
secrets_and_unsafe_findings = scan_code_for_secrets_and_unsafe_calls(python_code)
df_secrets_and_unsafe = pd.DataFrame(secrets_and_unsafe_findings)

if not df_secrets_and_unsafe.empty:
    print(f"Found {len(df_secrets_and_unsafe)} potential vulnerabilities:")
    display(df_secrets_and_unsafe[['risk_type', 'severity', 'confidence', 'line_num', 'code_snippet', 'description']])
else:
    print("No hard-coded secrets or unsafe eval/exec calls detected.")
class InjectionDetector(VulnerabilityDetector):
    """
    Extends VulnerabilityDetector for SQL and Command Injection detection.
    """
    def _is_formatted(self, node):
        return (
            isinstance(node, ast.JoinedStr) or
            isinstance(node, ast.BinOp) or
            (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'format')
        )

    def visit_Call(self, node):
        # Preserve base detections (unsafe eval/exec) and formatted var tracking
        super().visit_Call(node)

        # Detect SQL Injection via string formatting in database calls
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["execute", "executemany"]:
            risky = False
            # Check direct formatted arguments
            for arg in node.args:
                if self._is_formatted(arg):
                    risky = True
                    break
                if isinstance(arg, ast.Name) and arg.id in self.formatted_vars:
                    risky = True
                    break
            if risky:
                line_num = getattr(node, 'lineno', 1)
                self._add_finding(
                    risk_type="SQL_Injection",
                    severity="Critical",
                    confidence="Medium",
                    line_num=line_num,
                    code_snippet=self.code_lines[line_num - 1] if line_num - 1 < len(self.code_lines) else '',
                    description="Potential SQL Injection due to string formatting (f-string, .format(), or concatenation) used in or prior to database query execution. Use parameterized queries.",
                    remediation="Always use parameterized queries (e.g., cursor.execute('SELECT * FROM users WHERE username = ?', (username,)) for SQLite) instead of string formatting."
                )

        # Detect Command Injection via subprocess calls with shell=True
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["run", "call", "check_call", "Popen"]:
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                has_shell_true = any((kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True) for kw in node.keywords)
                if has_shell_true:
                    for arg in node.args:
                        if self._is_formatted(arg) or (isinstance(arg, ast.Name) and arg.id in self.formatted_vars):
                            line_num = getattr(node, 'lineno', 1)
                            self._add_finding(
                                risk_type="Command_Injection",
                                severity="High",
                                confidence="Medium",
                                line_num=line_num,
                                code_snippet=self.code_lines[line_num - 1] if line_num - 1 < len(self.code_lines) else '',
                                description="Potential Command Injection detected. subprocess uses shell=True and constructs command using string formatting, allowing arbitrary command execution.",
                                remediation="Avoid shell=True with user-controlled input. Pass commands as a list (e.g., subprocess.run(['ls', '-l', filename])). If shell=True is necessary, strictly validate and sanitize input."
                            )
                            break
        self.generic_visit(node)


def scan_code_for_injection_vulnerabilities(python_code):
    """
    Orchestrates the static analysis for SQL and Command Injection.
    """
    code_lines = python_code.splitlines()
    tree = ast.parse(python_code)

    detector = InjectionDetector(code_lines)
    detector.visit(tree)

    return detector.get_findings()


# --- Execution ---
print("\n--- Scanning for SQL and Command Injection ---")
injection_findings = scan_code_for_injection_vulnerabilities(python_code)
df_injection = pd.DataFrame(injection_findings)

if not df_injection.empty:
    print(f"Found {len(df_injection)} potential injection vulnerabilities:")
    display(df_injection[['risk_type', 'severity', 'confidence', 'line_num', 'code_snippet', 'description']])
else:
    print("No SQL or Command Injection patterns detected.")
class DeserializationDetector(InjectionDetector):
    """
    Extends InjectionDetector for Insecure Deserialization detection.
    """
    def visit_Call(self, node):
        # Preserve parent detections (unsafe exec, SQL/Command injection)
        super().visit_Call(node)

        # Detect insecure deserialization (e.g., pickle.loads)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "loads":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                line_num = getattr(node, 'lineno', 1)
                self._add_finding(
                    risk_type="Insecure_Deserialization",
                    severity="Critical",
                    confidence="High",
                    line_num=line_num,
                    code_snippet=self.code_lines[line_num - 1] if line_num - 1 < len(self.code_lines) else '',
                    description="Insecure deserialization detected using pickle.loads(). Deserializing untrusted data can lead to arbitrary code execution.",
                    remediation="Avoid deserializing untrusted data using pickle. Use safer, schema-validated formats like JSON or Protocol Buffers. If deserialization is necessary, enforce integrity/authentication and strict validation."
                )
        self.generic_visit(node)


def scan_code_for_insecure_deserialization(python_code):
    """Orchestrates static analysis for Insecure Deserialization and consolidates all static findings."""
    code_lines = python_code.splitlines()
    tree = ast.parse(python_code)

    detector = DeserializationDetector(code_lines)
    detector.visit(tree)

    # Also include hardcoded secrets
    detector.detect_hardcoded_secrets(python_code)

    return detector.get_findings()


# --- Execution ---
print("\n--- Scanning for Insecure Deserialization and Consolidating All Static Findings ---")
all_static_findings = scan_code_for_insecure_deserialization(python_code)
df_all_static_findings = pd.DataFrame(all_static_findings).drop_duplicates(
    subset=['line_num', 'risk_type', 'code_snippet', 'description']
).reset_index(drop=True)

if not df_all_static_findings.empty:
    print(f"Found {len(df_all_static_findings)} unique static analysis vulnerabilities:")
    display(df_all_static_findings[['risk_type', 'severity', 'confidence', 'line_num', 'code_snippet', 'description']])
else:
    print("No insecure deserialization or other static analysis patterns detected.")
def parse_requirements(requirements_content):
    """Parses requirements.txt content into a list of dependency dicts, stripping inline comments."""
    dependencies = []
    for line in requirements_content.splitlines():
        raw = line
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Strip inline comments
        if '#' in line:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
        match = re.match(r"([a-zA-Z0-9._-]+)\s*(==|>=|<=|>|<|~=)?\s*([^\s]+)?", line)
        if match:
            pkg_name = match.group(1)
            operator = match.group(2) if match.group(2) else "=="
            version = (match.group(3) or "").strip()
            dependencies.append({"package": pkg_name, "version": version, "operator": operator, "line": raw.strip()})
    return dependencies


def detect_dependency_hallucinations(requirements_content, dependency_allowlist):
    """Compares dependencies from requirements.txt against an approved allowlist."""
    parsed_dependencies = parse_requirements(requirements_content)
    dependency_findings = []

    for dep in parsed_dependencies:
        pkg_name_lower = dep['package'].lower()
        version = dep['version']
        line = dep['line']

        if pkg_name_lower not in dependency_allowlist:
            dependency_findings.append({
                "risk_type": "Dependency_Hallucination",
                "severity": "Critical",
                "confidence": "High",
                "package": dep['package'],
                "version": version if version else "N/A",
                "line_in_requirements_txt": line,
                "description": f"Unknown or unapproved package '{dep['package']}' detected. This could be a hallucinated dependency or a malicious package.",
                "remediation": "Investigate this package. If legitimate, add it to the approved dependency_allowlist.json with specific versions. If not, remove it from requirements.txt."
            })
        else:
            allowed_versions = dependency_allowlist.get(pkg_name_lower, [])
            if version and version not in allowed_versions:
                dependency_findings.append({
                    "risk_type": "Dependency_Version_Mismatch",
                    "severity": "Medium",
                    "confidence": "High",
                    "package": dep['package'],
                    "version": version,
                    "line_in_requirements_txt": line,
                    "description": f"Approved package '{dep['package']}' found, but version '{version}' is not in the allowlist. Allowed versions: {', '.join(allowed_versions)}.",
                    "remediation": f"Update the package version to an approved one (e.g., {allowed_versions[0] if allowed_versions else 'N/A'}) or get approval for the new version and update dependency_allowlist.json."
                })
    return dependency_findings


# --- Execution ---
print("\n--- Detecting Dependency Hallucinations and Unapproved Versions ---")
dependency_findings_list = detect_dependency_hallucinations(requirements_content, dependency_allowlist)
df_dependency_findings = pd.DataFrame(dependency_findings_list)

if not df_dependency_findings.empty:
    print(f"Found {len(df_dependency_findings)} dependency-related issues:")
    display(df_dependency_findings[['risk_type', 'severity', 'confidence', 'package', 'version', 'line_in_requirements_txt', 'description']])
else:
    print("All dependencies are approved and using allowed versions.")
def create_risk_scorecard(static_findings_df, dependency_findings_df):
    """Consolidates all findings and generates a risk scorecard summary."""
    all_findings_list = []
    if static_findings_df is not None and not static_findings_df.empty:
        all_findings_list.extend(static_findings_df.to_dict(orient='records'))
    if dependency_findings_df is not None and not dependency_findings_df.empty:
        all_findings_list.extend(dependency_findings_df.to_dict(orient='records'))

    if not all_findings_list:
        return pd.DataFrame(), {}

    df_all_findings = pd.DataFrame(all_findings_list)

    # Define numerical mapping for severity and confidence for risk calculation
    severity_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    confidence_map = {"High": 1.0, "Medium": 0.75, "Low": 0.5}

    df_all_findings['severity_score'] = df_all_findings['severity'].map(severity_map).fillna(0)
    df_all_findings['confidence_score'] = df_all_findings['confidence'].map(confidence_map).fillna(0)
    df_all_findings['risk_score'] = df_all_findings['severity_score'] * df_all_findings['confidence_score']

    # Determine highest severity overall correctly using numeric mapping
    if not df_all_findings.empty:
        idx = df_all_findings['severity_score'].idxmax()
        highest_sev = df_all_findings.loc[idx, 'severity'] if pd.notna(idx) else "None"
    else:
        highest_sev = "None"

    risk_summary = {
        "total_findings": int(len(df_all_findings)),
        "findings_by_severity": df_all_findings['severity'].value_counts().to_dict(),
        "findings_by_risk_type": df_all_findings['risk_type'].value_counts().to_dict(),
        "max_risk_score": float(df_all_findings['risk_score'].max()) if not df_all_findings.empty else 0.0,
        "average_risk_score": float(df_all_findings['risk_score'].mean()) if not df_all_findings.empty else 0.0,
        "highest_severity_overall": highest_sev,
    }

    # Sort findings by risk score (descending)
    df_all_findings_sorted = df_all_findings.sort_values(by='risk_score', ascending=False).reset_index(drop=True)

    return df_all_findings_sorted, risk_summary


# --- Execution ---
print("\n--- Generating Consolidated Risk Scorecard ---")
df_consolidated_findings, risk_summary_data = create_risk_scorecard(df_all_static_findings, df_dependency_findings)

if not df_consolidated_findings.empty:
    print(f"Total Unique Findings: {len(df_consolidated_findings)}")
    print("\nOverall Risk Summary:")
    for key, value in risk_summary_data.items():
        print(f"- {key.replace('_', ' ').title()}: {value}")

    print("\nTop 10 Consolidated Vulnerabilities (sorted by Risk Score):")
    display(df_consolidated_findings[[
        'risk_type', 'severity', 'confidence', 'risk_score',
        'line_num', 'package', 'code_snippet', 'description'
    ]].head(10))

    # Save consolidated findings to JSON
    consolidated_findings_filepath = os.path.join(report_path, "code_findings.json")
    df_consolidated_findings.to_json(consolidated_findings_filepath, orient="records", indent=4)
    print(f"\nConsolidated findings saved to: {consolidated_findings_filepath}")

    # Save risk scorecard summary to JSON
    risk_scorecard_filepath = os.path.join(report_path, "risk_scorecard.json")
    with open(risk_scorecard_filepath, "w") as f:
        json.dump(risk_summary_data, f, indent=4)
    print(f"Risk scorecard summary saved to: {risk_scorecard_filepath}")
else:
    print("No vulnerabilities detected in the AI-generated code or dependencies.")
def generate_sdlc_control_recommendations(risk_summary, consolidated_findings_df):
    """Generates SDLC control recommendations based on the analysis findings."""
    recommendations = []

    if risk_summary.get("highest_severity_overall") == "Critical":
        recommendations.append("- Mandatory Human Review Gate: Implement a manual security review gate for all AI-generated code before QA or production.")
        recommendations.append("- Automated SAST Integration: Integrate SAST into CI/CD to block builds with critical/high findings.")
        recommendations.append("- Enhanced Developer Training: Provide secure coding training focused on AI-generated code pitfalls.")
    elif risk_summary.get("highest_severity_overall") == "High":
        recommendations.append("- Mandatory Peer Review with Security Checklist for all AI-generated code.")
        recommendations.append("- SAST in CI/CD (Advisory Mode): Provide feedback for high-severity issues (block only critical).")
    else:
        recommendations.append("- Regular Security Scans: Run routine static analysis on all codebases, including AI-generated components.")
        recommendations.append("- Review Dependency Management: Maintain and enforce an approved dependency allowlist.")

    # Specific recommendations by risk type
    types = risk_summary.get("findings_by_risk_type", {})
    if "Secrets_Hardcoded" in types:
        recommendations.append("- Implement Secrets Management: Use Vault/Secrets Manager; remove all hard-coded secrets from source.")
    if any(t in types for t in ["SQL_Injection", "Command_Injection", "Unsafe_Execution"]):
        recommendations.append("- Input Validation & Parameterization: Enforce strict validation and parameterized queries/commands.")
    if "Insecure_Deserialization" in types:
        recommendations.append("- Safe Data Formats: Use schema-validated formats (JSON/Protobuf) instead of pickle for untrusted data.")
    if any(t in types for t in ["Dependency_Hallucination", "Dependency_Version_Mismatch"]):
        recommendations.append("- Enforce Dependency Allowlist: Automate allowlist checks in CI/CD to block unapproved packages/versions.")

    return "\n".join(recommendations)


def generate_executive_summary(run_id, risk_summary):
    """Generates an executive summary markdown report."""
    sev_breakdown_lines = []
    for severity, count in risk_summary.get('findings_by_severity', {}).items():
        sev_breakdown_lines.append(f"- {severity}: {count} findings")
    sev_breakdown = "\n".join(sev_breakdown_lines) if sev_breakdown_lines else "- None"

    summary_md = f"""
# Executive Summary: AI-Generated Code Vulnerability Report - {run_id}

## Overview
This report summarizes the security assessment of an AI-generated Python API handler (sample_insecure_code.py) at InnovateTech Solutions. The assessment identified and prioritized vulnerabilities introduced by AI-assisted code generation prior to deployment.

## Key Findings
- Total Vulnerabilities Detected: {risk_summary.get('total_findings', 0)}
- Highest Severity Finding: {risk_summary.get('highest_severity_overall', 'None')}
- Breakdown by Severity:
{sev_breakdown}
- Primary Risk Types Identified: {', '.join(risk_summary.get('findings_by_risk_type', {}).keys()) if risk_summary.get('findings_by_risk_type') else 'None'}

The analysis revealed critical vulnerabilities including hard-coded secrets, SQL injection points, unsafe execution calls, insecure deserialization, and an unapproved third-party dependency. These pose significant risks to application security, data integrity, and compliance if not addressed promptly.

## Impact
- Data Breaches: Exposure of sensitive customer data or IP
- System Compromise: Remote code execution enabling server control
- Reputational Damage: Erosion of customer trust and brand value
- Compliance Violations: Non-adherence to regulations (e.g., GDPR, SOC 2)

## Recommendations for Mitigation
{generate_sdlc_control_recommendations(risk_summary, df_consolidated_findings)}

## Conclusion
Proactive security analysis of AI-generated code is essential for a strong security posture. By implementing the recommended remediations and SDLC controls, InnovateTech Solutions can harness AI code generation benefits while effectively managing associated security risks.
"""
    return summary_md


# --- Execution ---
print("\n--- Generating SDLC Control Recommendations ---")
sdlc_recommendations_markdown = generate_sdlc_control_recommendations(risk_summary_data, df_consolidated_findings)
print(sdlc_recommendations_markdown)

sdlc_recommendations_filepath = os.path.join(report_path, "sdlc_control_recommendations.md")
with open(sdlc_recommendations_filepath, "w") as f:
    f.write(sdlc_recommendations_markdown)
print(f"\nSDLC control recommendations saved to: {sdlc_recommendations_filepath}")

print("\n--- Generating Executive Summary ---")
executive_summary_markdown = generate_executive_summary(run_id, risk_summary_data)
print(executive_summary_markdown)

executive_summary_filepath = os.path.join(report_path, "session12_executive_summary.md")
with open(executive_summary_filepath, "w") as f:
    f.write(executive_summary_markdown)
print(f"\nExecutive summary saved to: {executive_summary_filepath}")
def compute_sha256(filepath):
    """Computes the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def create_evidence_manifest(report_path):
    """Creates an evidence manifest (JSON) with SHA-256 hashes for all artifacts."""
    manifest = {}
    for root, _, files in os.walk(report_path):
        for file in files:
            filepath = os.path.join(root, file)
            relative_filepath = os.path.relpath(filepath, report_path)
            manifest[relative_filepath] = {
                "hash_sha256": compute_sha256(filepath),
                "size_bytes": os.path.getsize(filepath)
            }
    manifest_filepath = os.path.join(report_path, "evidence_manifest.json")
    with open(manifest_filepath, "w") as f:
        json.dump(manifest, f, indent=4)
    print(f"Evidence manifest created: {manifest_filepath}")
    return manifest_filepath


def bundle_artifacts_to_zip(report_path, run_id, output_dir="."):
    """Bundles all generated artifacts into a single zip archive."""
    zip_filename = os.path.join(output_dir, f"Session_12_{run_id}.zip")
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(report_path):
            for file in files:
                filepath = os.path.join(root, file)
                zipf.write(filepath, os.path.relpath(filepath, os.path.dirname(report_path)))
    print(f"All artifacts bundled into: {zip_filename}")
    return zip_filename


# --- Execution ---
print("\n--- Generating Evidence Manifest ---")
evidence_manifest_filepath = create_evidence_manifest(report_path)

print("\n--- Bundling All Artifacts ---")
zip_archive_filepath = bundle_artifacts_to_zip(report_path, run_id)

print("\n--- Analysis Complete ---")
print(f"All reports and evidence saved to: {report_path}")
print(f"Manifest: {evidence_manifest_filepath}")
print(f"Archive: {zip_archive_filepath}")