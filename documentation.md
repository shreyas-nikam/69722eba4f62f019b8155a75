id: 69722eba4f62f019b8155a75_documentation
summary: Lab 12: AI Code-Generation Risk Analyzer Documentation
feedback link: https://docs.google.com/forms/d/e/1FAIpQLSfWkOK-in_bMMoHSZfcIvAeO58PAH9wrDqcxnJABHaxiDqhSA/viewform?usp=sf_link
environments: Web
status: Published
# QuLab: AI Code-Generation Risk Analyzer

## Step 1: Introduction to Securing AI-Generated Code
Duration: 0:05:00

Welcome to **QuLab: Lab 12: AI Code-Generation Risk Analyzer**. In this codelab, you will step into the shoes of **Alice, an AppSec Engineer** at InnovateTech Solutions, to understand and implement a robust workflow for securing AI-generated code.

The rapid adoption of AI-powered code generation tools, such as GitHub Copilot, ChatGPT, Claude, and various AI agents, has revolutionized software development. While these tools significantly boost productivity, they also introduce new security challenges. AI models can sometimes generate code that contains vulnerabilities, hard-coded secrets, insecure dependencies, or adherence to deprecated patterns, inadvertently creating attack vectors in applications.

This application provides a hands-on simulation of a security review process designed to catch these common failure modes before AI-generated code integrates into critical systems. Alice's primary goal is to ensure that all AI-assisted code adheres to InnovateTech Solutions' stringent secure coding standards.

### Why is this important?
Integrating AI-generated code without proper security vetting can lead to:
*   **Data Breaches:** Exposure of sensitive information due to hard-coded credentials or insecure data handling.
*   **System Compromise:** Injection vulnerabilities (SQL, Command Injection) that allow attackers to execute arbitrary code or commands.
*   **Supply Chain Attacks:** Inclusion of malicious or unapproved third-party dependencies.
*   **Compliance Violations:** Failure to meet regulatory security standards.

### Learning Objectives
By completing this lab, you will be able to:
1.  **Identify** common failure modes and insecure patterns in AI-generated code.
2.  **Understand** how static analysis techniques (heuristic and AST-based) detect these patterns.
3.  **Recognize** and mitigate dependency hallucinations and supply-chain risks.
4.  **Define** and integrate SDLC control gates for AI-assisted development.
5.  **Produce** audit-ready, comprehensive risk reports for AI-generated code.

### Application Workflow Overview

The AI Code-Generation Risk Analyzer follows a structured approach to evaluate AI-generated code. Here's a high-level overview of the process:

**1. Code & Context Input:** The user provides the Python code, `requirements.txt`, an approved dependency allowlist, and context about the AI generation method and human review level.

**2. Analysis Engine:**
    *   **Static Analysis:** Scans the Python code for common vulnerabilities like hard-coded secrets, command injection, SQL injection, unsafe deserialization, and insecure `eval`/`exec` usage using heuristics and Abstract Syntax Tree (AST) analysis.
    *   **Dependency Analysis:** Compares declared dependencies in `requirements.txt` against an allowlist to detect unapproved packages or versions, mitigating supply chain risks and dependency hallucinations.
    *   **Risk Scoring:** Consolidates findings from static and dependency analyses, assigning a risk score based on severity and confidence.

**3. Reporting & Artifact Generation:**
    *   Generates a consolidated risk scorecard.
    *   Provides SDLC control recommendations tailored to the identified risks.
    *   Creates an executive summary.
    *   Bundles all analysis reports, configuration snapshots, and an evidence manifest into an auditable ZIP archive.

<aside class="positive">
Understanding this workflow is crucial as it mirrors best practices for integrating security into an AI-driven development lifecycle. This comprehensive approach ensures that security is a continuous part of the development process, not an afterthought.
</aside>

## Step 2: Exploring the Application Interface
Duration: 0:02:00

Let's familiarize ourselves with the layout and navigation of the Streamlit application.

Upon launching the application, you'll see a sidebar on the left and the main content area.

### Sidebar Navigation
The sidebar contains the primary navigation for the different stages of our security analysis workflow. You'll find:
*   **Home:** The introductory page you're currently viewing.
*   **1. Code & Context Input:** Where you provide the code and relevant context for analysis.
*   **2. Static Analysis Findings:** Displays vulnerabilities detected directly within the Python code.
*   **3. Dependency Analysis:** Shows issues related to the project's dependencies.
*   **4. Consolidated Risk & Controls:** Presents a combined view of all findings, risk scores, and SDLC recommendations.
*   **5. Report Export:** Allows you to download all generated reports and artifacts.

### Main Content Area
The main content area changes based on your selection in the sidebar. It provides detailed information and interactive elements for each step of the analysis.

You will also notice the `st.sidebar.image` and `st.title` elements that define the branding and main title of the application.

```python
st.set_page_config(page_title="QuLab: Lab 12: AI Code-Generation Risk Analyzer", layout="wide")
st.sidebar.image("https://www.quantuniversity.com/assets/img/logo5.jpg")
st.sidebar.divider()
st.title("QuLab: Lab 12: AI Code-Generation Risk Analyzer")
st.divider()
```

<aside class="positive">
Familiarizing yourself with the navigation upfront will help you move seamlessly through the different analysis stages and understand where each piece of information is presented.
</aside>

## Step 3: Providing Code and Context for Analysis
Duration: 0:08:00

Navigate to the **"1. Code & Context Input"** page using the sidebar. This is where Alice initiates the security review by providing the necessary code and defining the generation context.

This page is critical as it feeds all subsequent analysis steps. It ensures that the security review is comprehensive and tailored to the specific artifacts under examination.

### AI-Generated Python Code (`sample_insecure_code.py`)

This `text_area` is where you input the Python code generated by an AI (or any Python code you want to analyze). The application comes pre-loaded with a `DEFAULT_PYTHON_CODE` that contains various common vulnerabilities for demonstration purposes.

```python
st.session_state.python_code = st.text_area(
    "Python Code",
    value=st.session_state.python_code,
    height=400,
    key="python_code_input"
)
```

The default code includes examples of:
*   Hardcoded API keys and secrets (`API_KEY`, `SECRET_PHRASE`).
*   Potential Command Injection (`subprocess.run(f"echo {command}", shell=True)`).
*   Unsafe `eval`/`exec` usage (`eval(expr)`).
*   Potential SQL Injection (`cursor.execute(query)` with string concatenation).
*   Insecure Deserialization (`pickle.loads(data)`).

```python
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
```

### Dependency Context

This section handles the project's dependencies, which are crucial for detecting supply-chain risks.

*   **Requirements.txt Content (Optional):** Input the contents of your `requirements.txt` file. This lists all third-party libraries and their versions.

    ```python
    st.session_state.requirements_content = st.text_area(
        "Requirements.txt Content (Optional)",
        value=st.session_state.requirements_content,
        height=150,
        key="requirements_input"
    )
    ```

    The default `requirements.txt` includes a malicious-looking package:

    ```
    flask==2.1.0
    requests==2.28.1
    unknown-package-malware==1.0.0 # This should be flagged
    sqlalchemy==1.4.32
    ```

*   **Dependency Allowlist (JSON):** This is a JSON object defining approved packages and their allowed versions. Any package or version not in this list will be flagged.

    ```python
    st.session_state.dependency_allowlist_json_str = st.text_area(
        "Dependency Allowlist (JSON)",
        value=st.session_state.dependency_allowlist_json_str,
        height=200,
        key="allowlist_input"
    )
    ```

    The default allowlist:

    ```json
    {
        "flask": ["2.1.0", "2.2.0"],
        "requests": ["2.28.1", "2.29.0", "2.30.0"],
        "sqlalchemy": ["1.4.32", "2.0.0"]
    }
    ```

    <aside class="negative">
    An invalid JSON format in the Dependency Allowlist will prevent dependency analysis from running correctly. The application includes basic error handling for this.
    </aside>

### Generation Context

Understanding how the code was generated helps tailor security expectations and recommendations.

*   **AI Generation Method:** Select the AI tool used (e.g., Copilot, Claude, Agent).
    ```python
    generation_options = ["Copilot", "Claude", "Agent"]
    st.session_state.generation_method = st.selectbox(
        "AI Generation Method",
        generation_options,
        index=generation_options.index(st.session_state.generation_method) if st.session_state.generation_method in generation_options else 0,
        key="generation_method_selector"
    )
    ```
*   **Human Review Level:** Indicate the extent of human review already applied to the code.
    ```python
    review_options = ["None", "Partial", "Full"]
    st.session_state.human_review_level = st.selectbox(
        "Human Review Level",
        review_options,
        index=review_options.index(st.session_state.human_review_level) if st.session_state.human_review_level in review_options else 1,
        key="review_level_selector"
    )
    ```

### Running the Analysis

After providing all inputs, click the **"Run Analysis"** button.

```python
if st.button("Run Analysis", key="run_analysis_button"):
    # ... analysis logic ...
    st.success("Analysis complete! See findings in the navigation sidebar.")
```

This button triggers a series of backend processes:
1.  **Environment Setup:** Initializes a unique session and report directory.
2.  **Configuration Snapshot:** Saves the input parameters (code hash, requirements hash, allowlist hash, generation method, human review level) for auditability.
3.  **Static Analysis:** Calls `scan_code_for_insecure_deserialization()` (and implicitly other static checks from `source.py`) on the Python code.
4.  **Dependency Analysis:** Calls `detect_dependency_hallucinations()` to check `requirements.txt` against the allowlist.
5.  **Risk Scoring:** Calls `create_risk_scorecard()` to consolidate and score all findings.
6.  **Report Generation:** Calls `generate_sdlc_control_recommendations()` and `generate_executive_summary()` to create textual reports.
7.  **Artifact Management:** Calls `create_evidence_manifest()` and `bundle_artifacts_to_zip()` to package all outputs for export.

<aside class="positive">
Press the "Run Analysis" button now using the default values. You will see a spinner indicating the analysis is running, followed by a success message. This prepares the data for the subsequent steps.
</aside>

## Step 4: Understanding Static Analysis Findings
Duration: 0:07:00

Navigate to the **"2. Static Analysis Findings"** page. This section reveals vulnerabilities detected directly within the provided Python code using static analysis techniques.

Static analysis examines code without executing it, looking for patterns that indicate potential security flaws. The analyzer uses both heuristic rules (e.g., searching for keywords like "API_KEY", `eval`, `subprocess.run(..., shell=True)`) and Abstract Syntax Tree (AST) analysis to identify insecure constructs.

### Identified Code Vulnerabilities

The application displays a dataframe (`st.session_state.df_all_static_findings`) containing the detected issues.

```python
if not st.session_state.df_all_static_findings.empty:
    st.markdown(f"### Identified Code Vulnerabilities")
    st.dataframe(st.session_state.df_all_static_findings[['risk_type', 'severity', 'confidence', 'line_num', 'code_snippet', 'description', 'remediation']])
else:
    st.info("No static analysis findings detected in the provided code.")
```

Let's look at the key columns:

*   **`risk_type`**: The category of the vulnerability (e.g., `Hardcoded Secret`, `Command Injection`, `Unsafe Deserialization`).
*   **`severity`**: The impact of the vulnerability (Critical, High, Medium, Low).
*   **`confidence`**: How certain the analyzer is about the finding (High, Medium, Low).
*   **`line_num`**: The line number in the code where the vulnerability was found.
*   **`code_snippet`**: The relevant line of code.
*   **`description`**: A brief explanation of the vulnerability.
*   **`remediation`**: Suggested actions to fix the vulnerability.

### Examples from Default Code

If you ran the analysis with the default Python code, you should observe findings similar to these:

*   **Hardcoded Secrets:** Lines containing `API_KEY = "..."` and `SECRET_PHRASE = "..."` will be flagged as `Hardcoded Secret`.
*   **Command Injection:** The line `subprocess.run(f"echo {command}", shell=True)` is a classic command injection vulnerability because `shell=True` allows execution of arbitrary commands if `command` is user-controlled.
*   **Unsafe Eval/Exec:** The `eval(expr)` call allows arbitrary code execution if `expr` is untrusted.
*   **SQL Injection:** The `query = f"SELECT * FROM users WHERE username = '{username}'"` line is vulnerable because it concatenates user input directly into an SQL query without proper sanitization or parameterization.
*   **Insecure Deserialization:** `pickle.loads(data)` is flagged because deserializing untrusted data with `pickle` can lead to arbitrary code execution.

<aside class="negative">
These findings highlight common pitfalls in AI-generated code. While AI is powerful, it might sometimes replicate patterns from its training data that are insecure, especially if it doesn't fully grasp the security implications of certain functions or configurations. <b>Always review AI-generated code critically.</b>
</aside>

## Step 5: Detecting Dependency Hallucinations and Risks
Duration: 0:06:00

Navigate to the **"3. Dependency Analysis"** page. This section focuses on a critical aspect of modern software security: supply chain risk, particularly in the context of AI-generated code.

AI models, when generating `requirements.txt` files or suggesting packages, can sometimes "hallucinate" dependencies. This means they might suggest non-existent packages, misspell package names, or recommend outdated/vulnerable versions. Additionally, they might suggest legitimate but unapproved packages, leading to security or compliance issues.

To mitigate this, Alice verifies declared dependencies against a predefined `dependency_allowlist`.

### Dependency-Related Issues

The application displays a dataframe (`st.session_state.df_dependency_findings`) showing any identified dependency issues.

```python
if not st.session_state.df_dependency_findings.empty:
    st.markdown(f"### Dependency-Related Issues")
    st.dataframe(st.session_state.df_dependency_findings[['risk_type', 'severity', 'confidence', 'package', 'version', 'line_in_requirements_txt', 'description', 'remediation']])
else:
    st.info("No dependency-related issues detected. All dependencies are approved and using allowed versions.")
```

Key columns in this dataframe include:

*   **`risk_type`**: The nature of the dependency issue (e.g., `Unauthorized Dependency`, `Unauthorized Version`).
*   **`severity`**: The impact of the issue (Critical, High, Medium, Low).
*   **`confidence`**: How certain the analyzer is.
*   **`package`**: The name of the package.
*   **`version`**: The version of the package.
*   **`line_in_requirements_txt`**: The line number in `requirements.txt` where the dependency was found.
*   **`description`**: Explanation of the finding.
*   **`remediation`**: Suggested fixes.

### How the Allowlist Works

The `dependency_allowlist.json` acts as a whitelist. For each package, it specifies a list of approved versions.

```json
{
    "flask": ["2.1.0", "2.2.0"],
    "requests": ["2.28.1", "2.29.0", "2.30.0"],
    "sqlalchemy": ["1.4.32", "2.0.0"]
}
```

If a package listed in `requirements.txt`:
1.  **Is not present** in the `dependency_allowlist`: It's flagged as an `Unauthorized Dependency`.
2.  **Is present, but its version is not in the allowed list** for that package: It's flagged as an `Unauthorized Version`.

### Example from Default Requirements.txt

With the default `requirements.txt`:

```
flask==2.1.0
requests==2.28.1
unknown-package-malware==1.0.0 # This should be flagged
sqlalchemy==1.4.32
```

And the default `dependency_allowlist`, you should see a finding for `unknown-package-malware==1.0.0` as an `Unauthorized Dependency` because it's not present in the allowlist. Even if `flask==2.1.0` was changed to `flask==1.0.0` (not in the allowlist), it would be flagged as an `Unauthorized Version`.

<aside class="positive">
Implementing a dependency allowlist is a critical control against supply chain attacks and ensures that only vetted, secure, and approved third-party components are used in your projects. This reduces the attack surface significantly.
</aside>

## Step 6: Consolidating Risk and Defining SDLC Controls
Duration: 0:08:00

Navigate to the **"4. Consolidated Risk & Controls"** page. This section brings together all the findings from static and dependency analysis into a single, prioritized view. Alice needs this consolidated perspective to understand the overall risk posture and to formulate effective remediation and SDLC (Software Development Life Cycle) control strategies.

### Overall Risk Summary

The page begins with an "Overall Risk Summary" that provides key metrics about the analysis, such as the total number of findings, critical risks, high risks, etc. This summary is generated from `st.session_state.risk_summary_data`.

```python
st.markdown(f"### Overall Risk Summary")
for key, value in st.session_state.risk_summary_data.items():
    st.markdown(f"- **{key.replace('_', ' ').title()}**: {value}")
```

### Risk Score Calculation

To prioritize findings, each vulnerability is assigned a risk score. This score helps Alice understand which issues require immediate attention.

The risk score is calculated using the following formula:

$$ \text{Risk Score} = \text{Severity Weight} \times \text{Confidence Weight} $$

Where:
*   $\text{Severity Weight}$ is mapped as: Critical = 4, High = 3, Medium = 2, Low = 1.
*   $\text{Confidence Weight}$ is mapped as: High = 1.0, Medium = 0.75, Low = 0.5.

For example, a **Critical** vulnerability with **High** confidence would have a risk score of $4 \times 1.0 = 4$. A **High** severity with **Medium** confidence would be $3 \times 0.75 = 2.25$.

### Consolidated Vulnerabilities

All findings (from both static and dependency analysis) are combined into a single dataframe (`st.session_state.df_consolidated_findings`) and sorted by their calculated `risk_score` in descending order.

```python
st.dataframe(st.session_state.df_consolidated_findings[[
    'risk_type', 'severity', 'confidence', 'risk_score',
    'line_num', 'package', 'code_snippet', 'description', 'remediation'
]])
```

This table provides a comprehensive overview, making it easy to identify the most critical issues first. Notice how the `line_num` and `code_snippet` are relevant for static findings, while `package` and `version` are relevant for dependency findings.

### SDLC Control Recommendations

Based on the overall risk summary and specific findings, the application generates tailored SDLC control recommendations. These recommendations (`st.session_state.sdlc_recommendations_markdown`) are actionable steps that InnovateTech Solutions can integrate into their development pipeline to prevent similar vulnerabilities in the future.

```python
st.markdown(f"### SDLC Control Recommendations")
st.markdown(st.session_state.sdlc_recommendations_markdown)
```

Examples of recommendations might include:
*   **Pre-commit hooks:** To scan for secrets or lint code.
*   **Automated static analysis:** Integration of SAST tools into CI/CD pipelines.
*   **Dependency scanning:** Regular checks for known vulnerabilities in third-party libraries.
*   **Code review policies:** Mandatory human review for AI-generated code.
*   **Developer training:** Educating developers on secure coding practices and AI security risks.

<aside class="positive">
This consolidated view and risk-based prioritization are essential for AppSec engineers like Alice to efficiently manage security debt and guide developers toward the most impactful remediations. The SDLC recommendations provide a strategic blueprint for improving the overall security posture.
</aside>

## Step 7: Exporting Reports and Artifacts
Duration: 0:06:00

Navigate to the **"5. Report Export"** page. The final step in Alice's workflow is to generate and export all analysis artifacts. This is crucial for auditability, compliance, and for sharing findings with various stakeholders (developers, project managers, security auditors).

### Executive Summary

The page starts by displaying the "Executive Summary" (`st.session_state.executive_summary_markdown`). This is a high-level overview, typically non-technical, designed for management and non-security personnel to quickly grasp the overall security posture and key risks.

```python
st.markdown(f"### Executive Summary")
st.markdown(st.session_state.executive_summary_markdown)
```

### Download Analysis Artifacts (ZIP Archive)

All generated reports and evidence for a given session are bundled into a single ZIP archive. This makes it convenient to download all relevant files in one go. The `session_id` uniquely identifies each analysis run.

```python
if st.session_state.zip_archive_filepath and os.path.exists(st.session_state.zip_archive_filepath):
    with open(st.session_state.zip_archive_filepath, "rb") as fp:
        st.download_button(
            label=f"Download All Reports (Session_{st.session_state.session_id}.zip)",
            data=fp,
            file_name=f"Session_{st.session_state.session_id}.zip",
            mime="application/zip",
            key="download_all_zip"
        )
```
<button>
  [Download All Reports (Session_<YOUR_SESSION_ID>.zip)](javascript:void(0))
</button>

### Individual Report Files

For more granular access or specific audit requirements, you can also download each generated file individually. These files are stored in a dedicated report path (`st.session_state.report_path`) for the current session.

The available individual files include:
*   `code_findings.json`: Detailed static analysis findings.
*   `dependency_findings.json`: Detailed dependency analysis findings.
*   `risk_scorecard.json`: The raw risk summary data.
*   `sdlc_control_recommendations.md`: Markdown document of SDLC recommendations.
*   `session12_executive_summary.md`: Markdown document of the executive summary.
*   `config_snapshot.json`: A snapshot of all input configuration and hashes for the analysis run.
*   `evidence_manifest.json`: A manifest listing all generated artifacts along with their SHA256 hashes, ensuring data integrity and non-repudiation.

```python
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
```

<aside class="positive">
The ability to export comprehensive, auditable reports is a cornerstone of any effective AppSec program. This ensures transparency, accountability, and a clear record of security due diligence, which is especially important for AI-generated code.
</aside>
