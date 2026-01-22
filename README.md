This README.md provides a comprehensive guide to the Streamlit application for analyzing AI-generated code for security risks.

---

# QuLab: Lab 12: AI Code-Generation Risk Analyzer

![QuantUniversity Logo](https://www.quantuniversity.com/assets/img/logo5.jpg)

## Project Title

**AI Code-Generation Risk Analyzer: Secure SDLC Controls for Copilot, Claude, Agents, Tool Calling, and MCP**

## Description

This Streamlit application, developed as part of QuLab's Lab 12, empowers AppSec Engineers like "Alice" at InnovateTech Solutions to conduct thorough security reviews of AI-generated code. With the increasing adoption of AI tools in software development, it's crucial to ensure that AI-assisted code adheres to stringent secure coding standards before being integrated into production systems.

The application simulates Alice's workflow, providing capabilities to:
*   Identify common security vulnerabilities (e.g., hard-coded secrets, injection flaws, unsafe deserialization) using heuristic and Abstract Syntax Tree (AST)-based static analysis.
*   Detect dependency hallucinations and supply-chain risks by verifying declared packages against an approved allowlist.
*   Consolidate findings, prioritize risks, and generate actionable remediation plans.
*   Produce audit-ready reports, including an executive summary, SDLC control recommendations, and a manifest of evidence, all bundled into a single archive.

This lab focuses on establishing robust Secure Software Development Lifecycle (SDLC) control gates specifically for code produced by AI tools like Copilot, Claude, and autonomous agents, ensuring a higher level of application security.

## Features

The AI Code-Generation Risk Analyzer offers the following key functionalities:

*   **Interactive Input Interface**:
    *   Paste or upload AI-generated Python code for analysis.
    *   Provide `requirements.txt` content for dependency scanning.
    *   Define a JSON-based dependency allowlist for version control and hallucination detection.
    *   Specify AI generation method (e.g., Copilot, Claude, Agent) and human review level for contextual analysis.
*   **Static Code Analysis**:
    *   Heuristic and AST-based scanning to detect common vulnerabilities:
        *   Hard-coded secrets (e.g., API keys, secret phrases).
        *   Command injection flaws (e.g., `subprocess.run` with `shell=True`).
        *   SQL injection vulnerabilities (e.g., f-strings in SQL queries).
        *   Unsafe deserialization (e.g., `pickle.loads`).
        *   Unsafe `eval`/`exec` usage.
*   **Dependency Analysis**:
    *   Compares declared dependencies in `requirements.txt` against a user-provided allowlist.
    *   Flags unknown packages, unapproved versions, and potential dependency hallucinations.
*   **Consolidated Risk Scoring**:
    *   Aggregates static and dependency findings into a unified scorecard.
    *   Calculates a risk score for each finding based on severity and confidence.
    *   Provides an overall risk summary for the analyzed codebase.
*   **SDLC Control Recommendations**:
    *   Generates tailored recommendations for integrating security controls into the SDLC, based on identified risks.
*   **Comprehensive Reporting**:
    *   Produces an Executive Summary for management.
    *   Generates detailed JSON reports for static findings, dependency findings, and the risk scorecard.
    *   Creates a markdown report for SDLC control recommendations.
*   **Auditability & Artifact Management**:
    *   Captures a configuration snapshot of the analysis parameters.
    *   Generates an evidence manifest (JSON) listing all produced artifacts and their SHA256 hashes.
    *   Bundles all analysis reports and evidence into a single, downloadable ZIP archive for audit purposes.
*   **Streamlit UI**: User-friendly, interactive web interface for seamless workflow.

## Getting Started

Follow these instructions to get a copy of the project up and running on your local machine.

### Prerequisites

*   Python 3.8+
*   `pip` (Python package installer)

### Installation

1.  **Clone the repository (or download the project files):**

    ```bash
    git clone https://github.com/your-repo/ai-code-risk-analyzer.git
    cd ai-code-risk-analyzer
    ```
    *(Note: Replace `your-repo` with the actual repository URL if this project is hosted.)*

2.  **Create a virtual environment (recommended):**

    ```bash
    python -m venv venv
    source venv/bin/activate   # On Windows: `venv\Scripts\activate`
    ```

3.  **Install the required Python packages:**

    ```bash
    pip install -r requirements.txt
    ```
    *(If a `requirements.txt` is not provided, you will need to create one. Based on the `import` statements in `app.py`, the core requirements for the application itself are:)*
    ```
    # requirements.txt
    streamlit==1.x.x # Use a compatible version
    pandas==1.x.x    # Use a compatible version
    # Add any other specific versions you use or if 'source.py' has external dependencies
    ```

4.  **Ensure `source.py` is present:**
    The application relies on a `source.py` file containing the core analysis logic. Make sure this file is in the same directory as `app.py`.

## Usage

1.  **Run the Streamlit application:**

    ```bash
    streamlit run app.py
    ```
    (Assuming your main application file is named `app.py`)

2.  **Access the application:**
    Your web browser should automatically open to the application's local URL (usually `http://localhost:8501`).

3.  **Navigate and Analyze:**

    *   **Home**: Provides an introduction and learning objectives.
    *   **1. Code & Context Input**:
        *   Paste your AI-generated Python code into the "Python Code" text area.
        *   (Optional) Paste your `requirements.txt` content.
        *   Paste your dependency allowlist in JSON format (a default is provided).
        *   Select the "AI Generation Method" and "Human Review Level".
        *   Click the "Run Analysis" button to start the security scan.
    *   **2. Static Analysis Findings**: View detected code vulnerabilities.
    *   **3. Dependency Analysis**: Review dependency-related issues and hallucination alerts.
    *   **4. Consolidated Risk & Controls**: See the overall risk summary, risk scorecard, and SDLC control recommendations.
    *   **5. Report Export**: Download the executive summary, individual reports, or a complete ZIP archive of all analysis artifacts.

## Project Structure

```
.
├── app.py                      # Main Streamlit application file
├── source.py                   # Contains core analysis logic (static analysis, dependency analysis, reporting functions)
├── requirements.txt            # Python dependencies for the application
├── reports/                    # Directory for generated analysis reports (created dynamically during runtime)
│   └── <session_id>/           # Unique directory for each analysis session
│       ├── code_findings.json
│       ├── config_snapshot.json
│       ├── dependency_findings.json
│       ├── evidence_manifest.json
│       ├── risk_scorecard.json
│       ├── sdlc_control_recommendations.md
│       └── session12_executive_summary.md
└── README.md                   # This project README file
```

## Technology Stack

*   **Frontend/Backend Framework**: [Streamlit](https://streamlit.io/) (for interactive web applications in Python)
*   **Programming Language**: Python 3.8+
*   **Data Manipulation**: [Pandas](https://pandas.pydata.org/)
*   **Static Analysis**: Custom heuristic and AST-based logic (implemented in `source.py`)
*   **Dependency Management**: `pip`
*   **Serialization/Hashing**: `json`, `hashlib` (standard Python libraries)
*   **Other Standard Libraries**: `os`, `io`, `datetime`

## Contributing

Contributions are welcome! If you have suggestions for improvements, new features, or bug fixes, please follow these steps:

1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/AmazingFeature`).
3.  Make your changes and ensure they adhere to the existing code style.
4.  Commit your changes (`git commit -m 'Add some AmazingFeature'`).
5.  Push to the branch (`git push origin feature/AmazingFeature`).
6.  Open a Pull Request.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details (if applicable).

## Contact

For questions or feedback, please reach out via:

*   **QuantUniversity (QuLab)**: [www.quantuniversity.com](https://www.quantuniversity.com/)
*   **GitHub Issues**: [https://github.com/your-repo/ai-code-risk-analyzer/issues](https://github.com/your-repo/ai-code-risk-analyzer/issues) (if hosted)

---