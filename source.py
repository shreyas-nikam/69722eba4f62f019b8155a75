# source.py
import ast
import re
import json
import os
import zipfile
import hashlib
import pandas as pd
import datetime
import uuid
from typing import Dict, Any, List, Tuple, Optional, Union


# -----------------------------
# Environment
# -----------------------------
def setup_analysis_environment(base_report_dir: str = "reports/session12") -> Tuple[str, str]:
    run_id = f"{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{str(uuid.uuid4())[:8]}"
    report_path = os.path.join(base_report_dir, run_id)
    os.makedirs(report_path, exist_ok=True)
    return run_id, report_path


# -----------------------------
# Safe ZIP extraction + discovery
# -----------------------------
def _is_within_directory(directory: str, target: str) -> bool:
    abs_directory = os.path.abspath(directory)
    abs_target = os.path.abspath(target)
    return os.path.commonpath([abs_directory]) == os.path.commonpath([abs_directory, abs_target])


def safe_extract_zip(zip_path: str, extract_dir: str) -> List[str]:
    """
    Safely extracts a zip file, preventing Zip Slip.
    Returns list of extracted file paths.
    """
    os.makedirs(extract_dir, exist_ok=True)
    extracted_paths: List[str] = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            # Skip directories
            if member.is_dir():
                continue

            dest_path = os.path.join(extract_dir, member.filename)

            # Zip Slip check
            if not _is_within_directory(extract_dir, dest_path):
                raise ValueError(
                    f"Unsafe zip entry detected (Zip Slip): {member.filename}")

            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            with zf.open(member, "r") as src, open(dest_path, "wb") as dst:
                dst.write(src.read())

            extracted_paths.append(dest_path)

    return extracted_paths


def discover_files(root_dir: str, exts: Tuple[str, ...]) -> List[str]:
    found: List[str] = []
    for root, _, files in os.walk(root_dir):
        for fn in files:
            if fn.lower().endswith(exts):
                found.append(os.path.join(root, fn))
    return sorted(found)


def find_first_by_name(root_dir: str, filename: str) -> Optional[str]:
    filename_lower = filename.lower()
    for root, _, files in os.walk(root_dir):
        for fn in files:
            if fn.lower() == filename_lower:
                return os.path.join(root, fn)
    return None


def read_text_file(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def compute_sha256_from_string(content: str) -> str:
    if not content:
        return ""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def compute_sha256(filepath: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


# -----------------------------
# Config snapshot (multi-code aware)
# -----------------------------
def store_config_snapshot(
    report_path: str,
    run_id: str,
    code_filepaths: Union[str, List[str]],
    requirements_filepath: Optional[str] = None,
    allowlist_filepath: Optional[str] = None,
    git_commit: str = "N/A",
    ai_generation_method: str = "Copilot",
    human_review_level: str = "Partial",
    extra: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Stores config snapshot. Supports single code file OR multiple code files.
    """
    if isinstance(code_filepaths, str):
        code_files = [code_filepaths]
    else:
        code_files = list(code_filepaths)

    snapshot = {
        "run_id": run_id,
        "timestamp": datetime.datetime.now().isoformat(),
        "git_commit": git_commit,
        "ai_generation_method": ai_generation_method,
        "human_review_level": human_review_level,
        "code_filepaths": code_files,
        "requirements_filepath": requirements_filepath,
        "allowlist_filepath": allowlist_filepath,
        "code_files_sha256": {os.path.basename(p): compute_sha256(p) for p in code_files if p and os.path.exists(p)},
        "requirements_sha256": compute_sha256(requirements_filepath) if requirements_filepath and os.path.exists(requirements_filepath) else None,
        "allowlist_sha256": compute_sha256(allowlist_filepath) if allowlist_filepath and os.path.exists(allowlist_filepath) else None,
    }

    if extra:
        snapshot["extra"] = extra

    out_path = os.path.join(report_path, "config_snapshot.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=4)
    return out_path


# -----------------------------
# Static Analysis Detectors
# -----------------------------
class VulnerabilityDetector(ast.NodeVisitor):
    def __init__(self, code_lines: List[str]):
        self.findings: List[Dict[str, Any]] = []
        self.code_lines = code_lines
        self.formatted_vars = set()

    def _add_finding(self, risk_type, severity, confidence, line_num, code_snippet, description, remediation):
        self.findings.append({
            "risk_type": risk_type,
            "severity": severity,
            "confidence": confidence,
            "line_num": line_num,
            "code_snippet": (code_snippet or "").strip(),
            "description": description,
            "remediation": remediation
        })

    def visit_Assign(self, node):
        def is_formatted_value(val):
            return (
                isinstance(val, ast.JoinedStr) or
                isinstance(val, ast.BinOp) or
                (isinstance(val, ast.Call) and isinstance(
                    val.func, ast.Attribute) and val.func.attr == "format")
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
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in ["eval", "exec"]:
                line_num = getattr(node, "lineno", 1)
                self._add_finding(
                    risk_type="Unsafe_Execution",
                    severity="Critical",
                    confidence="High",
                    line_num=line_num,
                    code_snippet=self.code_lines[line_num -
                                                 1] if line_num - 1 < len(self.code_lines) else "",
                    description=f"Direct call to unsafe function '{func_name}'. This can lead to arbitrary code execution if user-controlled input is passed.",
                    remediation="Avoid using eval/exec with untrusted input. Consider ast.literal_eval for literals, or strict allowlists/sandboxing if dynamic execution is unavoidable."
                )
        self.generic_visit(node)

    def detect_hardcoded_secrets(self, code_string: str) -> None:
        try:
            tree = ast.parse(code_string)
        except SyntaxError:
            return

        sensitive_keywords = re.compile(
            r"(api|secret|token|passwd|password|key)", re.IGNORECASE)
        benign_names = re.compile(
            r"^(debug|user_id_prefix|some_id|test|placeholder)$", re.IGNORECASE)

        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = []
                if isinstance(node, ast.Assign):
                    targets = [
                        t for t in node.targets if isinstance(t, ast.Name)]
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    targets = [node.target]

                value_node = node.value if hasattr(node, "value") else None
                if not targets or not isinstance(value_node, ast.Constant) or not isinstance(value_node.value, str):
                    continue

                for t in targets:
                    var_name = t.id
                    if benign_names.search(var_name):
                        continue
                    if sensitive_keywords.search(var_name):
                        literal = value_node.value
                        if len(literal) >= 8:
                            line_num = getattr(node, "lineno", 1)
                            severity = "Critical" if re.search(
                                r"(api|token|secret|key|passwd|password)", var_name, re.IGNORECASE) else "High"
                            self._add_finding(
                                risk_type="Secrets_Hardcoded",
                                severity=severity,
                                confidence="High",
                                line_num=line_num,
                                code_snippet=self.code_lines[line_num - 1] if line_num - 1 < len(
                                    self.code_lines) else "",
                                description=f"Hard-coded secret detected in variable '{var_name}'.",
                                remediation="Store secrets in env vars or a secrets manager (AWS Secrets Manager/Vault). Avoid committing secrets to VCS."
                            )

    def get_findings(self) -> List[Dict[str, Any]]:
        return self.findings


class InjectionDetector(VulnerabilityDetector):
    def _is_formatted(self, node):
        return (
            isinstance(node, ast.JoinedStr) or
            isinstance(node, ast.BinOp) or
            (isinstance(node, ast.Call) and isinstance(
                node.func, ast.Attribute) and node.func.attr == "format")
        )

    def visit_Call(self, node):
        super().visit_Call(node)

        if isinstance(node.func, ast.Attribute) and node.func.attr in ["execute", "executemany"]:
            risky = False
            for arg in node.args:
                if self._is_formatted(arg):
                    risky = True
                    break
                if isinstance(arg, ast.Name) and arg.id in self.formatted_vars:
                    risky = True
                    break
            if risky:
                line_num = getattr(node, "lineno", 1)
                self._add_finding(
                    risk_type="SQL_Injection",
                    severity="Critical",
                    confidence="Medium",
                    line_num=line_num,
                    code_snippet=self.code_lines[line_num -
                                                 1] if line_num - 1 < len(self.code_lines) else "",
                    description="Potential SQL Injection due to string formatting used in/prior to query execution. Use parameterized queries.",
                    remediation="Use parameterized queries (e.g., cursor.execute('... WHERE x=?', (value,))). Avoid f-strings/concat for SQL."
                )

        if isinstance(node.func, ast.Attribute) and node.func.attr in ["run", "call", "check_call", "Popen"]:
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                has_shell_true = any(
                    (kw.arg == "shell" and isinstance(
                        kw.value, ast.Constant) and kw.value.value is True)
                    for kw in node.keywords
                )
                if has_shell_true:
                    for arg in node.args:
                        if self._is_formatted(arg) or (isinstance(arg, ast.Name) and arg.id in self.formatted_vars):
                            line_num = getattr(node, "lineno", 1)
                            self._add_finding(
                                risk_type="Command_Injection",
                                severity="High",
                                confidence="Medium",
                                line_num=line_num,
                                code_snippet=self.code_lines[line_num - 1] if line_num - 1 < len(
                                    self.code_lines) else "",
                                description="Potential Command Injection: subprocess uses shell=True with formatted input.",
                                remediation="Avoid shell=True; pass args as a list. If unavoidable, strictly validate/allowlist inputs."
                            )
                            break

        self.generic_visit(node)


class DeserializationDetector(InjectionDetector):
    def visit_Call(self, node):
        super().visit_Call(node)

        if isinstance(node.func, ast.Attribute) and node.func.attr == "loads":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                line_num = getattr(node, "lineno", 1)
                self._add_finding(
                    risk_type="Insecure_Deserialization",
                    severity="Critical",
                    confidence="High",
                    line_num=line_num,
                    code_snippet=self.code_lines[line_num -
                                                 1] if line_num - 1 < len(self.code_lines) else "",
                    description="Insecure deserialization using pickle.loads(). Untrusted pickle can lead to RCE.",
                    remediation="Avoid pickle for untrusted data. Prefer JSON/Protobuf with schema validation. Add integrity/authn checks."
                )
        self.generic_visit(node)


# -----------------------------
# Scan (single string)
# -----------------------------
def scan_code_for_insecure_deserialization_and_consolidate(python_code: str) -> List[Dict[str, Any]]:
    code_lines = python_code.splitlines()
    try:
        tree = ast.parse(python_code)
    except SyntaxError:
        # Return a single finding noting parsing failed
        return [{
            "risk_type": "Parse_Error",
            "severity": "Medium",
            "confidence": "High",
            "line_num": 1,
            "code_snippet": "",
            "description": "Python code could not be parsed (SyntaxError). Static analysis may be incomplete.",
            "remediation": "Fix syntax errors and re-run analysis."
        }]

    detector = DeserializationDetector(code_lines)
    detector.visit(tree)
    detector.detect_hardcoded_secrets(python_code)
    return detector.get_findings()


# -----------------------------
# Scan (multiple files)
# -----------------------------
def scan_code_files_for_insecure_deserialization_and_consolidate(code_filepaths: List[str]) -> pd.DataFrame:
    """
    Runs static analysis across multiple .py files.
    Returns a dataframe with an added 'file_path' column.
    """
    rows: List[Dict[str, Any]] = []
    for fp in code_filepaths:
        try:
            code = read_text_file(fp)
        except Exception:
            rows.append({
                "file_path": fp,
                "risk_type": "Read_Error",
                "severity": "Medium",
                "confidence": "High",
                "line_num": 1,
                "code_snippet": "",
                "description": "Could not read file for analysis.",
                "remediation": "Ensure file is readable and encoded as UTF-8."
            })
            continue

        findings = scan_code_for_insecure_deserialization_and_consolidate(code)
        for f in findings:
            f2 = dict(f)
            f2["file_path"] = fp
            rows.append(f2)

    df = pd.DataFrame(rows)
    if not df.empty:
        # De-dup within each file
        subset_cols = [c for c in ["file_path", "line_num", "risk_type",
                                   "code_snippet", "description"] if c in df.columns]
        df = df.drop_duplicates(subset=subset_cols).reset_index(drop=True)
    return df


# -----------------------------
# Dependency Analysis
# -----------------------------
def parse_requirements(requirements_content: str) -> List[Dict[str, str]]:
    dependencies = []
    for line in requirements_content.splitlines():
        raw = line
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
        match = re.match(
            r"([a-zA-Z0-9._-]+)\s*(==|>=|<=|>|<|~=)?\s*([^\s]+)?", line)
        if match:
            pkg_name = match.group(1)
            operator = match.group(2) if match.group(2) else "=="
            version = (match.group(3) or "").strip()
            dependencies.append(
                {"package": pkg_name, "version": version, "operator": operator, "line": raw.strip()})
    return dependencies


def detect_dependency_hallucinations(requirements_content: str, dependency_allowlist: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    parsed_dependencies = parse_requirements(requirements_content)
    dependency_findings = []

    for dep in parsed_dependencies:
        pkg_name_lower = dep["package"].lower()
        version = dep["version"]
        line = dep["line"]

        if pkg_name_lower not in dependency_allowlist:
            dependency_findings.append({
                "risk_type": "Dependency_Hallucination",
                "severity": "Critical",
                "confidence": "High",
                "package": dep["package"],
                "version": version if version else "N/A",
                "line_in_requirements_txt": line,
                "description": f"Unknown or unapproved package '{dep['package']}' detected.",
                "remediation": "Investigate package legitimacy; remove if unneeded or add to allowlist with approved versions."
            })
        else:
            allowed_versions = dependency_allowlist.get(pkg_name_lower, [])
            if version and version not in allowed_versions:
                dependency_findings.append({
                    "risk_type": "Dependency_Version_Mismatch",
                    "severity": "Medium",
                    "confidence": "High",
                    "package": dep["package"],
                    "version": version,
                    "line_in_requirements_txt": line,
                    "description": f"Approved package '{dep['package']}', but version '{version}' not allowlisted. Allowed: {', '.join(allowed_versions)}.",
                    "remediation": f"Use an allowlisted version or update allowlist after approval."
                })

    return dependency_findings


# -----------------------------
# Risk Scorecard + Reports
# -----------------------------
def create_risk_scorecard(
    static_findings_df: Optional[pd.DataFrame],
    dependency_findings_df: Optional[pd.DataFrame],
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    all_findings_list: List[Dict[str, Any]] = []
    if static_findings_df is not None and not static_findings_df.empty:
        all_findings_list.extend(static_findings_df.to_dict(orient="records"))
    if dependency_findings_df is not None and not dependency_findings_df.empty:
        all_findings_list.extend(
            dependency_findings_df.to_dict(orient="records"))

    if not all_findings_list:
        return pd.DataFrame(), {}

    df_all = pd.DataFrame(all_findings_list)

    severity_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    confidence_map = {"High": 1.0, "Medium": 0.75, "Low": 0.5}

    df_all["severity_score"] = df_all["severity"].map(severity_map).fillna(0)
    df_all["confidence_score"] = df_all["confidence"].map(
        confidence_map).fillna(0)
    df_all["risk_score"] = df_all["severity_score"] * \
        df_all["confidence_score"]

    if not df_all.empty:
        idx = df_all["severity_score"].idxmax()
        highest_sev = df_all.loc[idx, "severity"] if pd.notna(idx) else "None"
    else:
        highest_sev = "None"

    risk_summary = {
        "total_findings": int(len(df_all)),
        "findings_by_severity": df_all["severity"].value_counts().to_dict(),
        "findings_by_risk_type": df_all["risk_type"].value_counts().to_dict(),
        "max_risk_score": float(df_all["risk_score"].max()) if not df_all.empty else 0.0,
        "average_risk_score": float(df_all["risk_score"].mean()) if not df_all.empty else 0.0,
        "highest_severity_overall": highest_sev,
    }

    df_sorted = df_all.sort_values(
        by="risk_score", ascending=False).reset_index(drop=True)
    return df_sorted, risk_summary


def generate_sdlc_control_recommendations(risk_summary: Dict[str, Any]) -> str:
    recommendations: List[str] = []

    if risk_summary.get("highest_severity_overall") == "Critical":
        recommendations.append(
            "- Mandatory Human Review Gate: Manual security review gate for all AI-generated code before QA/production.")
        recommendations.append(
            "- Automated SAST Integration: Integrate SAST into CI/CD to block builds with critical/high findings.")
        recommendations.append(
            "- Enhanced Developer Training: Secure coding training focused on AI-generated code pitfalls.")
    elif risk_summary.get("highest_severity_overall") == "High":
        recommendations.append(
            "- Mandatory Peer Review with Security Checklist for AI-generated code.")
        recommendations.append(
            "- SAST in CI/CD (Advisory Mode): Block only critical; warn on high.")
    else:
        recommendations.append(
            "- Regular Security Scans: Routine static analysis on all codebases, including AI-generated components.")
        recommendations.append(
            "- Review Dependency Management: Maintain/enforce approved dependency allowlist.")

    types = risk_summary.get("findings_by_risk_type", {}) or {}
    if "Secrets_Hardcoded" in types:
        recommendations.append(
            "- Implement Secrets Management: Use Vault/Secrets Manager; remove all hard-coded secrets.")
    if any(t in types for t in ["SQL_Injection", "Command_Injection", "Unsafe_Execution"]):
        recommendations.append(
            "- Input Validation & Parameterization: Enforce strict validation and parameterized queries/commands.")
    if "Insecure_Deserialization" in types:
        recommendations.append(
            "- Safe Data Formats: Use schema-validated formats (JSON/Protobuf) instead of pickle for untrusted data.")
    if any(t in types for t in ["Dependency_Hallucination", "Dependency_Version_Mismatch"]):
        recommendations.append(
            "- Enforce Dependency Allowlist: Automate checks in CI/CD to block unapproved packages/versions.")

    return "\n".join(recommendations)


def generate_executive_summary(run_id: str, risk_summary: Dict[str, Any], sdlc_recommendations_md: str) -> str:
    sev_breakdown_lines = [
        f"- {severity}: {count} findings"
        for severity, count in (risk_summary.get("findings_by_severity") or {}).items()
    ]
    sev_breakdown = "\n".join(
        sev_breakdown_lines) if sev_breakdown_lines else "- None"
    primary_risk_types = ", ".join(
        (risk_summary.get("findings_by_risk_type") or {}).keys()) or "None"

    return f"""# Executive Summary: AI-Generated Code Vulnerability Report - {run_id}

## Overview
This report summarizes the security assessment of AI-generated Python code. The assessment identified and prioritized vulnerabilities introduced by AI-assisted code generation prior to deployment.

## Key Findings
- Total Vulnerabilities Detected: {risk_summary.get('total_findings', 0)}
- Highest Severity Finding: {risk_summary.get('highest_severity_overall', 'None')}
- Breakdown by Severity:
{sev_breakdown}
- Primary Risk Types Identified: {primary_risk_types}

## Recommendations for Mitigation
{sdlc_recommendations_md}

## Conclusion
Proactive security analysis of AI-generated code is essential for a strong security posture. By implementing recommended remediations and SDLC controls, teams can harness AI code generation benefits while managing security risks.
"""


def save_reports(
    report_path: str,
    run_id: str,
    df_consolidated: pd.DataFrame,
    risk_summary: Dict[str, Any],
    sdlc_md: str,
    exec_md: str,
) -> Dict[str, str]:
    paths: Dict[str, str] = {}

    if df_consolidated is not None and not df_consolidated.empty:
        findings_path = os.path.join(report_path, "code_findings.json")
        df_consolidated.to_json(findings_path, orient="records", indent=4)
        paths["consolidated_findings_json"] = findings_path

        scorecard_path = os.path.join(report_path, "risk_scorecard.json")
        with open(scorecard_path, "w", encoding="utf-8") as f:
            json.dump(risk_summary, f, indent=4)
        paths["risk_scorecard_json"] = scorecard_path

    sdlc_path = os.path.join(report_path, "sdlc_control_recommendations.md")
    with open(sdlc_path, "w", encoding="utf-8") as f:
        f.write(sdlc_md)
    paths["sdlc_recommendations_md"] = sdlc_path

    exec_path = os.path.join(report_path, "session12_executive_summary.md")
    with open(exec_path, "w", encoding="utf-8") as f:
        f.write(exec_md)
    paths["executive_summary_md"] = exec_path

    return paths


# -----------------------------
# Evidence / Bundling
# -----------------------------
def create_evidence_manifest(report_path: str) -> str:
    manifest: Dict[str, Any] = {}
    for root, _, files in os.walk(report_path):
        for file in files:
            filepath = os.path.join(root, file)
            relative_filepath = os.path.relpath(filepath, report_path)
            manifest[relative_filepath] = {
                "hash_sha256": compute_sha256(filepath),
                "size_bytes": os.path.getsize(filepath),
            }
    manifest_filepath = os.path.join(report_path, "evidence_manifest.json")
    with open(manifest_filepath, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=4)
    return manifest_filepath


def bundle_artifacts_to_zip(report_path: str, run_id: str, output_dir: str = ".") -> str:
    zip_filename = os.path.join(output_dir, f"Session_12_{run_id}.zip")
    with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(report_path):
            for file in files:
                filepath = os.path.join(root, file)
                zipf.write(filepath, os.path.relpath(
                    filepath, os.path.dirname(report_path)))
    return zip_filename
