"""
Global compliance mapping for ML model security findings.

Maps finding types to controls across 5 frameworks:
  - ISM (Australian Information Security Manual)
  - EU AI Act
  - OWASP LLM Top 10
  - MITRE ATLAS
  - NIST AI RMF

Deterministic. No LLM inference. Static mapping.
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass
class ComplianceRef:
    framework: str
    control_id: str
    status: str  # PASS, FAIL, WARN, N/A
    title: str
    evidence: str


# Finding types that trigger compliance checks
FINDING_TYPES = {
    "executable_format",       # Pickle/joblib used
    "executable_with_alt",     # Pickle used but SafeTensors available
    "malicious_code",          # Scanner detected malicious payload
    "suspicious_code",         # Scanner flagged suspicious imports
    "trust_remote_code",       # config.json has trust_remote_code: true
    "auto_map",                # config.json has auto_map (loads custom Python)
    "no_provenance",           # No verified source for the model
    "format_safe",             # SafeTensors/ONNX/GGUF used
}

# Static compliance mapping
COMPLIANCE_MAP: dict[str, list[ComplianceRef]] = {
    "executable_format": [
        ComplianceRef("ISM", "ISM-2072", "FAIL",
            "AI models must be stored in non-executable formats",
            "Model uses pickle/joblib format which allows arbitrary code execution"),
        ComplianceRef("OWASP", "LLM06", "FAIL",
            "Supply Chain Vulnerabilities",
            "Executable model format enables code injection via deserialization"),
        ComplianceRef("MITRE", "AML.T0010", "WARN",
            "ML Supply Chain Compromise",
            "Model file format permits embedded code execution on load"),
        ComplianceRef("EU-AI-ACT", "Art.15", "WARN",
            "Accuracy, robustness and cybersecurity",
            "Executable format exposes system to model poisoning attacks"),
        ComplianceRef("NIST", "MAP 3.4", "WARN",
            "AI supply chain risk management",
            "Model stored in format that does not support integrity verification"),
    ],
    "executable_with_alt": [
        ComplianceRef("ISM", "ISM-2072", "FAIL",
            "AI models must be stored in non-executable formats",
            "Non-executable alternative (SafeTensors) exists but pickle still present"),
        ComplianceRef("OWASP", "LLM06", "FAIL",
            "Supply Chain Vulnerabilities",
            "Safe format available but not used — unnecessary risk"),
    ],
    "malicious_code": [
        ComplianceRef("ISM", "ISM-2072", "FAIL",
            "AI models must be stored in non-executable formats",
            "Confirmed malicious code detected in model file"),
        ComplianceRef("ISM", "ISM-2086", "FAIL",
            "Verify source and integrity of AI models",
            "Model contains code that was not part of legitimate training"),
        ComplianceRef("EU-AI-ACT", "Art.15", "FAIL",
            "Accuracy, robustness and cybersecurity",
            "Model compromised with malicious payload"),
        ComplianceRef("OWASP", "LLM06", "FAIL",
            "Supply Chain Vulnerabilities",
            "Malicious code in model supply chain"),
        ComplianceRef("MITRE", "AML.T0010.002", "FAIL",
            "ML Supply Chain Compromise: Backdoor ML Model",
            "Confirmed backdoor payload in model file"),
        ComplianceRef("NIST", "MANAGE 2.4", "FAIL",
            "Mechanisms for tracking identified AI risks over time",
            "Active threat detected — model compromised"),
    ],
    "suspicious_code": [
        ComplianceRef("ISM", "ISM-2072", "WARN",
            "AI models must be stored in non-executable formats",
            "Suspicious imports detected — may be legitimate or malicious"),
        ComplianceRef("OWASP", "LLM06", "WARN",
            "Supply Chain Vulnerabilities",
            "Ambiguous model content requires manual review"),
        ComplianceRef("MITRE", "AML.T0010", "WARN",
            "ML Supply Chain Compromise",
            "Suspicious patterns consistent with known attack techniques"),
    ],
    "trust_remote_code": [
        ComplianceRef("ISM", "ISM-2092", "WARN",
            "Fine-grained access control for AI applications",
            "trust_remote_code allows execution of arbitrary Python from model repo"),
        ComplianceRef("EU-AI-ACT", "Art.15", "WARN",
            "Accuracy, robustness and cybersecurity",
            "Uncontrolled code execution path via trust_remote_code"),
        ComplianceRef("OWASP", "LLM06", "WARN",
            "Supply Chain Vulnerabilities",
            "Remote code execution enabled in model configuration"),
        ComplianceRef("MITRE", "AML.T0010", "WARN",
            "ML Supply Chain Compromise",
            "Configuration enables loading of unverified external code"),
        ComplianceRef("NIST", "MAP 3.4", "WARN",
            "AI supply chain risk management",
            "Model loading executes unaudited code from external source"),
    ],
    "auto_map": [
        ComplianceRef("ISM", "ISM-2092", "WARN",
            "Fine-grained access control for AI applications",
            "auto_map loads custom Python files that are not scanned by model scanners"),
        ComplianceRef("OWASP", "LLM06", "WARN",
            "Supply Chain Vulnerabilities",
            "Custom modeling code loaded outside scanner coverage"),
    ],
    "no_provenance": [
        ComplianceRef("ISM", "ISM-2086", "WARN",
            "Verify source and integrity of AI models",
            "No verified source or signature for this model"),
        ComplianceRef("ISM", "ISM-2087", "WARN",
            "Verify source and integrity of training data",
            "Training data provenance unknown"),
        ComplianceRef("EU-AI-ACT", "Art.15", "WARN",
            "Accuracy, robustness and cybersecurity",
            "Model provenance not established"),
        ComplianceRef("NIST", "MANAGE 4.1", "WARN",
            "Post-deployment AI system monitoring",
            "Model source unverified — cannot establish supply chain trust"),
    ],
    "format_safe": [
        ComplianceRef("ISM", "ISM-2072", "PASS",
            "AI models must be stored in non-executable formats",
            "Model uses non-executable format (SafeTensors/ONNX/GGUF)"),
        ComplianceRef("OWASP", "LLM06", "PASS",
            "Supply Chain Vulnerabilities",
            "Non-executable format eliminates deserialization attack surface"),
    ],
}


def classify_findings(scan_results: list[dict], hf_models: list[dict] | None = None) -> set[str]:
    """
    Determine which finding types apply based on scan results and HF metadata.
    """
    findings = set()
    hf_models = hf_models or []

    all_extensions = {r.get("extension", "") for r in scan_results}
    has_safetensors = ".safetensors" in all_extensions
    pickle_exts = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".joblib"}
    safe_exts = {".safetensors", ".onnx", ".gguf"}

    for result in scan_results:
        ext = result.get("extension", "")
        verdict = result.get("overall_verdict", "SAFE")

        if ext in pickle_exts:
            findings.add("executable_format")
            if has_safetensors:
                findings.add("executable_with_alt")

        if ext in safe_exts:
            findings.add("format_safe")

        if verdict == "MALICIOUS":
            findings.add("malicious_code")
        elif verdict == "SUSPICIOUS":
            findings.add("suspicious_code")

    for model in hf_models:
        if model.get("trust_remote_code"):
            findings.add("trust_remote_code")
        if model.get("auto_map"):
            findings.add("auto_map")
        if not model.get("hf_id"):
            findings.add("no_provenance")

    return findings


def map_compliance(scan_results: list[dict], hf_models: list[dict] | None = None) -> dict[str, list[ComplianceRef]]:
    """
    Map findings to compliance framework controls.

    Returns dict keyed by framework name, with list of ComplianceRefs.
    """
    finding_types = classify_findings(scan_results, hf_models)

    # Collect all refs grouped by framework
    by_framework: dict[str, list[ComplianceRef]] = {}

    for finding_type in finding_types:
        refs = COMPLIANCE_MAP.get(finding_type, [])
        for ref in refs:
            by_framework.setdefault(ref.framework, []).append(ref)

    # Deduplicate: if same control_id appears multiple times, keep worst status
    status_priority = {"FAIL": 3, "WARN": 2, "PASS": 1, "N/A": 0}

    for framework in by_framework:
        seen: dict[str, ComplianceRef] = {}
        for ref in by_framework[framework]:
            existing = seen.get(ref.control_id)
            if not existing or status_priority.get(ref.status, 0) > status_priority.get(existing.status, 0):
                seen[ref.control_id] = ref
        by_framework[framework] = sorted(seen.values(), key=lambda r: -status_priority.get(r.status, 0))

    return by_framework


def format_compliance_report(compliance: dict[str, list[ComplianceRef]]) -> str:
    """Format compliance results as markdown."""
    if not compliance:
        return "## Compliance\n\nNo compliance-relevant findings.\n"

    lines = ["## Compliance", ""]

    framework_order = ["ISM", "EU-AI-ACT", "OWASP", "MITRE", "NIST"]
    framework_names = {
        "ISM": "Australian ISM",
        "EU-AI-ACT": "EU AI Act",
        "OWASP": "OWASP LLM Top 10",
        "MITRE": "MITRE ATLAS",
        "NIST": "NIST AI RMF",
    }

    for fw in framework_order:
        refs = compliance.get(fw, [])
        if not refs:
            continue

        name = framework_names.get(fw, fw)
        lines.append(f"### {name}")

        for ref in refs:
            status_marker = {"FAIL": "FAIL", "WARN": "WARN", "PASS": "PASS"}.get(ref.status, ref.status)
            lines.append(f"- **{ref.control_id}** {status_marker} — {ref.title}")
            lines.append(f"  {ref.evidence}")

        lines.append("")

    return "\n".join(lines)


def format_compliance_json(compliance: dict[str, list[ComplianceRef]]) -> dict:
    """Format compliance as JSON-serializable dict."""
    return {
        framework: [
            {
                "control_id": ref.control_id,
                "status": ref.status,
                "title": ref.title,
                "evidence": ref.evidence,
            }
            for ref in refs
        ]
        for framework, refs in compliance.items()
    }
