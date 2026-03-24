"""
Remediation engine for ML model security findings.

Returns actionable, specific fix steps ordered by impact.
"""

from __future__ import annotations


# Remediation lookup: finding type → (priority, action)
# Lower priority number = fix first
REMEDIATION_MAP: dict[str, tuple[int, str]] = {
    "malicious_code": (
        1,
        "DELETE or quarantine the file immediately. Do not load with torch.load() or pickle.load(). "
        "If from HuggingFace, report via https://huggingface.co/docs/hub/security"
    ),
    "executable_with_alt": (
        2,
        "Remove the pickle file and use the SafeTensors version instead. "
        "SafeTensors is non-executable by design. Update loading code to use safetensors library."
    ),
    "trust_remote_code": (
        3,
        "Set trust_remote_code: false in config.json. If the model requires custom code, "
        "audit modeling_*.py files manually before enabling. Look for os.*, subprocess, "
        "network calls, and env variable access."
    ),
    "auto_map": (
        4,
        "Review the Python files referenced by auto_map in config.json. "
        "Model scanners do NOT analyze these files. Check for: os.environ access, "
        "network calls, file writes, subprocess execution, eval/exec usage."
    ),
    "executable_format": (
        5,
        "Convert model to SafeTensors format for ISM-2072 compliance. "
        "Use: python -c \"import torch; from safetensors.torch import save_file; "
        "save_file(torch.load('model.pt', weights_only=True), 'model.safetensors')\" "
        "Or check HuggingFace for an existing SafeTensors conversion."
    ),
    "suspicious_code": (
        6,
        "Review flagged imports manually. Scanner disagreement means the finding is ambiguous. "
        "Consider running dynamic analysis in a sandbox: pip install dyana && dyana scan <file>. "
        "If the model is from HuggingFace, check the model page for community reports."
    ),
    "no_provenance": (
        7,
        "Verify model source. If from HuggingFace, confirm the repo owner is the expected organization. "
        "Check for model signatures (OpenSSF Model Signing). Avoid loading models from unknown sources."
    ),
}


def get_remediation(finding_types: set[str]) -> list[dict]:
    """
    Get ordered remediation steps for a set of finding types.

    Returns list of {priority, finding, action} dicts, sorted by priority (most urgent first).
    """
    steps = []
    for finding_type in finding_types:
        entry = REMEDIATION_MAP.get(finding_type)
        if entry:
            priority, action = entry
            steps.append({
                "priority": priority,
                "finding": finding_type,
                "action": action,
            })

    return sorted(steps, key=lambda s: s["priority"])


def format_remediation_report(steps: list[dict]) -> str:
    """Format remediation as markdown."""
    if not steps:
        return "## Remediation\n\nNo actions needed.\n"

    lines = ["## Remediation", ""]
    for i, step in enumerate(steps, 1):
        lines.append(f"{i}. **{step['finding'].replace('_', ' ').title()}**: {step['action']}")
        lines.append("")

    return "\n".join(lines)


def format_remediation_json(steps: list[dict]) -> list[dict]:
    """Format remediation as JSON-serializable list."""
    return steps
