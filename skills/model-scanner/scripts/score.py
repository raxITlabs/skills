"""
Risk scoring engine for ML model supply chain security.

Starts at 100, deducts points for risk factors. Transparent, explainable, deterministic.

Score bands:
  90-100  GOOD      (green)
  70-89   MODERATE  (yellow)
  50-69   POOR      (orange)
  0-49    CRITICAL  (red)
"""

from __future__ import annotations


def score_band(score: int) -> str:
    if score >= 90:
        return "GOOD"
    elif score >= 70:
        return "MODERATE"
    elif score >= 50:
        return "POOR"
    else:
        return "CRITICAL"


def calculate_score(scan_results: list[dict], hf_models: list[dict] | None = None) -> tuple[int, list[tuple[str, int]]]:
    """
    Calculate risk score from scan results and HF model metadata.

    Args:
        scan_results: List of per-file scan result dicts (from format_json)
        hf_models: List of detected HuggingFace model metadata dicts

    Returns:
        (score, breakdown) where breakdown is list of (reason, deduction)
    """
    score = 100
    breakdown = []
    hf_models = hf_models or []

    # Collect all extensions for SafeTensors-available check
    all_extensions = {r.get("extension", "") for r in scan_results}
    has_safetensors = ".safetensors" in all_extensions

    # --- Per-file deductions ---

    seen_verdicts = set()
    pickle_count = 0
    malicious_count = 0

    for result in scan_results:
        ext = result.get("extension", "")
        verdict = result.get("overall_verdict", "SAFE")
        filename = result.get("filename", "unknown")

        # Format deductions
        if ext in (".pkl", ".pickle", ".pt", ".pth", ".bin", ".joblib"):
            pickle_count += 1
            if has_safetensors:
                deduction = -20
                reason = f"Executable format ({ext}) with SafeTensors alternative available: {filename}"
            else:
                deduction = -15
                reason = f"Executable format ({ext}), no SafeTensors alternative: {filename}"
            score += deduction
            breakdown.append((reason, deduction))

        # Scanner verdict deductions
        if verdict == "MALICIOUS" and "malicious" not in seen_verdicts:
            malicious_count += 1
            deduction = -40
            score += deduction
            breakdown.append((f"Malicious code detected: {filename}", deduction))
            seen_verdicts.add("malicious")
        elif verdict == "MALICIOUS":
            malicious_count += 1
            # Additional malicious files after the first get smaller deduction
            deduction = -10
            score += deduction
            breakdown.append((f"Additional malicious file: {filename}", deduction))

        if verdict == "SUSPICIOUS":
            deduction = -15
            score += deduction
            breakdown.append((f"Suspicious findings: {filename}", deduction))

        # Check for scanner disagreement
        scanners = result.get("scanners", [])
        active_verdicts = {
            s["verdict"] for s in scanners
            if s.get("available") and s["verdict"] not in ("ERROR",)
            and "Not applicable" not in str(s.get("details", []))
        }
        if len(active_verdicts) > 1 and "MALICIOUS" not in active_verdicts:
            deduction = -8
            score += deduction
            breakdown.append((f"Scanner disagreement on: {filename}", deduction))

    # --- HuggingFace config deductions ---

    for model in hf_models:
        dir_name = model.get("dir", "").split("/")[-1]

        if model.get("trust_remote_code"):
            deduction = -10
            score += deduction
            breakdown.append((f"trust_remote_code: true in {dir_name}/config.json", deduction))

        if model.get("auto_map"):
            deduction = -8
            score += deduction
            breakdown.append((f"auto_map loads custom Python in {dir_name}/", deduction))

    # --- Supply chain deductions ---
    # No provenance check available in v1, but deduct if no HF source
    for model in hf_models:
        if not model.get("hf_id"):
            deduction = -5
            score += deduction
            dir_name = model.get("dir", "").split("/")[-1]
            breakdown.append((f"No verified source/provenance for {dir_name}/", deduction))

    # Clamp to 0-100
    score = max(0, min(100, score))

    return score, breakdown


def format_score_report(score: int, breakdown: list[tuple[str, int]]) -> str:
    """Format score as a markdown section."""
    band = score_band(score)
    lines = [
        f"## Risk Score: {score}/100 ({band})",
        "",
    ]

    if not breakdown:
        lines.append("No risk factors identified.")
    else:
        for reason, deduction in breakdown:
            lines.append(f"  {deduction:+d}  {reason}")

    lines.append("")
    return "\n".join(lines)


def format_score_json(score: int, breakdown: list[tuple[str, int]]) -> dict:
    """Format score as JSON-serializable dict."""
    return {
        "score": score,
        "band": score_band(score),
        "breakdown": [
            {"reason": reason, "deduction": deduction}
            for reason, deduction in breakdown
        ],
    }
