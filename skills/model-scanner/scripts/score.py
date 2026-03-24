"""
Risk scoring engine for ML model supply chain security.

Starts at 100, deducts points for risk factors. Transparent, explainable, deterministic.

Deductions are capped per category to prevent score collapse when a project
has many pickle files (common in real ML projects). A project with 10 legit
pickle files should not score the same as one with a malicious backdoor.

Score bands:
  90-100  GOOD      (green)
  70-89   MODERATE  (yellow)
  50-69   POOR      (orange)
  0-49    CRITICAL  (red)
"""

from __future__ import annotations


# Category caps prevent score collapse
FORMAT_DEDUCTION_CAP = -30    # Max total deduction for executable formats
SCANNER_DEDUCTION_CAP = -50   # Max total deduction for scanner findings
CONFIG_DEDUCTION_CAP = -15    # Max total deduction for config issues
PROVENANCE_DEDUCTION_CAP = -10  # Max total deduction for provenance


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

    Returns:
        (score, breakdown) where breakdown is list of (reason, deduction)
    """
    score = 100
    breakdown = []
    hf_models = hf_models or []

    all_extensions = {r.get("extension", "") for r in scan_results}
    has_safetensors = ".safetensors" in all_extensions
    pickle_exts = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".joblib"}

    # --- Format deductions (capped) ---
    format_total = 0
    pickle_files = [r for r in scan_results if r.get("extension", "") in pickle_exts]

    if pickle_files:
        if has_safetensors:
            # Worse: you HAVE safe format but still use pickle
            per_file = -8
            reason_suffix = "with SafeTensors alternative available"
        else:
            per_file = -5
            reason_suffix = "no SafeTensors alternative"

        raw_deduction = per_file * len(pickle_files)
        capped = max(raw_deduction, FORMAT_DEDUCTION_CAP)
        format_total = capped
        score += capped
        breakdown.append((
            f"{len(pickle_files)} file(s) in executable format ({reason_suffix})",
            capped,
        ))

    # --- Scanner verdict deductions (capped) ---
    scanner_total = 0

    malicious_files = [r for r in scan_results if r.get("overall_verdict") == "MALICIOUS"]
    suspicious_files = [r for r in scan_results if r.get("overall_verdict") == "SUSPICIOUS"]

    if malicious_files:
        # First malicious file is a big deal
        deduction = -40
        scanner_total += deduction
        names = ", ".join(r.get("filename", "?") for r in malicious_files[:3])
        breakdown.append((f"Malicious code detected: {names}", deduction))

        # Additional malicious files compound but less
        if len(malicious_files) > 1:
            extra = min(-5 * (len(malicious_files) - 1), 0)
            extra = max(extra, -10)  # Cap additional at -10
            scanner_total += extra
            breakdown.append((f"{len(malicious_files) - 1} additional malicious file(s)", extra))

    if suspicious_files:
        deduction = max(-8 * len(suspicious_files), -15)  # Cap suspicious at -15
        scanner_total += deduction
        names = ", ".join(r.get("filename", "?") for r in suspicious_files[:3])
        breakdown.append((f"Suspicious findings in {len(suspicious_files)} file(s): {names}", deduction))

    # Scanner disagreements (only for non-malicious files)
    disagreement_count = 0
    for result in scan_results:
        if result.get("overall_verdict") in ("MALICIOUS",):
            continue
        scanners = result.get("scanners", [])
        active_verdicts = {
            s["verdict"] for s in scanners
            if s.get("available") and s["verdict"] not in ("ERROR",)
            and "Not applicable" not in str(s.get("details", []))
        }
        if len(active_verdicts) > 1:
            disagreement_count += 1

    if disagreement_count:
        deduction = max(-3 * disagreement_count, -8)  # Cap at -8
        scanner_total += deduction
        breakdown.append((f"Scanner disagreement on {disagreement_count} file(s)", deduction))

    # Apply capped scanner total
    scanner_total = max(scanner_total, SCANNER_DEDUCTION_CAP)
    score += scanner_total

    # --- Config deductions (capped) ---
    config_total = 0

    for model in hf_models:
        dir_name = model.get("dir", "").split("/")[-1]

        if model.get("trust_remote_code"):
            deduction = -10
            config_total += deduction
            breakdown.append((f"trust_remote_code: true in {dir_name}/config.json", deduction))

        if model.get("auto_map"):
            deduction = -5
            config_total += deduction
            breakdown.append((f"auto_map loads custom Python in {dir_name}/", deduction))

    config_total = max(config_total, CONFIG_DEDUCTION_CAP)
    score += config_total

    # --- Provenance deductions (capped) ---
    provenance_total = 0

    unverified = [m for m in hf_models if not m.get("hf_id")]
    if unverified:
        deduction = max(-3 * len(unverified), PROVENANCE_DEDUCTION_CAP)
        provenance_total = deduction
        score += deduction
        breakdown.append((f"{len(unverified)} model(s) with no verified source/provenance", deduction))

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
