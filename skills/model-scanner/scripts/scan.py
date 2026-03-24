# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
Multi-scanner ML model security analysis.

Runs model files through available scanners (Fickling, ModelScan, PickleScan, ModelAudit)
and aggregates results into a verdict.

Usage:
    uv run scripts/scan.py <path> [--verbose] [--json] [--install]
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Verdict(Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    FORMAT_SAFE = "FORMAT_SAFE"
    ERROR = "ERROR"


@dataclass
class ScannerResult:
    scanner: str
    available: bool
    verdict: Verdict
    details: list[str] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""


SAFE_EXTENSIONS = {".safetensors", ".gguf", ".onnx"}

SCANNABLE_EXTENSIONS = {
    ".pkl", ".pickle", ".pt", ".pth", ".bin", ".joblib",
    ".npy", ".h5", ".keras", ".pb",
    ".safetensors", ".onnx",
    ".json", ".yaml", ".yml",
}


def check_tool(name: str, check_cmd: list[str]) -> bool:
    try:
        subprocess.run(check_cmd, capture_output=True, timeout=10)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def detect_available_scanners() -> dict[str, bool]:
    return {
        "fickling": check_tool("fickling", ["fickling", "--help"]),
        "modelscan": check_tool("modelscan", ["modelscan", "--help"]),
        "picklescan": check_tool("picklescan", ["picklescan", "--help"]),
        "modelaudit": check_tool("modelaudit", ["promptfoo", "scan-model", "--help"]),
    }


def install_scanners() -> None:
    print("\n--- Installing scanners ---")

    pip_packages = ["fickling", "modelscan", "picklescan"]
    print(f"Installing Python scanners: {', '.join(pip_packages)}")
    subprocess.run(
        [sys.executable, "-m", "pip", "install", *pip_packages],
        capture_output=False,
    )

    if shutil.which("npm"):
        print("Installing ModelAudit (promptfoo)...")
        subprocess.run(["npm", "install", "-g", "promptfoo"], capture_output=False)
    else:
        print("npm not found, skipping ModelAudit install")

    print("--- Installation complete ---\n")


def run_fickling(path: Path, verbose: bool) -> ScannerResult:
    result = ScannerResult(scanner="fickling", available=True, verdict=Verdict.SAFE)
    try:
        proc = subprocess.run(
            ["fickling", "--check-safety", str(path)],
            capture_output=True, text=True, timeout=120,
        )
        result.raw_output = proc.stdout + proc.stderr
        output = result.raw_output.lower()

        if proc.returncode != 0 and ("error" in output or "traceback" in output):
            if "not a valid pickle" in output or "unsupported" in output:
                result.verdict = Verdict.SAFE
                result.details.append("File format not applicable to Fickling")
            else:
                result.verdict = Verdict.ERROR
                result.error = proc.stderr[:500]
        elif "malicious" in output or "unsafe" in output or "dangerous" in output:
            result.verdict = Verdict.MALICIOUS
            for line in result.raw_output.splitlines():
                line_lower = line.lower()
                if any(w in line_lower for w in ["unsafe", "malicious", "dangerous", "import", "call"]):
                    result.details.append(line.strip())
        elif "suspicious" in output or "warning" in output or "unknown" in output:
            result.verdict = Verdict.SUSPICIOUS
            for line in result.raw_output.splitlines():
                if any(w in line.lower() for w in ["suspicious", "warning", "unknown"]):
                    result.details.append(line.strip())
        else:
            result.verdict = Verdict.SAFE
            result.details.append("No unsafe imports detected (allowlist-based)")

    except subprocess.TimeoutExpired:
        result.verdict = Verdict.ERROR
        result.error = "Timed out after 120s"
    except Exception as e:
        result.verdict = Verdict.ERROR
        result.error = str(e)

    return result


def run_modelscan(path: Path, verbose: bool) -> ScannerResult:
    result = ScannerResult(scanner="modelscan", available=True, verdict=Verdict.SAFE)
    try:
        proc = subprocess.run(
            ["modelscan", "--path", str(path), "-r", "json"],
            capture_output=True, text=True, timeout=120,
        )
        result.raw_output = proc.stdout + proc.stderr

        try:
            data = json.loads(proc.stdout)
            issues = data.get("issues", [])
            if not issues:
                result.verdict = Verdict.SAFE
                result.details.append("No issues found")
            else:
                severities = [i.get("severity", "").upper() for i in issues]
                if "CRITICAL" in severities or "HIGH" in severities:
                    result.verdict = Verdict.MALICIOUS
                elif "MEDIUM" in severities:
                    result.verdict = Verdict.SUSPICIOUS
                else:
                    result.verdict = Verdict.SUSPICIOUS

                for issue in issues[:10]:
                    desc = issue.get("description", issue.get("operator", "Unknown issue"))
                    sev = issue.get("severity", "unknown")
                    result.details.append(f"[{sev}] {desc}")
        except json.JSONDecodeError:
            output = result.raw_output.lower()
            if "no issues" in output or proc.returncode == 0:
                result.verdict = Verdict.SAFE
                result.details.append("No issues found")
            elif "unsafe" in output or "critical" in output:
                result.verdict = Verdict.MALICIOUS
                result.details.append(proc.stdout[:500])
            else:
                result.verdict = Verdict.SUSPICIOUS
                result.details.append(f"Non-JSON output: {proc.stdout[:300]}")

    except subprocess.TimeoutExpired:
        result.verdict = Verdict.ERROR
        result.error = "Timed out after 120s"
    except Exception as e:
        result.verdict = Verdict.ERROR
        result.error = str(e)

    return result


def run_picklescan(path: Path, verbose: bool) -> ScannerResult:
    result = ScannerResult(scanner="picklescan", available=True, verdict=Verdict.SAFE)
    try:
        proc = subprocess.run(
            ["picklescan", "--path", str(path)],
            capture_output=True, text=True, timeout=120,
        )
        result.raw_output = proc.stdout + proc.stderr
        output = result.raw_output.lower()

        if "dangerous" in output or "unsafe" in output or "malicious" in output:
            result.verdict = Verdict.MALICIOUS
            for line in result.raw_output.splitlines():
                if any(w in line.lower() for w in ["dangerous", "unsafe", "malicious", "global"]):
                    result.details.append(line.strip())
        elif "suspicious" in output or "warning" in output:
            result.verdict = Verdict.SUSPICIOUS
            result.details.append("Suspicious imports detected")
        elif proc.returncode == 0:
            result.verdict = Verdict.SAFE
            result.details.append("No dangerous imports found (denylist-based)")
        else:
            result.verdict = Verdict.ERROR
            result.error = proc.stderr[:500]

    except subprocess.TimeoutExpired:
        result.verdict = Verdict.ERROR
        result.error = "Timed out after 120s"
    except Exception as e:
        result.verdict = Verdict.ERROR
        result.error = str(e)

    return result


def run_modelaudit(path: Path, verbose: bool) -> ScannerResult:
    result = ScannerResult(scanner="modelaudit", available=True, verdict=Verdict.SAFE)
    try:
        proc = subprocess.run(
            ["promptfoo", "scan-model", str(path), "--output", "json"],
            capture_output=True, text=True, timeout=120,
        )
        result.raw_output = proc.stdout + proc.stderr

        try:
            data = json.loads(proc.stdout)
            findings = data.get("findings", data.get("results", []))
            if not findings:
                result.verdict = Verdict.SAFE
                result.details.append("No findings")
            else:
                severities = [f.get("severity", "").upper() for f in findings if isinstance(f, dict)]
                if "CRITICAL" in severities or "HIGH" in severities:
                    result.verdict = Verdict.MALICIOUS
                elif "MEDIUM" in severities:
                    result.verdict = Verdict.SUSPICIOUS
                else:
                    result.verdict = Verdict.SUSPICIOUS

                for finding in findings[:10]:
                    if isinstance(finding, dict):
                        msg = finding.get("message", finding.get("rule", "Unknown"))
                        sev = finding.get("severity", "unknown")
                        result.details.append(f"[{sev}] {msg}")
        except json.JSONDecodeError:
            if proc.returncode == 0:
                result.verdict = Verdict.SAFE
                result.details.append("No issues detected")
            else:
                result.verdict = Verdict.SUSPICIOUS
                result.details.append(f"Non-JSON output: {proc.stdout[:300]}")

    except subprocess.TimeoutExpired:
        result.verdict = Verdict.ERROR
        result.error = "Timed out after 120s"
    except Exception as e:
        result.verdict = Verdict.ERROR
        result.error = str(e)

    return result


def aggregate_verdict(results: list[ScannerResult]) -> Verdict:
    active = [r for r in results if r.available and r.verdict != Verdict.ERROR]
    if not active:
        return Verdict.ERROR

    verdicts = [r.verdict for r in active]

    if Verdict.MALICIOUS in verdicts:
        return Verdict.MALICIOUS
    if Verdict.SUSPICIOUS in verdicts:
        return Verdict.SUSPICIOUS
    if all(v == Verdict.FORMAT_SAFE for v in verdicts):
        return Verdict.FORMAT_SAFE
    return Verdict.SAFE


def format_report(path: Path, results: list[ScannerResult], overall: Verdict) -> str:
    lines = []
    lines.append(f"# Model Security Scan Report")
    lines.append(f"")
    lines.append(f"**File:** `{path}`")
    lines.append(f"**Size:** {path.stat().st_size:,} bytes")
    lines.append(f"**Extension:** `{path.suffix}`")
    lines.append(f"")

    verdict_symbols = {
        Verdict.SAFE: "SAFE",
        Verdict.FORMAT_SAFE: "FORMAT_SAFE (non-executable format)",
        Verdict.SUSPICIOUS: "SUSPICIOUS",
        Verdict.MALICIOUS: "MALICIOUS",
        Verdict.ERROR: "ERROR",
    }
    lines.append(f"## Overall Verdict: {verdict_symbols.get(overall, str(overall))}")
    lines.append(f"")

    lines.append(f"## Scanner Results")
    lines.append(f"")

    for r in results:
        if not r.available:
            lines.append(f"### {r.scanner} (not installed)")
            lines.append(f"")
            continue

        status = verdict_symbols.get(r.verdict, str(r.verdict))
        lines.append(f"### {r.scanner}: {status}")
        if r.details:
            for d in r.details:
                lines.append(f"- {d}")
        if r.error:
            lines.append(f"- Error: {r.error}")
        lines.append(f"")

    lines.append(f"## Recommendations")
    lines.append(f"")

    if overall == Verdict.MALICIOUS:
        lines.append(f"- DO NOT load this model. Malicious code detected.")
        lines.append(f"- Delete the file or quarantine it for further analysis.")
        lines.append(f"- If downloaded from HuggingFace, report it via their security contact.")
    elif overall == Verdict.SUSPICIOUS:
        lines.append(f"- Exercise caution. Some scanners flagged concerns.")
        lines.append(f"- Review the flagged imports manually before loading.")
        lines.append(f"- Consider running dynamic analysis (Dyana) in a sandbox.")
        lines.append(f"- If possible, find a SafeTensors version of this model.")
    elif overall == Verdict.FORMAT_SAFE:
        lines.append(f"- Model uses a non-executable format. Weight data cannot contain code.")
        lines.append(f"- Check if the model repo uses `trust_remote_code=True` or `auto_map` in config.json.")
        lines.append(f"- If so, the Python code loaded alongside weights is NOT covered by this scan.")
    else:
        lines.append(f"- No issues detected by any scanner.")
        lines.append(f"- Note: static scanners have known bypass techniques (133+ documented).")
        lines.append(f"- For high-value deployments, also run dynamic analysis in a sandbox.")

    lines.append(f"")
    lines.append(f"---")
    lines.append(f"*Scanned by raxIT model-scanner (Fickling + ModelScan + PickleScan + ModelAudit)*")

    return "\n".join(lines)


def format_json_report(path: Path, results: list[ScannerResult], overall: Verdict) -> str:
    return json.dumps({
        "file": str(path),
        "size_bytes": path.stat().st_size,
        "extension": path.suffix,
        "overall_verdict": overall.value,
        "scanners": [
            {
                "name": r.scanner,
                "available": r.available,
                "verdict": r.verdict.value,
                "details": r.details,
                "error": r.error or None,
            }
            for r in results
        ],
    }, indent=2)


def scan_file(path: Path, available: dict[str, bool], verbose: bool) -> tuple[list[ScannerResult], Verdict]:
    ext = path.suffix.lower()

    if ext in SAFE_EXTENSIONS:
        results = []
        for name, is_available in available.items():
            if name == "modelaudit" and is_available:
                results.append(run_modelaudit(path, verbose))
            else:
                r = ScannerResult(scanner=name, available=is_available, verdict=Verdict.FORMAT_SAFE)
                r.details.append(f"Non-executable format ({ext}), skipping")
                results.append(r)
        return results, aggregate_verdict(results)

    scanners = {
        "fickling": run_fickling,
        "modelscan": run_modelscan,
        "picklescan": run_picklescan,
        "modelaudit": run_modelaudit,
    }

    results = []
    for name, run_fn in scanners.items():
        if available.get(name):
            if verbose:
                print(f"Running {name}...")
            results.append(run_fn(path, verbose))
        else:
            results.append(ScannerResult(scanner=name, available=False, verdict=Verdict.ERROR))

    return results, aggregate_verdict(results)


def find_model_files(directory: Path) -> list[Path]:
    files = []
    for f in directory.rglob("*"):
        if f.is_file() and f.suffix.lower() in SCANNABLE_EXTENSIONS:
            files.append(f)
    return sorted(files)


def main():
    parser = argparse.ArgumentParser(description="Multi-scanner ML model security analysis")
    parser.add_argument("path", help="Path to model file or directory")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed output")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--install", action="store_true", help="Install missing scanners")
    args = parser.parse_args()

    path = Path(args.path)
    if not path.exists():
        print(f"Error: {path} does not exist", file=sys.stderr)
        sys.exit(1)

    available = detect_available_scanners()
    installed_count = sum(available.values())

    if installed_count == 0:
        print("No scanners installed.", file=sys.stderr)
        if args.install:
            install_scanners()
            available = detect_available_scanners()
            installed_count = sum(available.values())
            if installed_count == 0:
                print("Installation failed. Install manually:", file=sys.stderr)
                print("  pip install fickling modelscan picklescan", file=sys.stderr)
                print("  npm install -g promptfoo", file=sys.stderr)
                sys.exit(1)
        else:
            print("Run with --install to auto-install, or install manually:", file=sys.stderr)
            print("  pip install fickling modelscan picklescan", file=sys.stderr)
            print("  npm install -g promptfoo", file=sys.stderr)
            sys.exit(1)

    if not args.json:
        print(f"Available scanners: {', '.join(k for k, v in available.items() if v)} ({installed_count}/4)")
        missing = [k for k, v in available.items() if not v]
        if missing:
            print(f"Not installed: {', '.join(missing)}")
        print()

    if path.is_dir():
        files = find_model_files(path)
        if not files:
            print(f"No model files found in {path}", file=sys.stderr)
            sys.exit(1)
        if not args.json:
            print(f"Found {len(files)} model file(s) in {path}\n")
    else:
        files = [path]

    all_reports = []
    for f in files:
        if not args.json:
            print(f"Scanning: {f}")
            print("-" * 60)

        results, overall = scan_file(f, available, args.verbose)

        if args.json:
            all_reports.append(json.loads(format_json_report(f, results, overall)))
        else:
            print(format_report(f, results, overall))
            print()

    if args.json:
        if len(all_reports) == 1:
            print(json.dumps(all_reports[0], indent=2))
        else:
            print(json.dumps(all_reports, indent=2))

    worst = Verdict.SAFE
    for f in files:
        results, overall = scan_file(f, available, False)
        if overall == Verdict.MALICIOUS:
            worst = Verdict.MALICIOUS
            break
        elif overall == Verdict.SUSPICIOUS and worst != Verdict.MALICIOUS:
            worst = Verdict.SUSPICIOUS

    sys.exit(0 if worst in (Verdict.SAFE, Verdict.FORMAT_SAFE) else 1)


if __name__ == "__main__":
    main()
