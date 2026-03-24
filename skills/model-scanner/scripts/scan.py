# /// script
# requires-python = ">=3.10"
# dependencies = ["huggingface_hub"]
# ///
"""
Multi-scanner ML model security analysis. Zero-config.

Auto-installs scanners on first run. Downloads HuggingFace models by ID.
Runs model files through all available scanners and aggregates results.

Usage:
    uv run scripts/scan.py <path-or-hf-model-id> [--verbose] [--json]

Examples:
    uv run scripts/scan.py model.pkl
    uv run scripts/scan.py ./models/
    uv run scripts/scan.py microsoft/phi-2
    uv run scripts/scan.py deepseek-ai/deepseek-coder-1.3b-base --json
"""

import argparse
import fnmatch
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SAFE_EXTENSIONS = {".safetensors", ".gguf", ".onnx"}

# Pickle-based formats — run pickle scanners (fickling, modelscan, picklescan)
PICKLE_EXTENSIONS = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".joblib"}

# Non-pickle model formats — only modelscan or modelaudit can handle these
NONPICKLE_MODEL_EXTENSIONS = {".npy", ".h5", ".keras", ".pb"}

# Config files — only modelaudit checks these (trust_remote_code, auto_map)
CONFIG_EXTENSIONS = {".json", ".yaml", ".yml"}

SCANNABLE_EXTENSIONS = (
    PICKLE_EXTENSIONS | NONPICKLE_MODEL_EXTENSIONS | SAFE_EXTENSIONS | CONFIG_EXTENSIONS
)

HF_SKIP_PATTERNS = {
    "tokenizer*", "vocab*", "merges*", "special_tokens*",
    "*.md", "*.txt", "*.gitattributes", "*.gitignore", "*.msgpack",
    "*.lock", "*.html",
}

PIP_SCANNERS = {
    "fickling": "fickling",
    "modelscan": "modelscan",
    "picklescan": "picklescan",
}

NPM_SCANNERS = {
    "modelaudit": "promptfoo",
}


# ---------------------------------------------------------------------------
# Auto-install (zero-config)
# ---------------------------------------------------------------------------

def check_tool(name: str, check_cmd: list[str]) -> bool:
    try:
        subprocess.run(check_cmd, capture_output=True, timeout=10)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def detect_scanners() -> dict[str, bool]:
    return {
        "fickling": check_tool("fickling", ["fickling", "--help"]),
        "modelscan": check_tool("modelscan", ["modelscan", "--help"]),
        "picklescan": check_tool("picklescan", ["picklescan", "--help"]),
        "modelaudit": check_tool("modelaudit", ["promptfoo", "--help"]),
    }


def find_pip_cmd() -> list[str]:
    """Find the best pip install command: uv pip > pip > python -m pip."""
    if shutil.which("uv"):
        return ["uv", "pip", "install"]
    if shutil.which("pip"):
        return ["pip", "install"]
    return [sys.executable, "-m", "pip", "install"]


def auto_install(available: dict[str, bool], quiet: bool = False) -> dict[str, bool]:
    """Install any missing scanners. Returns updated availability."""
    missing_pip = [pkg for name, pkg in PIP_SCANNERS.items() if not available.get(name)]
    missing_npm = [pkg for name, pkg in NPM_SCANNERS.items() if not available.get(name)]

    if not missing_pip and not missing_npm:
        return available

    if not quiet:
        print("Installing missing scanners (first-run setup)...")

    if missing_pip:
        pip_cmd = find_pip_cmd()
        cmd_name = " ".join(pip_cmd)
        if not quiet:
            print(f"  {cmd_name} {' '.join(missing_pip)}")
        subprocess.run(
            [*pip_cmd, "-q", *missing_pip],
            capture_output=quiet, timeout=180,
        )

    if missing_npm and shutil.which("npm"):
        if not quiet:
            print(f"  npm install -g {' '.join(missing_npm)}")
        subprocess.run(
            ["npm", "install", "-g", *missing_npm],
            capture_output=quiet, timeout=120,
        )
    elif missing_npm and not quiet:
        print("  npm not found, skipping ModelAudit (install Node.js for full coverage)")

    if not quiet:
        print()

    return detect_scanners()


# ---------------------------------------------------------------------------
# HuggingFace support
# ---------------------------------------------------------------------------

def is_hf_model_id(path_str: str) -> bool:
    """Check if input looks like a HuggingFace model ID (org/model)."""
    return "/" in path_str and not Path(path_str).exists()


def should_scan_hf_file(filename: str) -> bool:
    name = Path(filename).name
    if any(fnmatch.fnmatch(name, p) for p in HF_SKIP_PATTERNS):
        return False
    return any(fnmatch.fnmatch(name, f"*{ext}") for ext in SCANNABLE_EXTENSIONS)


def download_hf_model(model_id: str, quiet: bool = False) -> Path:
    """Download scannable files from a HuggingFace model repo."""
    from huggingface_hub import hf_hub_download, list_repo_files

    if not quiet:
        print(f"Fetching file list for {model_id}...")

    all_files = list(list_repo_files(model_id))
    scannable = [f for f in all_files if should_scan_hf_file(f)]

    if not quiet:
        print(f"  {len(all_files)} total files, {len(scannable)} scannable")

        # Show format breakdown
        formats = {}
        for f in all_files:
            ext = Path(f).suffix or "(no ext)"
            formats[ext] = formats.get(ext, 0) + 1
        for ext, count in sorted(formats.items(), key=lambda x: -x[1])[:8]:
            print(f"    {ext}: {count}")
        print()

    if not scannable:
        print(f"No scannable files in {model_id}", file=sys.stderr)
        sys.exit(1)

    local_dir = Path("/tmp") / "model-scanner" / model_id.replace("/", "__")
    local_dir.mkdir(parents=True, exist_ok=True)

    for filename in scannable:
        if not quiet:
            print(f"  Downloading {filename}...")
        hf_hub_download(repo_id=model_id, filename=filename, local_dir=str(local_dir))

    if not quiet:
        print()

    return local_dir


# ---------------------------------------------------------------------------
# Scanners
# ---------------------------------------------------------------------------

def run_fickling(path: Path, verbose: bool) -> ScannerResult:
    result = ScannerResult(scanner="fickling", available=True, verdict=Verdict.SAFE)
    try:
        proc = subprocess.run(
            ["fickling", "--check-safety", str(path)],
            capture_output=True, text=True, timeout=120,
        )
        result.raw_output = proc.stdout + proc.stderr
        output = result.raw_output.lower()

        if "not a valid pickle" in output or "unsupported" in output:
            result.verdict = Verdict.SAFE
            result.details.append("Format not applicable to Fickling")
        elif "malicious" in output or "unsafe" in output or "dangerous" in output:
            result.verdict = Verdict.MALICIOUS
            for line in result.raw_output.splitlines():
                if any(w in line.lower() for w in ["unsafe", "malicious", "dangerous", "import", "call"]):
                    result.details.append(line.strip())
        elif "suspicious" in output or "warning" in output or "unknown" in output:
            result.verdict = Verdict.SUSPICIOUS
            for line in result.raw_output.splitlines():
                if any(w in line.lower() for w in ["suspicious", "warning", "unknown"]):
                    result.details.append(line.strip())
        elif proc.returncode != 0:
            result.verdict = Verdict.ERROR
            result.error = proc.stderr[:500]
        else:
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
                    desc = issue.get("description", issue.get("operator", "Unknown"))
                    sev = issue.get("severity", "?")
                    result.details.append(f"[{sev}] {desc}")
        except json.JSONDecodeError:
            output = result.raw_output.lower()
            if "no issues" in output or proc.returncode == 0:
                result.details.append("No issues found")
            elif "unsafe" in output or "critical" in output:
                result.verdict = Verdict.MALICIOUS
                result.details.append(proc.stdout[:500])
            else:
                result.verdict = Verdict.SUSPICIOUS
                result.details.append(f"Parse error: {proc.stdout[:200]}")
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
                        sev = finding.get("severity", "?")
                        result.details.append(f"[{sev}] {msg}")
        except json.JSONDecodeError:
            if proc.returncode == 0:
                result.details.append("No issues detected")
            else:
                result.verdict = Verdict.SUSPICIOUS
                result.details.append(f"Parse error: {proc.stdout[:200]}")
    except subprocess.TimeoutExpired:
        result.verdict = Verdict.ERROR
        result.error = "Timed out after 120s"
    except Exception as e:
        result.verdict = Verdict.ERROR
        result.error = str(e)
    return result


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

SCANNER_RUNNERS = {
    "fickling": run_fickling,
    "modelscan": run_modelscan,
    "picklescan": run_picklescan,
    "modelaudit": run_modelaudit,
}


def aggregate_verdict(results: list[ScannerResult]) -> Verdict:
    # Only consider scanners that actually ran (not skipped, not errored, not unavailable)
    ran = [r for r in results if r.available and r.verdict not in (Verdict.ERROR,)]
    # Filter out scanners that were skipped (marked SAFE with "Not applicable" detail)
    active = [r for r in ran if not any("Not applicable" in d for d in r.details)]

    if not active:
        # All scanners were skipped or errored — check if format-safe
        format_safe = [r for r in ran if r.verdict == Verdict.FORMAT_SAFE]
        if format_safe:
            return Verdict.FORMAT_SAFE
        return Verdict.ERROR

    verdicts = [r.verdict for r in active]
    if Verdict.MALICIOUS in verdicts:
        return Verdict.MALICIOUS
    if Verdict.SUSPICIOUS in verdicts:
        return Verdict.SUSPICIOUS
    if all(v == Verdict.FORMAT_SAFE for v in verdicts):
        return Verdict.FORMAT_SAFE
    return Verdict.SAFE


def get_scanners_for_format(ext: str) -> dict[str, str]:
    """
    Route files to the right scanners based on format.
    This prevents false positives from running pickle scanners on JSON/NPY/etc.

    Returns dict of scanner_name -> reason it applies (or is skipped).
    """
    ext = ext.lower()

    if ext in SAFE_EXTENSIONS:
        # SafeTensors/ONNX/GGUF — non-executable, only check for config issues
        return {
            "fickling": "skip",      # not applicable
            "modelscan": "skip",     # not applicable
            "picklescan": "skip",    # not applicable
            "modelaudit": "run",     # checks for embedded issues
        }

    if ext in PICKLE_EXTENSIONS:
        # Pickle-based — run all pickle scanners
        return {
            "fickling": "run",
            "modelscan": "run",
            "picklescan": "run",
            "modelaudit": "run",
        }

    if ext in NONPICKLE_MODEL_EXTENSIONS:
        # NPY, H5, Keras, TF — only modelscan and modelaudit handle these
        return {
            "fickling": "skip",
            "modelscan": "run",
            "picklescan": "skip",
            "modelaudit": "run",
        }

    if ext in CONFIG_EXTENSIONS:
        # JSON/YAML configs — only modelaudit checks for trust_remote_code/auto_map
        return {
            "fickling": "skip",
            "modelscan": "skip",
            "picklescan": "skip",
            "modelaudit": "run",
        }

    # Unknown format — try modelaudit only (widest format support)
    return {
        "fickling": "skip",
        "modelscan": "skip",
        "picklescan": "skip",
        "modelaudit": "run",
    }


def scan_file(path: Path, available: dict[str, bool], verbose: bool) -> tuple[list[ScannerResult], Verdict]:
    ext = path.suffix.lower()
    routing = get_scanners_for_format(ext)

    results = []
    for name, runner in SCANNER_RUNNERS.items():
        action = routing.get(name, "skip")

        if action == "skip":
            r = ScannerResult(scanner=name, available=available.get(name, False), verdict=Verdict.SAFE)
            if ext in SAFE_EXTENSIONS:
                r.verdict = Verdict.FORMAT_SAFE
                r.details.append(f"Non-executable format ({ext})")
            else:
                r.details.append(f"Not applicable for {ext} files")
            results.append(r)
        elif not available.get(name):
            results.append(ScannerResult(scanner=name, available=False, verdict=Verdict.ERROR))
        else:
            if verbose:
                print(f"  Running {name}...")
            results.append(runner(path, verbose))

    return results, aggregate_verdict(results)


def detect_hf_models(directory: Path) -> list[dict]:
    """
    Detect HuggingFace model directories by finding config.json files
    with model_type, _name_or_path, or architectures fields.
    Returns metadata for each detected HF model.
    """
    hf_models = []
    for config_path in directory.rglob("config.json"):
        try:
            config = json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            continue

        # Check for HuggingFace signals
        model_type = config.get("model_type")
        hf_id = config.get("_name_or_path", "")
        architectures = config.get("architectures", [])
        auto_map = config.get("auto_map", {})
        trust_remote = config.get("trust_remote_code", False)

        if not model_type and not architectures:
            continue  # Not a HF model config

        model_dir = config_path.parent

        # Check what formats exist in this directory
        formats_found = set()
        for f in model_dir.iterdir():
            if f.is_file():
                formats_found.add(f.suffix.lower())

        has_pickle = bool(formats_found & PICKLE_EXTENSIONS)
        has_safetensors = ".safetensors" in formats_found
        has_onnx = ".onnx" in formats_found

        hf_models.append({
            "dir": str(model_dir),
            "config_path": str(config_path),
            "model_type": model_type,
            "hf_id": hf_id if "/" in str(hf_id) else None,
            "architectures": architectures,
            "auto_map": auto_map,
            "trust_remote_code": trust_remote,
            "has_pickle": has_pickle,
            "has_safetensors": has_safetensors,
            "has_onnx": has_onnx,
            "formats": sorted(formats_found),
        })

    return hf_models


def format_hf_summary(hf_models: list[dict]) -> str:
    """Format a summary of detected HuggingFace models."""
    if not hf_models:
        return ""

    lines = ["## HuggingFace Models Detected", ""]
    for m in hf_models:
        dir_name = Path(m["dir"]).name
        lines.append(f"### {dir_name}")
        if m["hf_id"]:
            lines.append(f"- **HuggingFace ID:** `{m['hf_id']}`")
        if m["model_type"]:
            lines.append(f"- **Model type:** {m['model_type']}")
        if m["architectures"]:
            lines.append(f"- **Architecture:** {', '.join(m['architectures'])}")

        # Format warnings
        if m["trust_remote_code"]:
            lines.append(f"- **trust_remote_code: True** — loads arbitrary Python from repo")
        if m["auto_map"]:
            files = [v.split(".")[0] + ".py" for v in m["auto_map"].values() if "." in v]
            lines.append(f"- **auto_map** loads: {', '.join(files)} (NOT scanned by model scanners)")

        # Format mix
        if m["has_pickle"] and m["has_safetensors"]:
            lines.append(f"- Formats: pickle AND safetensors (use safetensors for ISM-2072)")
        elif m["has_pickle"]:
            lines.append(f"- **Pickle only** — no SafeTensors alternative available locally")
            if m["hf_id"]:
                lines.append(f"  - Check HuggingFace for SafeTensors version: `uv run scripts/scan.py {m['hf_id']}`")
        elif m["has_safetensors"]:
            lines.append(f"- SafeTensors only (format-safe)")
        elif m["has_onnx"]:
            lines.append(f"- ONNX (format-safe)")

        lines.append("")

    return "\n".join(lines)


def find_model_files(directory: Path) -> list[Path]:
    files = []
    for f in directory.rglob("*"):
        if f.is_file() and f.suffix.lower() in SCANNABLE_EXTENSIONS:
            # Skip tokenizer/vocab files
            if any(fnmatch.fnmatch(f.name, p) for p in HF_SKIP_PATTERNS):
                continue
            files.append(f)
    return sorted(files)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def format_report(path: Path, results: list[ScannerResult], overall: Verdict) -> str:
    lines = []
    lines.append(f"# Model Security Scan Report")
    lines.append(f"")
    lines.append(f"**File:** `{path.name}`")
    lines.append(f"**Path:** `{path}`")
    lines.append(f"**Size:** {path.stat().st_size:,} bytes")
    lines.append(f"**Extension:** `{path.suffix}`")
    lines.append(f"")

    verdict_display = {
        Verdict.SAFE: "SAFE",
        Verdict.FORMAT_SAFE: "FORMAT_SAFE (non-executable format)",
        Verdict.SUSPICIOUS: "SUSPICIOUS",
        Verdict.MALICIOUS: "MALICIOUS",
        Verdict.ERROR: "ERROR",
    }

    lines.append(f"## Overall Verdict: {verdict_display.get(overall, str(overall))}")
    lines.append(f"")
    lines.append(f"## Scanner Results")
    lines.append(f"")

    for r in results:
        if not r.available:
            lines.append(f"### {r.scanner}: skipped (not installed)")
            lines.append(f"")
            continue

        lines.append(f"### {r.scanner}: {verdict_display.get(r.verdict, str(r.verdict))}")
        for d in r.details:
            lines.append(f"- {d}")
        if r.error:
            lines.append(f"- Error: {r.error}")
        lines.append(f"")

    lines.append(f"## Recommendations")
    lines.append(f"")
    if overall == Verdict.MALICIOUS:
        lines.append(f"- DO NOT load this model. Malicious code detected.")
        lines.append(f"- Delete or quarantine the file.")
        lines.append(f"- If from HuggingFace, report via their security contact.")
    elif overall == Verdict.SUSPICIOUS:
        lines.append(f"- Review flagged imports manually before loading.")
        lines.append(f"- Consider dynamic analysis in a sandbox (Dyana).")
        lines.append(f"- Look for a SafeTensors version of this model.")
    elif overall == Verdict.FORMAT_SAFE:
        lines.append(f"- Weight data uses a non-executable format.")
        lines.append(f"- Check config.json for `trust_remote_code` or `auto_map` (unscanned Python code).")
    else:
        lines.append(f"- No issues detected. Static scanners have known bypass techniques (133+).")
        lines.append(f"- For high-value deployments, also run dynamic sandbox analysis.")

    lines.append(f"")
    lines.append(f"---")
    lines.append(f"*Scanned by raxIT model-scanner | github.com/raxITlabs/skills*")
    return "\n".join(lines)


def format_json(path: Path, results: list[ScannerResult], overall: Verdict) -> dict:
    return {
        "file": str(path),
        "filename": path.name,
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
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Scan ML model files for malicious code. Zero-config.",
        epilog="Accepts local files, directories, or HuggingFace model IDs (e.g., microsoft/phi-2)",
    )
    parser.add_argument("path", help="File, directory, or HuggingFace model ID")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    quiet = args.json

    # Auto-install scanners
    available = detect_scanners()
    installed = sum(available.values())
    if installed < len(available):
        available = auto_install(available, quiet=quiet)
        installed = sum(available.values())

    if installed == 0:
        print("No scanners could be installed. Check pip/npm are available.", file=sys.stderr)
        sys.exit(1)

    if not quiet:
        names = [k for k, v in available.items() if v]
        missing = [k for k, v in available.items() if not v]
        print(f"Scanners: {', '.join(names)} ({installed}/4)")
        if missing:
            print(f"Unavailable: {', '.join(missing)}")
        print()

    # Resolve input: HuggingFace model ID or local path
    hf_models_detected = []

    if is_hf_model_id(args.path):
        if not quiet:
            print(f"HuggingFace model: {args.path}")
        target = download_hf_model(args.path, quiet=quiet)
        files = find_model_files(target)
    else:
        target = Path(args.path)
        if not target.exists():
            print(f"Error: {target} does not exist", file=sys.stderr)
            sys.exit(1)
        files = find_model_files(target) if target.is_dir() else [target]

        # Detect HuggingFace models in the directory
        if target.is_dir():
            hf_models_detected = detect_hf_models(target)

    if not files:
        print(f"No scannable model files found.", file=sys.stderr)
        sys.exit(1)

    # Show HuggingFace model detection results
    if not quiet and hf_models_detected:
        print(format_hf_summary(hf_models_detected))

    if not quiet:
        print(f"Scanning {len(files)} file(s)...\n")

    # Scan all files
    all_results = []
    worst = Verdict.SAFE
    verdict_priority = {Verdict.SAFE: 0, Verdict.FORMAT_SAFE: 1, Verdict.SUSPICIOUS: 2, Verdict.MALICIOUS: 3}

    for f in files:
        if not quiet:
            print(f"--- {f.name} ---")

        results, overall = scan_file(f, available, args.verbose)
        all_results.append(format_json(f, results, overall))

        if not quiet:
            print(format_report(f, results, overall))
            print()

        if verdict_priority.get(overall, -1) > verdict_priority.get(worst, -1):
            worst = overall

    # JSON output
    if args.json:
        output = {
            "input": args.path,
            "overall_verdict": worst.value,
            "files_scanned": len(all_results),
            "results": all_results,
        }
        if hf_models_detected:
            output["huggingface_models"] = hf_models_detected
        if len(all_results) == 1:
            output = all_results[0]
            if hf_models_detected:
                output["huggingface_models"] = hf_models_detected
        print(json.dumps(output, indent=2))

    # Summary for multi-file scans
    if not quiet and len(files) > 1:
        print("=" * 60)
        print(f"Overall: {worst.value}")
        verdicts = {}
        for r in all_results:
            v = r["overall_verdict"]
            verdicts[v] = verdicts.get(v, 0) + 1
        for v, count in sorted(verdicts.items()):
            print(f"  {v}: {count} file(s)")

        # ISM-2072 compliance summary
        pickle_files = [r for r in all_results if r["extension"] in (".pkl", ".pt", ".pth", ".bin", ".joblib")]
        safe_format_files = [r for r in all_results if r["extension"] in (".safetensors", ".onnx", ".gguf")]
        if pickle_files:
            print()
            print(f"ISM-2072: {len(pickle_files)} file(s) use executable formats (pickle/joblib)")
            if safe_format_files:
                print(f"          {len(safe_format_files)} file(s) use non-executable formats (safetensors/onnx)")
            print(f"          Migrate pickle files to SafeTensors for compliance")

        # HF model suggestions
        if hf_models_detected:
            for m in hf_models_detected:
                if m["hf_id"] and m["has_pickle"] and not m["has_safetensors"]:
                    print(f"\nHint: {m['hf_id']} is pickle-only locally.")
                    print(f"  Check HF for SafeTensors: uv run scripts/scan.py {m['hf_id']}")

    sys.exit(0 if worst in (Verdict.SAFE, Verdict.FORMAT_SAFE) else 1)


if __name__ == "__main__":
    main()
