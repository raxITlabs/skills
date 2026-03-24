"""
Model inventory: discover ML model files, classify formats, extract HF metadata.
"""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path


# Format classifications
SAFE_EXTENSIONS = {".safetensors", ".gguf", ".onnx"}
PICKLE_EXTENSIONS = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".joblib"}
NONPICKLE_MODEL_EXTENSIONS = {".npy", ".h5", ".keras", ".pb"}
CONFIG_EXTENSIONS = {".json", ".yaml", ".yml"}
SCANNABLE_EXTENSIONS = PICKLE_EXTENSIONS | NONPICKLE_MODEL_EXTENSIONS | SAFE_EXTENSIONS | CONFIG_EXTENSIONS

HF_SKIP_PATTERNS = {
    "tokenizer*", "vocab*", "merges*", "special_tokens*",
    "*.md", "*.txt", "*.gitattributes", "*.gitignore", "*.msgpack",
    "*.lock", "*.html",
}


def find_model_files(directory: Path) -> list[Path]:
    """Find all scannable model files in a directory, recursively."""
    files = []
    for f in directory.rglob("*"):
        if f.is_file() and f.suffix.lower() in SCANNABLE_EXTENSIONS:
            if any(fnmatch.fnmatch(f.name, p) for p in HF_SKIP_PATTERNS):
                continue
            files.append(f)
    return sorted(files)


def detect_hf_models(directory: Path) -> list[dict]:
    """
    Detect HuggingFace model directories by finding config.json files
    with model_type, _name_or_path, or architectures fields.
    """
    hf_models = []
    for config_path in directory.rglob("config.json"):
        try:
            config = json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            continue

        model_type = config.get("model_type")
        hf_id = config.get("_name_or_path", "")
        architectures = config.get("architectures", [])
        auto_map = config.get("auto_map", {})
        trust_remote = config.get("trust_remote_code", False)

        if not model_type and not architectures:
            continue

        model_dir = config_path.parent
        formats_found = set()
        for f in model_dir.iterdir():
            if f.is_file():
                formats_found.add(f.suffix.lower())

        hf_models.append({
            "dir": str(model_dir),
            "config_path": str(config_path),
            "model_type": model_type,
            "hf_id": hf_id if "/" in str(hf_id) else None,
            "architectures": architectures,
            "auto_map": auto_map,
            "trust_remote_code": trust_remote,
            "has_pickle": bool(formats_found & PICKLE_EXTENSIONS),
            "has_safetensors": ".safetensors" in formats_found,
            "has_onnx": ".onnx" in formats_found,
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

        if m["trust_remote_code"]:
            lines.append(f"- **trust_remote_code: True** -- loads arbitrary Python from repo")
        if m["auto_map"]:
            files = [v.split(".")[0] + ".py" for v in m["auto_map"].values() if "." in v]
            lines.append(f"- **auto_map** loads: {', '.join(files)} (NOT scanned by model scanners)")

        if m["has_pickle"] and m["has_safetensors"]:
            lines.append(f"- Formats: pickle AND safetensors (use safetensors for ISM-2072)")
        elif m["has_pickle"]:
            lines.append(f"- **Pickle only** -- no SafeTensors alternative available locally")
            if m["hf_id"]:
                lines.append(f"  Check HF for SafeTensors: `uv run scripts/scan.py {m['hf_id']}`")
        elif m["has_safetensors"]:
            lines.append(f"- SafeTensors only (format-safe)")
        elif m["has_onnx"]:
            lines.append(f"- ONNX (format-safe)")

        lines.append("")

    return "\n".join(lines)


def format_inventory(files: list[Path]) -> str:
    """Format file inventory as markdown."""
    if not files:
        return ""

    lines = ["## Inventory", "", f"Found {len(files)} scannable file(s):", ""]

    # Group by format
    by_format: dict[str, list[Path]] = {}
    for f in files:
        ext = f.suffix.lower()
        by_format.setdefault(ext, []).append(f)

    for ext in sorted(by_format):
        count = len(by_format[ext])
        is_safe = ext in SAFE_EXTENSIONS
        is_pickle = ext in PICKLE_EXTENSIONS
        marker = ""
        if is_safe:
            marker = " (non-executable)"
        elif is_pickle:
            marker = " (executable)"
        lines.append(f"- `{ext}`: {count} file(s){marker}")

    lines.append("")
    return "\n".join(lines)
