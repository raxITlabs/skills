---
name: model-scanner
description: Scan ML model files for malicious code using multiple security scanners. Use this skill whenever the user asks to scan a model file, check if a model is safe, audit a pickle file, verify model security, inspect a .pkl/.pt/.bin/.safetensors/.h5/.joblib file, or mentions model supply chain security. Also trigger when the user downloads a model from HuggingFace and wants to verify it before use, mentions ISM-2072 compliance, or asks about pickle deserialization risks.
---

# Model Scanner

Multi-scanner security analysis for ML model files. Runs models through up to 4 independent scanners and aggregates results into a clear verdict.

## Why Multiple Scanners

No single scanner catches everything. PickleScan (what HuggingFace uses) has a 7-63% F1-score depending on the attack. Fickling's allowlist approach is architecturally superior but had its own CVE. The only reliable approach is layered scanning with different detection strategies.

| Scanner | Approach | Strength |
|---------|----------|----------|
| Fickling | Allowlist + decompiler | Blocks unknown imports by default, can show exactly what code would execute |
| ModelAudit | Multi-format static | Widest format coverage (42+), catches config file issues, embedded executables |
| ModelScan | Denylist static | Broad ML format support (pickle, dill, keras, tensorflow, numpy, joblib) |
| PickleScan | Denylist static | Parity with HuggingFace's own scanning, fast |

## How to Use

The user will provide a path to a model file or a HuggingFace model ID. Run the scan script:

```bash
uv run scripts/scan.py <path-or-huggingface-id> [--verbose] [--json]
```

If the user provides a HuggingFace model ID (like `meta-llama/Llama-2-7b`), the script will download the model files to a temp directory first.

### Reading Results

The script outputs a structured report with:

1. **Overall Verdict**: SAFE / SUSPICIOUS / MALICIOUS
2. **Per-scanner results**: What each scanner found (or didn't find)
3. **Risk details**: Specific imports, functions, or behaviors flagged
4. **Recommendations**: What to do next based on findings

### Verdict Logic

- **MALICIOUS**: Any scanner detects confirmed malicious behavior (unsafe imports like `os.system`, `subprocess`, embedded executables, network indicators)
- **SUSPICIOUS**: Scanners disagree, or unknown/ambiguous imports detected that could be legitimate or malicious (common with custom architectures)
- **SAFE**: All scanners pass, no concerning findings
- **FORMAT_SAFE**: File uses a non-executable format (SafeTensors, ONNX, GGUF) that cannot execute arbitrary code by design. Note: this does NOT guarantee the full model loading pipeline is safe (custom architectures may load Python files via `auto_map`/`trust_remote_code`)

### Important Caveats

Always communicate these to the user:

1. **No scanner is perfect.** 133 known bypass techniques exist against static scanners. A clean scan reduces risk but does not eliminate it.
2. **SafeTensors is not a complete solution.** Models using `auto_map` or `trust_remote_code=True` load arbitrary Python code alongside safe weight files.
3. **ISM-2072 compliance** requires non-executable formats, not just scanning. Scanning is a risk reduction measure, not a compliance checkbox.
4. **Dynamic analysis** (sandbox execution) catches more than static scanning but is not included in this tool. For high-value models, recommend Dyana (https://github.com/dreadnode/dyana) or AIM Security's commercial scanner.

## Auto-Install

If scanners are not installed, the script will offer to install them:

```bash
# Python scanners
uv pip install fickling modelscan picklescan

# ModelAudit (Node.js)
npm install -g promptfoo
```

The script checks for each scanner at startup and skips any that aren't available, running whatever is installed. Minimum: at least one scanner must be available.

## Supported Formats

| Format | Extension | Scanners That Cover It |
|--------|-----------|----------------------|
| Pickle | .pkl, .pickle | All 4 |
| PyTorch | .pt, .pth, .bin | All 4 |
| Joblib | .joblib | PickleScan, ModelScan, Fickling |
| NumPy | .npy | ModelScan, PickleScan |
| Keras H5 | .h5 | ModelScan, ModelAudit |
| Keras V3 | .keras | ModelScan, ModelAudit |
| TensorFlow SavedModel | saved_model.pb | ModelScan, ModelAudit |
| SafeTensors | .safetensors | ModelAudit (checks for embedded issues) |
| ONNX | .onnx | ModelAudit |
| Config files | .json, .yaml | ModelAudit (checks for auto_map, trust_remote_code) |

## References

- Scanner landscape research: See `references/scanner-landscape.md` for detailed tool comparison, effectiveness data, and bypass rates
- ISM-2072 context: Australia mandates non-executable model formats (December 2025)
- Black Hat "Smashing Model Scanners" talk: https://youtu.be/jjiE9XzJo0M
- JFrog PickleScan zero-days: https://jfrog.com/blog/unveiling-3-zero-day-vulnerabilities-in-picklescan/
