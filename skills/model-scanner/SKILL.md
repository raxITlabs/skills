---
name: model-scanner
description: Scan ML model files for malicious code using multiple security scanners. Zero-config, auto-installs everything. Use this skill whenever the user asks to scan a model file, check if a model is safe, audit a pickle file, verify model security, inspect a .pkl/.pt/.bin/.safetensors/.h5/.joblib file, or mentions model supply chain security. Also trigger when the user downloads a model from HuggingFace and wants to verify it before use, mentions ISM-2072 compliance, or asks about pickle deserialization risks. Trigger on phrases like "is this model safe", "scan this model", "check this pickle file", "verify before loading".
---

# Model Scanner

Multi-scanner security analysis for ML model files. Zero configuration. Accepts local files, directories, or HuggingFace model IDs.

## Quick Start

Just run it. Scanners auto-install on first use.

```bash
# Local file
uv run scripts/scan.py model.pkl

# Entire directory
uv run scripts/scan.py ./models/

# HuggingFace model (downloads automatically)
uv run scripts/scan.py microsoft/phi-2

# JSON output for CI/CD
uv run scripts/scan.py deepseek-ai/deepseek-coder-1.3b-base --json
```

First run installs Fickling, ModelScan, PickleScan (via pip) and ModelAudit (via npm) automatically. No user action needed. If npm is not available, it skips ModelAudit and runs the three Python scanners.

## How It Works

The script runs up to 4 independent scanners with different detection strategies, then aggregates into a single verdict:

| Scanner | Approach | Why It Matters |
|---------|----------|----------------|
| **Fickling** | Allowlist + decompiler | Blocks unknown imports by default. Shows exactly what code would execute. Architecturally superior to denylists. |
| **ModelScan** | Denylist static | Broadest ML format support (pickle, dill, keras, tensorflow, numpy, joblib). |
| **PickleScan** | Denylist static | Same scanner HuggingFace uses. Provides parity with their platform scanning. |
| **ModelAudit** | Multi-format static | Widest format coverage (42+ formats). Catches config file issues, embedded executables, secrets. |

No single scanner catches everything. PickleScan has a 7-63% F1-score. Fickling had its own CVE. Running all four with different approaches is the only reliable strategy.

## Verdicts

- **MALICIOUS**: Any scanner detects confirmed malicious behavior (os.system, subprocess, eval, embedded executables, network indicators)
- **SUSPICIOUS**: Scanners disagree, or ambiguous imports detected (common with custom architectures like YOLO)
- **SAFE**: All scanners pass
- **FORMAT_SAFE**: File uses SafeTensors/ONNX/GGUF (non-executable by design). But check for `trust_remote_code` in config.json.

## HuggingFace Models

Pass any HuggingFace model ID directly. The script:

1. Lists all files in the repo
2. Shows format breakdown (how many pickle vs safetensors)
3. Downloads only scannable files (skips tokenizer, vocab, etc.)
4. Scans each file and aggregates

```bash
uv run scripts/scan.py meta-llama/Llama-2-7b-hf
```

This is the primary use case. Data scientists download models from HuggingFace daily. This skill lets them check before loading.

## Caveats to Always Communicate

When presenting results to the user, always include these:

1. **No scanner is perfect.** 133 known bypass techniques exist. A clean scan reduces risk but does not guarantee safety.
2. **SafeTensors is not a complete fix.** Models using `auto_map` or `trust_remote_code=True` load arbitrary Python alongside safe weights. The weights are safe; the code is unscanned.
3. **ISM-2072 compliance** requires non-executable formats, not just scanning. Scanning is risk reduction, not a compliance checkbox.
4. **Dynamic analysis** (sandbox execution) catches more than static scanning. For critical models, recommend [Dyana](https://github.com/dreadnode/dyana).

## Supported Formats

| Format | Extensions | Which Scanners |
|--------|-----------|----------------|
| Pickle | .pkl .pickle | All 4 |
| PyTorch | .pt .pth .bin | All 4 |
| Joblib | .joblib | Fickling, ModelScan, PickleScan |
| NumPy | .npy | ModelScan, PickleScan |
| Keras | .h5 .keras | ModelScan, ModelAudit |
| TensorFlow | saved_model.pb | ModelScan, ModelAudit |
| SafeTensors | .safetensors | ModelAudit (config checks) |
| ONNX | .onnx | ModelAudit |
| Configs | .json .yaml | ModelAudit (auto_map, trust_remote_code) |
