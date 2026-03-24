---
name: model-scanner
description: Scan ML model files for malicious code using multiple security scanners. Zero-config, auto-installs everything. Use this skill whenever the user asks to scan a model file, check if a model is safe, audit a pickle file, verify model security, inspect a .pkl/.pt/.bin/.safetensors/.h5/.joblib file, or mentions model supply chain security. Also trigger when the user downloads a model from HuggingFace and wants to verify it before use, mentions ISM-2072 compliance, or asks about pickle deserialization risks. Trigger on phrases like "is this model safe", "scan this model", "check this pickle file", "verify before loading", "scan all", "scan models", "check my models".
---

# Model Scanner

Multi-scanner security analysis for ML model files. Zero configuration. Accepts local files, directories, or HuggingFace model IDs.

## How You Should Behave

When this skill triggers, you are a security-aware assistant that understands ML model supply chains. Before running the scanner, ALWAYS look at what's in the project first.

### Step 1: Discover What's Here

Before scanning, explore the workspace to understand the model landscape:

```bash
# Find all model files in the project
find . -type f \( -name "*.pkl" -o -name "*.pt" -o -name "*.pth" -o -name "*.bin" -o -name "*.safetensors" -o -name "*.onnx" -o -name "*.gguf" -o -name "*.joblib" -o -name "*.h5" -o -name "*.keras" -o -name "*.npy" \) 2>/dev/null
```

Also check for `config.json` files — they reveal HuggingFace model metadata.

### Step 2: Detect HuggingFace Models

Read any `config.json` files found near model files. Look for these HuggingFace signals:

- `_name_or_path` — the original HuggingFace model ID (e.g., `"microsoft/phi-2"`)
- `model_type` — indicates it's a HF transformers model
- `auto_map` — custom code loading (security-relevant)
- `trust_remote_code` — arbitrary Python execution (security-relevant)
- `architectures` — model class names

If you find a HuggingFace model ID in `_name_or_path`, **offer the user options**:

```
I found a HuggingFace model: microsoft/phi-2

Options:
1. Scan local files only (what's downloaded here)
2. Check HuggingFace for the full model (may have more files, or HF may have flagged it)
3. Compare: check if a SafeTensors version exists on HF (ISM-2072 compliance path)
4. Scan everything (local + HF check)
```

### Step 3: Present Findings by Risk

Group results by risk level, not by file. Lead with threats:

1. **MALICIOUS files first** — these need immediate action
2. **SUSPICIOUS files** — need human review
3. **ISM-2072 compliance issues** — pickle/joblib files that aren't malicious but use executable formats
4. **SAFE / FORMAT_SAFE files** — clean

For each finding, explain:
- What was found (specific import, function, or pattern)
- Which scanners flagged it (and which didn't — disagreements are informative)
- What the user should do about it

### Step 4: HuggingFace-Specific Advice

When scanning HF models, always check and report:

- **Format mix**: Does the repo have both pickle AND safetensors? If so, recommend the safetensors version.
- **trust_remote_code**: If config.json has this, warn that `from_pretrained()` will execute arbitrary Python from the repo, even if weights are SafeTensors.
- **auto_map**: If present, the model loads custom Python files (like `modeling_*.py`). These are NOT scanned by any tool. Flag them.
- **HuggingFace scan status**: If scanning a HF model by ID, mention that HuggingFace runs PickleScan + ClamAV on their end, but those scanners have known bypasses (7 CVEs in 2025).
- **SafeTensors conversion**: If the model is pickle-only, check if HuggingFace's auto-conversion bot has created a SafeTensors PR. Mention it.

## Running the Scanner

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

First run installs Fickling, ModelScan, PickleScan (via pip/uv) and ModelAudit (via npm) automatically. Zero config.

## How It Works

4 independent scanners with different detection strategies:

| Scanner | Approach | Why It Matters |
|---------|----------|----------------|
| **Fickling** | Allowlist + decompiler | Blocks unknown imports by default. Can decompile pickle to show exactly what code would execute. |
| **ModelScan** | Denylist static | Broadest ML format support (pickle, dill, keras, tensorflow, numpy, joblib). |
| **PickleScan** | Denylist static | Same scanner HuggingFace uses. Parity with their platform. |
| **ModelAudit** | Multi-format static | Widest format coverage (42+). Catches config issues, embedded executables, secrets. |

### Format Routing

Not every scanner runs on every file. The script routes files to the right scanners:

| File Type | Fickling | ModelScan | PickleScan | ModelAudit |
|-----------|----------|-----------|------------|------------|
| `.pkl .pt .pth .bin .joblib` | yes | yes | yes | yes |
| `.npy .h5 .keras .pb` | skip | yes | skip | yes |
| `.json .yaml .yml` | skip | skip | skip | yes |
| `.safetensors .onnx .gguf` | skip | skip | skip | yes |

This prevents false positives from pickle scanners trying to parse JSON or NumPy files.

## Verdicts

- **MALICIOUS**: Any scanner detects confirmed malicious behavior (os.system, subprocess, eval, embedded executables, network indicators)
- **SUSPICIOUS**: Scanners disagree, or ambiguous imports detected (common with custom architectures)
- **SAFE**: All scanners pass
- **FORMAT_SAFE**: SafeTensors/ONNX/GGUF — non-executable by design. But check for trust_remote_code.

## Caveats to Always Communicate

1. **No scanner is perfect.** 133 known bypass techniques exist. Clean scan ≠ guaranteed safety.
2. **SafeTensors is not a complete fix.** `auto_map` + `trust_remote_code=True` loads arbitrary Python alongside safe weights.
3. **ISM-2072 compliance** requires non-executable formats, not just scanning.
4. **Dynamic analysis** catches more. For critical models, recommend [Dyana](https://github.com/dreadnode/dyana).
