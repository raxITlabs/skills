# raxIT Agent Skills

Open-source Agent Skills for AI Security by [raxIT](https://raxit.ai).

## model-scanner

**ML supply chain security scanner.** One command. Risk score. Global compliance mapping. Zero config.

### The Problem

83% of AI models on HuggingFace use pickle, a format designed to execute arbitrary code on deserialization. Your AppSec team scans code, containers, dependencies. Model files? Treated as "just data." They're not.

7 CVEs in PickleScan (the scanner HuggingFace uses) in 2025 alone. 133 known bypass techniques against all static scanners. 100+ malicious models found on HuggingFace with reverse shells.

Australia became the first government to mandate non-executable model formats (ISM-2072, December 2025). The EU AI Act requires robustness against model poisoning. OWASP lists it as LLM06. Nobody has a tool that checks all of this.

Until now.

### Install

```bash
npx skills add raxITlabs/skills@model-scanner -g -y
```

Then in Claude Code, just say: **"scan my models"**

### What It Does

```
Inventory    → Discovers all model files, detects HuggingFace models
Assessment   → Runs 4 scanners (Fickling, ModelScan, PickleScan, ModelAudit)
Risk Score   → 0-100 with transparent breakdown
Compliance   → Maps to ISM-2072, EU AI Act, OWASP LLM06, MITRE ATLAS, NIST AI RMF
Remediation  → Ordered actions: what to fix first and how
```

### Direct Usage

```bash
# Scan a directory
uv run scripts/scan.py ./models/

# Scan a HuggingFace model
uv run scripts/scan.py microsoft/phi-2

# JSON output for CI/CD
uv run scripts/scan.py ./models/ --json
```

### Compliance Frameworks

| Framework | Controls Checked |
|-----------|-----------------|
| Australian ISM | ISM-2072 (format), ISM-2086 (integrity), ISM-2087 (training data), ISM-2092 (access control) |
| EU AI Act | Article 15 (robustness against model poisoning) |
| OWASP LLM Top 10 | LLM06 (Supply Chain Vulnerabilities) |
| MITRE ATLAS | AML.T0010 (ML Supply Chain Compromise) |
| NIST AI RMF | MAP 3.4 (supply chain), MANAGE 2.4 (risk tracking), MANAGE 4.1 (monitoring) |

### Scanners

4 scanners with different detection strategies. No single scanner catches everything.

| Scanner | Approach | Why |
|---------|----------|-----|
| Fickling | Allowlist + decompiler | Blocks unknown imports by default |
| ModelScan | Denylist static | Broadest ML format support |
| PickleScan | Denylist static | Same scanner HuggingFace uses |
| ModelAudit | Multi-format static | 42+ formats, catches config issues |

All auto-installed on first run. Zero configuration.

### Important

- No scanner is perfect. 133 known bypass techniques exist. A clean scan reduces risk but does not guarantee safety.
- SafeTensors is not a complete fix. `trust_remote_code` + `auto_map` loads arbitrary Python alongside safe weights.
- ISM-2072 compliance requires non-executable formats, not just scanning.
- For critical models, use dynamic analysis: [Dyana](https://github.com/dreadnode/dyana)

## License

Apache 2.0
