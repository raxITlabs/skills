# Scanner Landscape Reference

Read this file when you need detailed comparison data between scanners, or when the user asks "which scanner is best" or "how do these compare."

## Effectiveness Data (SafePickle paper, Feb 2026)

| Scanner | F1-Score | Approach |
|---------|----------|----------|
| SafePickle (ML classifier) | 90.01% | Not yet released, paper only |
| PickleBall (hybrid) | 76.09% (OOD) | 100% malicious rejection, 20.2% false positive |
| Fickling (allowlist) | Up to 62.75% | Best of rule-based approaches |
| ModelScan (denylist) | Lower range | Similar to PickleScan |
| PickleScan (denylist) | 7.23%-62.75% | Depends heavily on dataset |

## Known Bypass Categories (Black Hat 2025)

1. **Deny-list exhaustion**: Thousands of wrapper functions exist that are not on any scanner's deny list. An AI agent found 50 in 2 hours.
2. **Embedded bytecode**: Dill/Cloudpickle embed Python bytecode. Static analysis of bytecode is NP-hard (halting problem).
3. **Pickle opcode desync**: putmem/getmem manipulation makes scanner see `builtins.str.system` while unpickler sees `os.system`.
4. **Joblib format interruption**: Random byte blob in middle stops scanner parsing. Payload after blob is invisible.

## PickleScan CVEs (2025)

- CVE-2025-10155: File extension bypass (rename .pkl to .bin)
- CVE-2025-10156: CRC bypass in ZIP archives
- CVE-2025-10157: Unsafe globals subclass bypass
- Sonatype found 4 additional critical vulnerabilities
- Total: 7 CVEs in one year, all allowing complete scanner bypass

## Tool Details

### Fickling (Trail of Bits)
- GitHub: https://github.com/trailofbits/fickling
- Approach: Allowlist + decompiler. Blocks unknown imports by default.
- Unique: Can decompile pickle to show exactly what code would execute
- Install: `pip install fickling`
- Had CVE-2026-22612 (detection bypass found)

### ModelScan (Protect AI)
- GitHub: https://github.com/protectai/modelscan
- Approach: Denylist with broad format support
- Formats: Pickle, Dill, Cloudpickle, PyTorch, Keras H5/V3, TF SavedModel, NumPy, Joblib
- Install: `pip install modelscan`
- Enterprise version (Guardian) powers HuggingFace's scanning

### PickleScan
- GitHub: https://github.com/mmaitre314/picklescan
- What HuggingFace uses on their platform
- Install: `pip install picklescan`
- 7 critical CVEs found in 2025

### ModelAudit (Promptfoo)
- GitHub: https://github.com/promptfoo/modelaudit
- 42+ formats including ONNX, SafeTensors, PMML, JSON/YAML configs
- Detects embedded executables, secrets, network indicators
- Outperformed ModelScan 16-to-3 in head-to-head
- Install: `npm install -g promptfoo`

### Dyana (Dreadnode) — Dynamic Analysis
- GitHub: https://github.com/dreadnode/dyana
- eBPF sandbox: traces syscalls, file access, network, GPU
- Catches everything static scanners miss (time-delayed, env-dependent)
- Requires Docker + Linux
- Install: `pip install dyana`
- Recommend for high-value models after static scanning passes

## ISM-2072 Context

Australian ISM control (December 2025) mandating non-executable model formats. First government to issue a specific technical control rather than principles-level guidance. Applies at all classification levels (NC through TS). IRAP assessors must check compliance.
