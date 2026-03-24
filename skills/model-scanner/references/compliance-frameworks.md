# Compliance Frameworks Reference

Read this file when the user asks about specific compliance requirements, what a control means, or how to achieve compliance.

## ISM (Australian Information Security Manual)

**Authority:** Australian Signals Directorate (ASD)
**Enforcement:** IRAP assessors, mandatory for government systems at all classification levels

| Control | Title | Requirement |
|---------|-------|-------------|
| ISM-2072 | Model storage format | AI models must be stored in a file format that does not allow arbitrary code execution |
| ISM-2086 | Model integrity | Verify source and integrity of AI models, structures and weights |
| ISM-2087 | Training data integrity | Verify source and integrity of training data |
| ISM-2092 | Fine-grained access | Implement fine-grained access control policies for AI applications |

**How to comply:**
- ISM-2072: Use SafeTensors, ONNX, or GGUF instead of pickle. Scanning alone is not compliance.
- ISM-2086: Verify model checksums, use signed models (OpenSSF Model Signing spec)
- ISM-2092: Disable trust_remote_code, audit auto_map Python files

## EU AI Act

**Authority:** European Parliament
**Enforcement:** National authorities, fines up to 35M EUR or 7% global turnover

| Article | Title | Relevance |
|---------|-------|-----------|
| Art. 15 | Accuracy, robustness and cybersecurity | High-risk AI must be resilient against model poisoning and supply chain attacks |

**How to comply:**
- Use non-executable model formats to prevent poisoning via deserialization
- Verify model provenance and integrity before deployment
- Document model supply chain in technical documentation

## OWASP LLM Top 10

**Authority:** OWASP Foundation
**Enforcement:** Industry best practice, referenced by regulators

| Risk | Title | Relevance |
|------|-------|-----------|
| LLM06 | Supply Chain Vulnerabilities | Executable model formats, unverified sources, tampered weights |

**How to comply:**
- Scan all models before deployment (multi-scanner approach)
- Use non-executable formats where possible
- Verify model checksums and signatures
- Maintain model inventory with provenance tracking

## MITRE ATLAS

**Authority:** MITRE Corporation
**Enforcement:** Threat intelligence framework

| Technique | Title | Relevance |
|-----------|-------|-----------|
| AML.T0010 | ML Supply Chain Compromise | Attacker poisons model via malicious weights, architecture code, or training data |
| AML.T0010.002 | Backdoor ML Model | Attacker embeds backdoor that activates on specific inputs |

**How to mitigate:**
- Scan models for embedded code before loading
- Use non-executable formats to eliminate deserialization attacks
- Verify model source matches expected publisher

## NIST AI RMF

**Authority:** National Institute of Standards and Technology (USA)
**Enforcement:** Voluntary framework, increasingly referenced by US regulators

| Function | Category | Relevance |
|----------|----------|-----------|
| MAP 3.4 | AI supply chain risk | Risks related to third-party AI components |
| MANAGE 2.4 | Risk tracking | Mechanisms for tracking identified AI risks |
| MANAGE 4.1 | Post-deployment monitoring | Monitor AI system behavior after deployment |

**How to comply:**
- Inventory all AI models and their sources
- Assess supply chain risk for each model (format, provenance, integrity)
- Establish monitoring for model behavior anomalies
