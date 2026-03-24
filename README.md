# raxIT Agent Skills

Open-source Agent Skills for AI Security by [raxIT](https://raxit.ai).

Skills are folders of instructions, scripts, and resources that Claude loads dynamically to improve performance on specialized tasks. These skills focus on AI security workflows that practitioners need.

For more about the Agent Skills standard, see [agentskills.io](http://agentskills.io).

## Skills

| Skill | Description |
|-------|-------------|
| [model-scanner](./skills/model-scanner) | Multi-scanner ML model security analysis. Runs pickle, safetensors, and other model files through Fickling, ModelScan, ModelAudit, and PickleScan with aggregated verdicts. |

## Install in Claude Code

Register as a plugin marketplace:

```
/plugin marketplace add raxITlabs/skills
```

Then install:

```
/plugin install ai-security-skills@raxit-ai-security-skills
```

Or install a specific skill directly:

```
npx skills add raxITlabs/skills@model-scanner -g -y
```

## Why These Skills Exist

AI model files are treated as "just data" by most security teams. They're not. Pickle-based model files can execute arbitrary code on load. Static scanners have been bypassed repeatedly (7 CVEs in PickleScan in 2025 alone, 133 exploitable gadgets with near-100% bypass rate).

Australia's ISM-2072 (December 2025) became the first government control to mandate non-executable model formats. These skills help practitioners assess their model supply chain security.

## Creating Your Own Skills

Use the `template/` directory as a starting point. Each skill needs a `SKILL.md` file with YAML frontmatter:

```markdown
---
name: my-skill-name
description: A clear description of what this skill does and when to use it
---

# My Skill Name

[Instructions here]
```

## License

Apache 2.0
