# Bayora Data Directory

This directory contains datasets, defense bundles, and model files used by the Bayora evaluation platform.

## Architecture & Security Boundaries

Bayora enforces strict tenant data isolation at the container boundary:
- **Red Agent (`red`)**: Mounts `./data/red` read-only at `/data`. Contains only the compiled attack pool (`pool.jsonl`).
- **Blue Agent (`blue`)**: Mounts `./data/blue` read-only at `/data`. Contains only pre-approved defense bundles (`bundles/`).
- **Model Server (`model`)**: Mounts `./data/models` read-only at `/models`.
- **Operator / Host**: Places raw source files into `./data/raw` for local dataset compilation.

Tenants never have access to `./data/raw` or each other's directories.

---

## Directory Structure

```text
data/
├── raw/                      # Raw upstream datasets (host-only, gitignored)
│   ├── harmful_behaviors.csv # AdvBench dataset
│   └── gandalf_ignore_instructions.json # Lakera Gandalf export
├── red/                      # Attack pool for red team (read-only in red container)
│   └── pool.jsonl            # Compiled prompts ({id, source, category, prompt})
├── blue/                     # Defense bundles for blue team (read-only in blue container)
│   └── bundles/
│       ├── baseline.json     # Baseline defense bundle (tracked in git)
│       └── hardened.json     # Hardened defense bundle (tracked in git)
├── models/                   # Local GGUF LLM models (read-only in model container)
└── README.md                 # This documentation
```

---

## 1. Attack Pool Production (`data/red/pool.jsonl`)

The attack pool is generated locally via `scripts/prepare_datasets.py`:

```bash
python3 scripts/prepare_datasets.py
```

### Raw Sources
1. **AdvBench (`harmful_behaviors.csv`)**:
   Standard safety testing benchmarks containing adversarial instructions across harmful categories.
2. **Lakera Gandalf (`gandalf_ignore_instructions.json`)**:
   Empirical prompt injection attempts designed to bypass system prompt constraints.

### Wrapper Templates
The preparation script applies adversarial framing templates to evaluate defense robustness:
- `roleplay`: Villain actor framing in fictional contexts.
- `ignore_instructions`: Direct prompt injection and instruction overrides.
- `academic_research`: Educational and academic inquiry framing.
- `system_override`: System administrative override pretexting.
- `hypothetical`: Theoretical cybersecurity research pretexting.

### Schema
Each line in `data/red/pool.jsonl` is a JSON record:
```json
{"id": "advbench_001_roleplay", "source": "advbench", "category": "roleplay_jailbreak", "prompt": "..."}
```

---

## 2. Defense Bundles (`data/blue/bundles/`)

Defense bundles define input and output inspection rules applied by the gateway. Bundles are purely data, never executed (SI-09).

### Bundles Provided:
1. `baseline.json`:
   - Basic keyword matching rules (`type: "contains"`).
   - Simulates a naive defense with minimal filtering.
2. `hardened.json`:
   - Advanced regex patterns with boundaries (`type: "regex"`).
   - Covers roleplay prefixes, instruction ignore patterns, override markers, and harmful intent keywords.
   - All regex operations run with strict execution timeouts to prevent ReDoS.

### Schema (Architecture §7)
```json
{
  "version": "hardened-v1",
  "input_rules": [
    {"id": "I1", "type": "regex", "pattern": "(?i)ignore\\s+.*instructions", "action": "block"}
  ],
  "output_rules": [
    {"id": "O1", "type": "contains", "pattern": "confidential_flag", "action": "block"}
  ],
  "refusal_text": "Request blocked by safety policy."
}
```

---

## 3. Git Version Control Policy

Per Security Invariant **SI-10**:
- **Tracked in Git**: `data/blue/bundles/baseline.json` and `data/blue/bundles/hardened.json`.
- **Gitignored**: `data/raw/`, `data/red/`, `data/models/`.
- No raw attack prompts, raw secrets, or binary models enter source control.
