# NuGuard Benchmark Suite

This directory contains ground truth datasets and evaluation tools for measuring AI analysis accuracy across two phases:

1. **Asset Discovery (Phase 1)** - Evaluate AI component detection accuracy
2. **Risk Assessment (Phase 2)** - Evaluate compliance gap analysis, covered controls, and risk scoring

## Structure

```
benchmark/
├── __init__.py              # Package init with exports
├── evaluate.py              # Asset discovery evaluation script
├── evaluate_risk.py         # Risk assessment evaluation script
├── schemas.py               # Asset discovery ground truth schemas
├── schemas_risk.py          # Risk assessment ground truth schemas
├── fetcher.py               # GitHub repo fetching utilities
├── README.md                # This file
├── policies/                # Policy fixture files
│   ├── owasp_ai_top_10.json
│   ├── hipaa.json
│   └── ...
└── repos/                   # Ground truth datasets
    ├── Healthcare-voice-agent/
    │   ├── ground_truth.json         # Asset discovery ground truth
    │   └── risk_ground_truth.json    # Risk assessment ground truth
    ├── openai-swarm/
    │   └── ground_truth.json
    └── ...
```

---

## Asset Discovery Benchmark (Phase 1)

Phase 1 now defaults to **API mode** and uses the `ai_asset_service` test CLI flow
(`backend/ai_asset_service/test_ai_asset_service.py`) to trigger AIBOM extraction.
Use `--mode local` only if you explicitly want the legacy in-process extractor.

Required auth for API mode:

```bash
export NUGUARD_EMAIL=admin@nuguard.ai
export NUGUARD_PASSWORD=admin123
# optional
export GITHUB_TOKEN=ghp_xxx
```

### Run All Benchmarks
```bash
cd backend
python -m benchmark.evaluate --all
```

### Run Single Repository
```bash
python -m benchmark.evaluate --repo langchain-examples
```

### Options
```bash
python -m benchmark.evaluate --all --output results.json  # JSON output
python -m benchmark.evaluate --all --verbose              # Show FP/FN details
python -m benchmark.evaluate --repo crewai-examples --mode local --enable-llm  # Enable LLM enrichment
python -m benchmark.evaluate --repo openai-cs-agents-demo --mode api \
  --data-service-url http://localhost:8000 \
  --asset-service-url http://localhost:8004
```

### Ground Truth Format (`ground_truth.json`)

```json
{
  "repo_name": "Healthcare-voice-agent",
  "repo_url": "https://github.com/NuGuardAI/Healthcare-voice-agent",
  "branch": "main",
  "annotated_at": "2026-02-06",
  "frameworks": ["langgraph", "langchain"],
  "assets": [
    {
      "asset_type": "AGENT",
      "name": "normalize_agent",
      "file_path": "backend/langgraph_llm_agents.py",
      "line_start": 42,
      "description": "LangGraph agent for symptom normalization",
      "framework": "langgraph"
    }
  ],
  "expected_counts": {
    "AGENT": 5,
    "MODEL": 1
  }
}
```

### Metrics

| Metric | Description |
|--------|-------------|
| **Precision** | TP / (TP + FP) — How many discovered assets are real? |
| **Recall** | TP / Total Ground Truth — How many real assets were found? |
| **F1 Score** | Harmonic mean of Precision and Recall |
| **By-Type** | Per asset-type precision/recall breakdown |

---

## Risk Assessment Benchmark (Phase 2)

### Run All Risk Benchmarks
```bash
cd backend
python -m benchmark.evaluate_risk --all
```

### Run Single Repository
```bash
python -m benchmark.evaluate_risk --repo Healthcare-voice-agent
```

### Options
```bash
python -m benchmark.evaluate_risk --all --output risk_results.json  # JSON output
python -m benchmark.evaluate_risk --all --verbose                   # Show details
python -m benchmark.evaluate_risk --repo Healthcare-voice-agent --skip-discovery  # Use cached assets
python -m benchmark.evaluate_risk --list                            # List available repos
```

### Ground Truth Format (`risk_ground_truth.json`)

```json
{
  "repo_name": "Healthcare-voice-agent",
  "repo_url": "https://github.com/NuGuardAI/Healthcare-voice-agent",
  "branch": "main",
  "annotated_at": "2026-02-06",
  "policies_evaluated": ["OWASP AI Top 10", "HIPAA"],
  
  "expected_findings": [
    {
      "title": "Missing Input Validation for Patient Symptoms",
      "severity": "HIGH",
      "control_id": "OWASP-A01",
      "policy_name": "OWASP AI Top 10",
      "affected_file": "backend/langgraph_llm_agents.py",
      "evidence_keywords": ["user input", "no validation"],
      "match_flexibility": "SEMANTIC"
    }
  ],
  
  "expected_covered_controls": [
    {
      "control_id": "HIPAA-164.312(e)(1)",
      "control_name": "Transmission Security",
      "policy_name": "HIPAA",
      "evidence_type": "ARCHITECTURE",
      "evidence_keywords": ["https", "TLS"]
    }
  ],
  
  "expected_risk_score": {
    "score": 68,
    "band": "HIGH",
    "tolerance": 15
  },
  
  "expected_red_team_attacks": {
    "min_count": 3,
    "expected_types": ["PROMPT_INJECTION", "PII_LEAKAGE"]
  }
}
```

### Metrics

| Metric | Description |
|--------|-------------|
| **Finding F1** | Precision/Recall for compliance gap findings |
| **Covered Control F1** | Precision/Recall for evidence-backed controls |
| **Risk Score MAE** | Mean Absolute Error from expected score |
| **Band Accuracy** | % repos with correct risk band (LOW/MEDIUM/HIGH/CRITICAL) |
| **Quality Score** | Weighted composite of all metrics (0-1) |

### Matching Flexibility

Findings and controls support different matching levels:

| Level | Criteria |
|-------|----------|
| `EXACT` | control_id + severity + file must all match |
| `EXACT_CONTROL` | control_id + policy match, severity ±1 |
| `SEMANTIC` | policy + severity category + keyword overlap |
| `TYPE_ONLY` | Same severity category only |

---

## Policy Fixtures

Policy fixtures in `policies/` provide standardized control definitions:

```json
{
  "policy_name": "OWASP AI Top 10",
  "controls": [
    {
      "control_id": "OWASP-A01",
      "name": "Prompt Injection",
      "description": "Manipulation of LLM behavior through malicious inputs...",
      "typical_gaps": ["No input sanitization", "System prompt exposed"],
      "typical_mitigations": ["Input filtering", "Guardrail implementation"]
    }
  ]
}
```

---

## Adding New Benchmark Repos

### For Asset Discovery

1. Create directory: `repos/<repo-name>/`
2. Add `ground_truth.json` with annotated assets
3. Run: `python -m benchmark.evaluate --repo <repo-name>`

### For Risk Assessment

1. Ensure asset discovery ground truth exists
2. Add `risk_ground_truth.json` with expected findings/controls
3. Run: `python -m benchmark.evaluate_risk --repo <repo-name>`

---

## Ground Truth Annotation Process

Creating high-quality ground truth annotations requires a systematic approach. Follow these steps for each benchmark repository.

### Step 1: Run Asset Discovery First

```bash
# Run discovery to understand the repo structure
python -m benchmark.evaluate --repo <repo-name>
```

This helps identify:
- AI frameworks in use (LangGraph, CrewAI, etc.)
- Number and types of agents, tools, prompts
- Key files where security issues might appear

### Step 2: Identify Applicable Policies

Based on the application domain, select relevant policies:

| Domain | Recommended Policies |
|--------|---------------------|
| Healthcare | OWASP AI Top 10, HIPAA, NIST AI RMF |
| Finance | OWASP AI Top 10, PCI-DSS, SOC 2 |
| General AI | OWASP AI Top 10, NIST AI RMF |
| EU Users | EU AI Act |

### Step 3: Manual Code Review for Findings

Review the codebase for compliance gaps:

1. **Input Validation** (OWASP-A01): Is user input sanitized before LLM calls?
2. **Output Handling** (OWASP-A02): Are LLM responses validated before use?
3. **Data Exposure** (OWASP-A06): Is sensitive data exposed in prompts?
4. **Excessive Agency** (OWASP-A08): Can agents take autonomous actions?
5. **Logging** (OWASP-A09): Is there adequate audit logging?

For each gap found, document:
- Title: Concise description
- Severity: CRITICAL > HIGH > MEDIUM > LOW > INFO
- Control ID: From the relevant policy
- Affected file: Where the issue appears
- Evidence keywords: Phrases that indicate the gap
- Remediation keywords: What should be added

### Step 4: Identify Covered Controls

Look for evidence that controls ARE implemented:

```python
# Example: Input validation evidence
if "sanitize" in code or "filter" in code or "validate" in code:
    # Candidate for covered control
```

Document:
- Control ID and name
- Evidence type: CODE, CONFIG, DOCUMENTATION, ARCHITECTURE
- Evidence keywords: Phrases proving compliance

### Step 5: Estimate Risk Score

Based on findings severity distribution:

| Finding Distribution | Expected Band | Score Range |
|---------------------|---------------|-------------|
| Any CRITICAL | CRITICAL | 80-100 |
| Multiple HIGH | HIGH | 60-79 |
| Mostly MEDIUM | MEDIUM | 40-59 |
| Only LOW/INFO | LOW | 0-39 |

Set tolerance based on confidence (±10 for high confidence, ±15-20 for lower).

### Step 6: Plan Red Team Attacks

Identify attack vectors based on discovered assets:

| Asset Type | Typical Attacks |
|------------|-----------------|
| AGENT with tools | PROMPT_INJECTION, JAILBREAK |
| User input handling | PROMPT_INJECTION |
| PII/PHI processing | PII_LEAKAGE |
| Model outputs | HALLUCINATION |
| Multi-agent | AGENT_HIJACKING |

### Step 7: Validate Ground Truth

```bash
# Dry-run to check parsing
python -m benchmark.evaluate_risk --repo <repo-name>

# Run unit tests
python -m pytest backend/tests/test_benchmark_risk.py -v
```

### Annotation Guidelines

**Match Flexibility Selection:**
- `EXACT`: Use for specific, unique findings with exact control + file + severity
- `EXACT_CONTROL`: Same control ID, flexible description/severity  
- `SEMANTIC`: Similar meaning, same policy/category, keyword overlap (most common)
- `TYPE_ONLY`: Only severity category matters

**Confidence Minimums:**
- 70+: High confidence findings (clear code evidence)
- 50-69: Medium confidence (inferred from patterns)
- 30-49: Low confidence (may vary between runs)

**Evidence Keywords:**
- Include 2-4 key phrases that would appear in finding descriptions
- Use lowercase, avoid special characters
- Focus on what the AI would say, not the code itself

---

## CI Integration

### Asset Discovery Check
```yaml
- name: Run Asset Discovery Benchmark
  run: python -m benchmark.evaluate --all --output discovery_results.json

- name: Check Discovery Threshold
  run: |
    F1=$(python -c "import json; print(json.load(open('discovery_results.json'))['overall_f1'])")
    if (( $(echo "$F1 < 0.80" | bc -l) )); then exit 1; fi
```

### Risk Assessment Check
```yaml
- name: Run Risk Assessment Benchmark
  run: python -m benchmark.evaluate_risk --all --output risk_results.json

- name: Check Risk Quality Threshold
  run: |
    QUALITY=$(python -c "import json; print(json.load(open('risk_results.json'))['aggregate_quality_score'])")
    if (( $(echo "$QUALITY < 0.70" | bc -l) )); then exit 1; fi
```

---

## Policy Compliance Benchmark (Phase 3)

The policy benchmark evaluates CCD (Compliance Control Descriptor) format policies against AIBOMs to measure policy assessment accuracy.

### Directory Structure

```
benchmark/
├── policies_ccd/                    # CCD-format policies
│   └── owasp_ai_top_10/
│       ├── policy_index.json        # Policy metadata and control list
│       ├── A01_prompt_injection.json
│       ├── A02_insecure_output.json
│       └── A05_supply_chain.json
├── policy_ground_truth/             # Expected policy evaluation results
│   └── owasp_ai_top_10/
│       └── langchain-quickstart.json
└── evaluate_policies.py             # Policy evaluation runner
```

### Run All Policy Benchmarks
```bash
cd backend
python -m benchmark.evaluate_policies --all
```

### Run Single Policy
```bash
python -m benchmark.evaluate_policies --policy owasp_ai_top_10
```

### Evaluate Policy Against Specific Repo
```bash
python -m benchmark.evaluate_policies --policy owasp_ai_top_10 --repo langchain-quickstart
```

### List Available Policies and Repos
```bash
python -m benchmark.evaluate_policies --list
```

### CCD Format

CCDs define how to evaluate compliance controls against an AIBOM:

```json
{
  "control_id": "OWASP-A01",
  "check_id": "A01-guardrails-present",
  "title": "Prompt Injection Defense",
  "severity": "HIGH",
  
  "applies_if": {
    "aibom_has_nodes": ["AGENT", "PROMPT"]
  },
  
  "queries": [
    {
      "id": "find_agents_with_prompts",
      "type": "find_nodes",
      "filter": {"type": "AGENT"}
    }
  ],
  
  "assertions": [
    {
      "id": "agents_have_guardrails",
      "type": "must_exist_per_instance",
      "severity": "HIGH",
      "for_each": {"query": {"type": "AGENT"}},
      "require": {"relationship": "protected_by", "target_type": "GUARDRAIL"}
    }
  ],
  
  "scoring": {
    "method": "graded",
    "pass_threshold": 0.80
  },
  
  "gap_diagnosis": {
    "no_guardrails": "No input guardrails detected"
  },
  
  "fix_guidance": [
    {
      "id": "add_guardrail",
      "action": "Implement input validation guardrail",
      "priority": 1
    }
  ]
}
```

### Policy Ground Truth Format

Ground truth files define expected evaluation results for a policy-repo pair:

```json
{
  "policy_id": "owasp_ai_top_10",
  "policy_name": "OWASP AI Top 10",
  "category": "security",
  "target_repo": "langchain-quickstart",
  
  "expected_overall_score": 0.35,
  "expected_pass_threshold": 0.70,
  
  "controls": [
    {
      "control_id": "OWASP-A01",
      "title": "Prompt Injection Defense",
      "expected_applicable": true,
      "expected_pass": false,
      "expected_score": 0.0,
      "assertions": [
        {
          "assertion_id": "agents_have_guardrails",
          "type": "must_exist_per_instance",
          "expected_pass": false
        }
      ],
      "expected_gaps": ["no_guardrails"]
    }
  ],
  
  "annotated_at": "2026-02-07"
}
```

### Assertion Types

| Type | Description |
|------|-------------|
| `must_exist` | Query must return at least `min_count` matches |
| `must_not_exist` | Query must return at most `max_count` matches |
| `must_exist_per_instance` | Each instance from `for_each` must meet `require` conditions |
| `must_exist_on_path` | Paths must include required intermediate nodes |
| `property_constraint` | Nodes must have specified property values |
| `count_threshold` | Count of matches must be within threshold |

### Policy Benchmark Metrics

| Metric | Description |
|--------|-------------|
| **Score Accuracy** | 1 - abs(actual_score - expected_score) |
| **Control Accuracy** | % of controls with correct pass/fail result |
| **Assertion Accuracy** | % of assertions with correct evaluation |
| **Gap Precision** | Correct gaps / detected gaps |
| **Gap Recall** | Correct gaps / expected gaps |
| **Gap F1** | Harmonic mean of gap precision and recall |

### CI Integration

```yaml
- name: Run Policy Benchmark
  run: python -m benchmark.evaluate_policies --all --output policy_results.json

- name: Check Policy Accuracy Threshold
  run: |
    ACCURACY=$(python -c "import json; print(json.load(open('policy_results.json'))['overall_control_accuracy'])")
    if (( $(echo "$ACCURACY < 0.80" | bc -l) )); then exit 1; fi
```
