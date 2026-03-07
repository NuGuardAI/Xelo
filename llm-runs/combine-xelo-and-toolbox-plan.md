# Plan: Combine Xelo + Xelo-Toolbox into a Single Open-Source Repo

**Date:** 2026-03-07  
**Branch:** `2-feat-combine-xelo-and-xelo-toolbox`  
**Goal:** Bring Xelo-toolbox into this repo, simplify the CLI and developer SDK, and publish a clean combined package on PyPI.

---

## 1. What each repo currently contains

### Xelo (`src/ai_sbom/`)
| Module | Role |
|---|---|
| `extractor.py` | 3-phase pipeline: AST adapters → regex fallbacks → optional LLM enrichment (`AiSbomExtractor`) |
| `adapters/` | Framework detection adapters (Python + TypeScript) |
| `models.py` | Pydantic v2 document model (`AiSbomDocument`) |
| `serializer.py` | JSON / CycloneDX / unified output (`AiSbomSerializer`) |
| `cli.py` | `xelo scan path`, `xelo scan repo`, `xelo validate`, `xelo schema` |
| `config.py` | `AiSbomConfig` |
| `__init__.py` | Public SDK: `AiSbomDocument`, `AiSbomConfig`, `AiSbomExtractor`, `AiSbomSerializer` |

### Xelo-Toolbox (`tests/benchmark/` — currently living here as dead weight)
| Module | Role |
|---|---|
| `evaluate.py` | Asset-discovery benchmark: precision/recall/F1 vs ground truth |
| `evaluate_risk.py` | Risk-assessment benchmark: findings, controls, risk scores vs ground truth |
| `evaluate_policies.py` | CCD-format policy evaluation against AIBOMs |
| `evaluate_streaming.py` | Streaming-service evaluation (compares against live endpoint) |
| `fetcher.py` | GitHub repo fetch/clone helpers for benchmarks |
| `schemas.py` + `schemas_risk.py` | Pydantic ground-truth schemas |
| `repos/*/ground_truth.json` | Ground truth datasets (21 repos) |
| `policies/` | Policy fixture files (OWASP AI Top 10, HIPAA, NIST AI RMF, EU AI Act) |
| `policies_ccd/` | CCD-format policy fixtures |
| `policy_ground_truth/` | Expected policy evaluation results |

---

## 2. Package naming and conventions

### 2a. Rename `ai_sbom` → `xelo`

**Yes — rename the importable package from `ai_sbom` to `xelo`.**

The PyPI distribution is already `xelo` and the CLI is already `xelo`. The current mismatch (`pip install xelo` but `import ai_sbom`) is confusing for open-source contributors and violates the principle of least surprise. A `src/xelo/` shim that re-exports from `ai_sbom` already exists, which confirms the intent — but the shim is inside-out. The real package should be `xelo`; the shim is eliminated.

| Concern | Before | After |
|---|---|---|
| Install | `pip install xelo` | `pip install xelo` (unchanged) |
| Import | `import ai_sbom` | `import xelo` |
| Import (toolbox) | `from ai_sbom.toolbox import ...` | `from xelo.toolbox import ...` |
| Core class names | `AiBomDocument`, `SbomExtractor`, `SbomSerializer`, `ExtractionConfig` | `AiSbomDocument`, `AiSbomExtractor`, `AiSbomSerializer`, `AiSbomConfig` |
| Entry point | `xelo = ai_sbom.cli:main` | `xelo = xelo.cli:main` |
| `src/` layout | `src/ai_sbom/` + `src/xelo/` (shim) | `src/xelo/` only |

### 2b. Naming conventions

Python-standard conventions enforced throughout the codebase:

| Scope | Convention | Examples |
|---|---|---|
| Package / module names | `snake_case` | `xelo`, `xelo.toolbox`, `xelo.plugins`, `xelo.adapters` |
| Class names | `PascalCase` | `AiSbomDocument`, `AiSbomExtractor`, `AiSbomSerializer`, `AiSbomConfig`, `PluginAdapter` |
| Function / method names | `snake_case` | `extract_from_path()`, `evaluate_repo()`, `load_plugins()` |
| Constants | `UPPER_SNAKE_CASE` | `CONFIDENCE_THRESHOLD`, `MAX_FILES` |
| Env vars | `UPPER_SNAKE_CASE` with `XELO_` prefix | `XELO_LLM`, `XELO_LLM_MODEL` |

Class name rule: all public classes carry the `AiSbom` prefix so the namespace is self-documenting — `AiSbomDocument`, `AiSbomExtractor`, `AiSbomSerializer`, `AiSbomConfig`. Toolbox result classes use a consistent `<Scope>EvaluationResult` suffix: `ScanEvaluationResult`, `RiskEvaluationResult`, `PolicyEvaluationResult`.

### 2c. Repository layout

```
src/
└── xelo/                           ← the one importable package (PyPI: xelo)
    ├── __init__.py                  ← public SDK (see §4)
    ├── cli.py                       ← simplified, see §3
    ├── config.py
    ├── extractor.py
    ├── models.py
    ├── serializer.py
    ├── types.py
    ├── normalization.py
    ├── deps.py
    ├── merger.py
    ├── cdx_tools.py
    ├── llm_client.py
    ├── ast_parser.py
    ├── py.typed
    ├── schemas/
    ├── adapters/                    ← core detection adapters (team-owned)
    │   ├── base.py
    │   ├── registry.py
    │   ├── python/
    │   └── typescript/
    ├── core/                        ← internal pipeline utilities
    ├── plugins/                     ← community plug-ins (see §5)
    │   ├── __init__.py              ← opt-in loader
    │   ├── base.py                  ← PluginAdapter ABC (minimal surface)
    │   └── <plugin_name>.py         ← one flat file per plug-in
    └── toolbox/                     ← moved from tests/benchmark/
        ├── __init__.py              ← public toolbox SDK (see §4)
        ├── evaluate.py              ← asset-discovery evaluation
        ├── evaluate_risk.py         ← risk evaluation
        ├── evaluate_policies.py     ← policy evaluation
        ├── fetcher.py               ← repo fetch helpers
        ├── schemas.py               ← ground-truth schemas
        ├── schemas_risk.py
        └── policies/                ← built-in policy fixtures
            ├── owasp_ai_top_10.json
            ├── hipaa.json
            ├── nist_ai_rmf.json
            └── eu_ai_act.json

tests/
├── conftest.py
├── test_cli.py                     ← covers new unified CLI
├── test_extraction.py
├── test_toolbox/                   ← replaces tests/benchmark/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_evaluate.py
│   ├── test_evaluate_risk.py
│   ├── test_evaluate_policies.py
│   └── fixtures/                   ← ground truth datasets (moved from benchmark/repos/)
│       ├── Healthcare-voice-agent/
│       ├── openai-swarm/
│       └── ...
├── fixtures/                       ← existing extraction fixtures (unchanged)
└── smoke/                          ← existing smoke tests (unchanged)
```

### 2d. Why `xelo/toolbox/` not a sibling package

- One `pip install xelo` installs everything — no separate `xelo-toolbox` coordinate.
- Contributors clone one repo. No cross-repo import chains.
- `toolbox` is a logical sub-namespace; it imports `xelo` internals freely.
- The separation is explicit: `from xelo.toolbox import ...` vs `from xelo import ...`.

---

## 3. Simplified CLI

### Current pain points
- `xelo scan path <path>` vs `xelo scan repo <url>` is two levels deep for a common operation.
- `--format` has three values with subtle differences that need the docstring to understand.
- LLM flags are repeated verbatim in both `scan path` and `scan repo`.
- No toolbox commands exist at all.

### New CLI surface (proposed)

```
xelo scan <path|url>             # auto-detects path vs URL
    --format json|cyclonedx|unified   (default: json)
    --output <file>               (default: stdout for json)
    --llm                         (enable LLM enrichment; env: XELO_LLM=true)
    --llm-model <model>           (env: XELO_LLM_MODEL)
    --llm-api-key <key>           (env: XELO_LLM_API_KEY)
    --llm-api-base <url>          (env: XELO_LLM_API_BASE)
    -v / --verbose
    --debug

xelo validate <file>             # unchanged

xelo schema [--output <file>]    # unchanged, default: stdout

# ── New toolbox commands ────────────────────────────────────────────────────

xelo eval <path|url>             # run asset-discovery benchmark (evaluate.py)
    --ground-truth <file>         (required — datasets are not bundled in the wheel)
    --output <file>               (default: stdout)
    --threshold <0-1>             (default: 0.80)
    -v / --verbose

xelo eval-risk <path|url>        # run risk-assessment benchmark (evaluate_risk.py)
    --ground-truth <file>         (required)
    --output <file>
    --threshold <0-1>
    -v / --verbose

xelo eval-policy <path|url>      # run policy evaluation (evaluate_policies.py)
    --policy <name|file>          # built-in: owasp_ai_top_10, hipaa, nist_ai_rmf, eu_ai_act
    --output <file>
    -v / --verbose
```

### Key simplification rules applied

1. **Flatten `scan path` / `scan repo` into `scan`** — the argument is either a local path or a URL; the CLI detects which by checking `://` presence.
2. **Rename `--enable-llm` → `--llm`** — shorter, consistent with common tool conventions.
3. **Default `--output` to stdout for JSON** — lets `xelo scan . | jq` work naturally.
4. **Toolbox commands are first-class CLI verbs**, not buried under `benchmark`.
5. **No deprecated aliases** — clean break, version bump to `0.2.0`.

---

## 4. Simplified Developer SDK

### Current `ai_sbom/__init__.py` (4 symbols)
```python
from .config import ExtractionConfig   # → renamed AiSbomConfig
from .extractor import SbomExtractor   # → renamed AiSbomExtractor
from .models import AiBomDocument      # → renamed AiSbomDocument
from .serializer import SbomSerializer # → renamed AiSbomSerializer
```

### New `xelo/__init__.py` (core — 4 symbols, consistent prefix)
```python
# Core scan-and-serialize workflow
from .config import AiSbomConfig
from .extractor import AiSbomExtractor
from .models import AiSbomDocument
from .serializer import AiSbomSerializer

__all__ = [
    "AiSbomDocument",
    "AiSbomConfig",
    "AiSbomExtractor",
    "AiSbomSerializer",
]
```

### New `xelo/toolbox/__init__.py` (toolbox SDK)
```python
from .evaluate import evaluate_repo, ScanEvaluationResult
from .evaluate_risk import evaluate_risk, RiskEvaluationResult
from .evaluate_policies import evaluate_policies, PolicyEvaluationResult
from .fetcher import fetch_repo_for_benchmark

__all__ = [
    "evaluate_repo",
    "ScanEvaluationResult",
    "evaluate_risk",
    "RiskEvaluationResult",
    "evaluate_policies",
    "PolicyEvaluationResult",
    "fetch_repo_for_benchmark",
]
```

### Typical developer usage after combination

```python
# Scan
import xelo
doc = xelo.AiSbomExtractor().extract_from_path("./my-app")

# Evaluate extraction quality (new, one import)
# ground_truth_path is always required — datasets are not bundled in the wheel
from xelo.toolbox import evaluate_repo
result = evaluate_repo("./my-app", ground_truth_path="ground_truth.json")
print(result.f1_score)   # result is a ScanEvaluationResult

# Policy check (new)
from xelo.toolbox import evaluate_policies
result = evaluate_policies(doc, policy="owasp_ai_top_10")  # PolicyEvaluationResult
```

### SDK design principles
- **`AiSbom` prefix for all core classes** — `AiSbomDocument`, `AiSbomExtractor`, `AiSbomSerializer`, `AiSbomConfig` are instantly recognisable as the public API.
- **`<Scope>EvaluationResult` suffix for all toolbox result classes** — `ScanEvaluationResult`, `RiskEvaluationResult`, `PolicyEvaluationResult` follow one pattern.
- **No internal classes leak into public `__init__`** — only function-level entry points for toolbox.
- **All toolbox functions accept both a path/URL string and a pre-built `AiSbomDocument`** — compose freely.
- **Pydantic result models for everything** — callers get typed, serialisable objects.
- **No required env vars for core scan** — LLM and auth are strictly opt-in.

---

## 5. Plug-in system (simplified, language-agnostic)

Since language-split plug-ins are not needed, the `plugins/` layout is flat:

```
src/xelo/plugins/
├── __init__.py          ← opt-in loader
├── base.py              ← PluginAdapter ABC
└── <name>.py            ← one file per plug-in
```

### `plugins/base.py` minimal ABC
```python
from abc import ABC, abstractmethod
from xelo.adapters.base import ComponentDetection, ParseResult

class PluginAdapter(ABC):
    """Minimal interface for community plug-ins."""

    name: str           # unique slug, e.g. "my_framework"
    priority: int = 50  # lower = higher precedence; core adapters use 10–40

    @abstractmethod
    def can_handle(self, imports: frozenset[str]) -> bool:
        """Return True if this plug-in should run for the given import set."""

    @abstractmethod
    def extract(self, parse_result: ParseResult) -> list[ComponentDetection]:
        """Extract components from the parsed file."""
```

### `plugins/__init__.py` — explicit opt-in loading
```python
import importlib, pkgutil
from .base import PluginAdapter

def load_plugins() -> list[PluginAdapter]:
    """Discover and instantiate all PluginAdapter subclasses in this package.

    Called only when AiSbomExtractor(load_plugins=True) is used.
    Default extractor runs are plugin-free for deterministic CI behaviour.
    """
    for _, name, _ in pkgutil.iter_modules(__path__):
        if not name.startswith("_"):
            importlib.import_module(f"{__name__}.{name}")
    return [cls() for cls in PluginAdapter.__subclasses__()]
```

### `SbomExtractor` opt-in signature
```python
# Default — fully deterministic, no plugins loaded
extractor = AiSbomExtractor()

# Opt-in — loads all installed plugins from xelo/plugins/
extractor = AiSbomExtractor(load_plugins=True)
```

### Contribution path (3 steps)
1. Create `src/xelo/plugins/myframework.py` — subclass `PluginAdapter`.
2. Add `tests/plugins/test_myframework.py` with a fixture snippet.
3. Open a PR — CI handles the rest.

No registry edits. No `__init__` imports to add. Plugins are never loaded unless the caller opts in.

---

## 6. PyPI publishing plan

### 6a. Version and package coordinates

| Item | Value |
|---|---|
| PyPI name | `xelo` (unchanged) |
| Version | `0.2.0` (breaking CLI change warrants minor bump) |
| Python | `>=3.11` (unchanged) |
| Entry points | `xelo = xelo.cli:main` only — `ai-sbom` alias removed immediately |

### 6b. Extras restructure

```toml
[project.optional-dependencies]
llm    = ["litellm>=1.40,<2"]
toolbox = [
    "python-dotenv>=1.0",   # currently missing from requirements
    "httpx>=0.27",          # used by evaluate_streaming
]
all    = ["litellm>=1.40,<2", "python-dotenv>=1.0", "httpx>=0.27"]
dev    = [
    "pytest>=8.0.0",
    "pytest-cov>=5.0.0",
    "ruff>=0.8.0",
    "mypy>=1.10.0",
    "litellm>=1.40,<2",
    "python-dotenv>=1.0",
    "httpx>=0.27",
]
```

**`ts` and `cdx` extras are dropped** — tree-sitter and cyclonedx-bom become hard dependencies (they're already in `dependencies` today; the extras were redundant).

### 6c. `package-data` update

```toml
[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-data]
"xelo" = [
    "py.typed",
    "schemas/*.json",
    "toolbox/policies/*.json",        # built-in policy fixtures — shipped in wheel
    "toolbox/policies_ccd/*.json",    # CCD-format policy fixtures — shipped in wheel
    # ground-truth datasets are NOT bundled — test-only
]
```

### 6d. Build and release workflow (`.github/workflows/publish.yml`)

```yaml
name: Publish to PyPI
on:
  push:
    tags: ["v*"]

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write   # OIDC trusted publishing — no stored API token needed

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install build
      - run: python -m build
      - uses: pypa/gh-action-pypi-publish@release/v1
        # Uses OIDC; configure trusted publisher on PyPI project settings
```

### 6e. Release checklist (per release)

- [ ] Update `version` in `pyproject.toml`
- [ ] Update `docs/CHANGELOG.md`
- [ ] `ruff check src tests && mypy src`
- [ ] `pytest -m "not smoke"` passes
- [ ] `python -m build && twine check dist/*`
- [ ] `git tag v0.2.0 && git push origin v0.2.0`
- [ ] GitHub Actions publishes to PyPI automatically via OIDC

---

## 7. Migration steps (ordered work items)

### Step 1 — Rename package `ai_sbom` → `xelo`
- Rename `src/ai_sbom/` → `src/xelo/`.
- Delete `src/xelo/__init__.py` shim (it only existed to re-export from `ai_sbom`; `xelo` is now the real package).
- Update `pyproject.toml`: `xelo = xelo.cli:main`, `"xelo" = ["py.typed", ...]` in package-data.
- Bulk-replace all `from ai_sbom` / `import ai_sbom` references across `src/`, `tests/`, and `docs/`.
- Update `CLAUDE.md` pythonpath and any `ai_sbom` references.

### Step 2 — Move toolbox code into `src/xelo/toolbox/`
- Move `tests/benchmark/{evaluate,evaluate_risk,evaluate_policies,fetcher,schemas,schemas_risk}.py` → `src/xelo/toolbox/`.
- Move `tests/benchmark/policies/` → `src/xelo/toolbox/policies/` (built-in policy fixtures are part of the library — shipped in the wheel).
- Move `tests/benchmark/policies_ccd/` → `src/xelo/toolbox/policies_ccd/`.
- Move `tests/benchmark/repos/` (ground truth datasets) → `tests/test_toolbox/fixtures/` — test-only, not shipped in the wheel.
- Leave `evaluate_streaming.py` in `tests/` unchanged — not part of the library or CI suite; contributors run it locally only.
- Update all internal imports from `.schemas` / `.fetcher` to `xelo.toolbox.*`.

### Step 3 — Fix missing dependencies
- Add `python-dotenv` and `httpx` to `pyproject.toml` under the `toolbox` extra (they're imported by benchmark code but not declared).
- Remove unused `structlog` dependency if no longer referenced after cleanup.

### Step 4 — Create `plugins/` skeleton
- Add `src/xelo/plugins/__init__.py` and `src/xelo/plugins/base.py`.
- Add `load_plugins: bool = False` parameter to `SbomExtractor.__init__()`; call `plugins.load_plugins()` only when `True`.

### Step 5 — Simplify CLI
- Flatten `scan path` / `scan repo` → `scan <target>` with auto-detection.
- Rename `--enable-llm` → `--llm`.
- Default `--output` to `-` (stdout) for JSON format.
- Add `eval`, `eval-risk`, `eval-policy` subcommands backed by `xelo.toolbox`.
- Remove `ai-sbom` entry-point alias from `pyproject.toml` (no deprecation warning — clean break).

### Step 6 — Consolidate `__init__.py` exports
- Keep `xelo/__init__.py` at 4 core symbols.
- Create `xelo/toolbox/__init__.py` with toolbox SDK symbols.

### Step 7 — Move and reorganise tests
- Create `tests/test_toolbox/` mirroring the new module layout.
- Port `tests/benchmark/tests/` into `tests/test_toolbox/`.
- Move ground truth fixture data to `tests/test_toolbox/fixtures/`.
- Delete `tests/benchmark/` once fully migrated.

### Step 8 — Rename env vars and simplify `config.py`
- Replace all `AISBOM_*` reads in `config.py` with `XELO_*` equivalents (see §10b).
- Delete `_default_llm_model()`, `_default_llm_api_key()`, `_default_llm_api_base()` helper functions and their Azure/Foundry/Kimi routing logic.
- Replace with direct `os.getenv("XELO_LLM_*")` calls in `ExtractionConfig` field defaults.
- Remove all internal confidence/verification tuning env vars (`AISBOM_CONFIDENCE_THRESHOLD`, etc.) from the public env surface — convert to module-level constants.
- Add `.env.example` to repo root.

### Step 9 — Update docs
- Update `CLAUDE.md` commands section for new CLI verbs and `XELO_*` env vars.
- Update `docs/cli-reference.md` with new `scan`, `eval`, `eval-risk`, `eval-policy` docs.
- Update `docs/developer-guide.md` with `from xelo.toolbox import ...` examples and env var table.
- Update `README.md` quickstart.

### Step 10 — Bump version and publish
- Set `version = "0.2.0"` in `pyproject.toml`.
- Add `CHANGELOG.md` entry.
- Configure OIDC trusted publisher on PyPI (`xelo` project → NuGuardAI org → this repo).
- Add `.github/workflows/publish.yml`.
- Tag `v0.2.0`.

---

## 8. What does NOT change

- PyPI distribution name: `xelo`
- Core public SDK symbols: `AiSbomDocument`, `AiSbomConfig`, `AiSbomExtractor`, `AiSbomSerializer`
- Toolbox result class names: `ScanEvaluationResult`, `RiskEvaluationResult`, `PolicyEvaluationResult`
- `AiSbomDocument` schema structure (no breaking model changes in this work)
- `adapters/` internal structure
- Minimum Python version: 3.11
- License: Apache-2.0

**What does change:** the importable package name (`ai_sbom` → `xelo`) and all core class names — both are breaking changes covered by the 0.2.0 version bump.

---

## 9. Decisions

| # | Question | Decision |
|---|---|---|
| 1 | Should `evaluate_streaming.py` (hits a live HTTP service) be part of the package? | **No.** Stays in `tests/` only. Contributors run it locally after cloning and installing dev dependencies. Not shipped in the wheel, not part of CI. |
| 2 | Should ground-truth datasets (`repos/*/ground_truth.json`) be bundled in the wheel? | **No.** All ground-truth data stays in `tests/test_toolbox/fixtures/` (test-only). Callers of `evaluate_repo()` must supply their own `ground_truth_path`. |
| 3 | Drop `ai-sbom` CLI alias or emit a deprecation warning? | **Drop it now.** Clean break. Only `xelo` is registered as an entry point in `pyproject.toml`. |
| 4 | Should plugins load automatically on every `SbomExtractor()` call? | **No.** Explicit opt-in: `SbomExtractor(load_plugins=True)`. Default behaviour stays fully deterministic for CI use. |