from __future__ import annotations

import re
from dataclasses import dataclass

from ai_sbom.adapters.base import DetectionAdapter, FrameworkAdapter, RegexAdapter
from ai_sbom.adapters.frameworks import builtin_framework_specs
from ai_sbom.normalization import canonicalize_text
from ai_sbom.types import ComponentType


@dataclass(frozen=True)
class IntakeCandidate:
    adapter_name: str
    source_path: str
    status: str
    priority: int


def intake_candidates() -> tuple[IntakeCandidate, ...]:
    candidates: list[IntakeCandidate] = []
    for spec in builtin_framework_specs():
        candidates.append(
            IntakeCandidate(
                adapter_name=spec.adapter_name,
                source_path=f"ai_sbom.adapters.frameworks:{spec.adapter_name}",
                status=spec.status,
                priority=spec.priority,
            )
        )
    return tuple(candidates)


def default_framework_adapters() -> tuple[FrameworkAdapter, ...]:
    """Return all AST-aware framework adapters in priority order.

    Includes both Python adapters (run against ``.py`` and ``.ipynb`` files)
    and TypeScript adapters (run against ``.ts``, ``.tsx``, ``.js``, ``.jsx``
    files).
    """
    from ai_sbom.adapters.data_classification import DataClassificationPythonAdapter
    from ai_sbom.adapters.python import (
        AgnoAdapter,
        AutoGenAdapter,
        AzureAIAgentsAdapter,
        BedrockAgentCoreAdapter,
        CrewAIAdapter,
        GoogleADKPythonAdapter,
        GuardrailsAIAdapter,
        LangGraphAdapter,
        LlamaIndexAdapter,
        LLMClientsAdapter,
        MCPServerAdapter,
        OpenAIAgentsAdapter,
        SemanticKernelAdapter,
    )
    from ai_sbom.adapters.typescript import (
        AgnoTSAdapter,
        AzureAIAgentsTSAdapter,
        BedrockAgentsTSAdapter,
        DatastoreTSAdapter,
        GoogleADKAdapter,
        LangGraphTSAdapter,
        LLMClientTSAdapter,
        OpenAIAgentsTSAdapter,
        PromptTSAdapter,
    )

    adapters: list[FrameworkAdapter] = [
        # Data classification (Python models — Pydantic, SQLAlchemy, dataclasses)
        DataClassificationPythonAdapter(),
        # Python AI framework adapters
        LangGraphAdapter(),
        OpenAIAgentsAdapter(),
        AutoGenAdapter(),
        GuardrailsAIAdapter(),
        SemanticKernelAdapter(),
        CrewAIAdapter(),
        LlamaIndexAdapter(),
        LLMClientsAdapter(),
        AgnoAdapter(),
        AzureAIAgentsAdapter(),
        BedrockAgentCoreAdapter(),
        GoogleADKPythonAdapter(),
        MCPServerAdapter(),
        # TypeScript / JavaScript adapters
        LangGraphTSAdapter(),
        OpenAIAgentsTSAdapter(),
        GoogleADKAdapter(),
        LLMClientTSAdapter(),
        BedrockAgentsTSAdapter(),
        DatastoreTSAdapter(),
        PromptTSAdapter(),
        AgnoTSAdapter(),
        AzureAIAgentsTSAdapter(),
    ]
    return tuple(sorted(adapters, key=lambda a: (a.priority, canonicalize_text(a.name))))


def default_registry() -> tuple[DetectionAdapter, ...]:
    """Return regex-based adapters: framework detectors + generic component detectors.

    Framework detectors (from ``builtin_framework_adapters``) run on all file
    types and serve as a lightweight fallback for non-Python files (YAML, Terraform,
    Dockerfiles, etc.) and as a text-based signal for Python comments/configs.
    """
    from ai_sbom.adapters.frameworks import builtin_framework_adapters

    adapters: list[DetectionAdapter] = list(builtin_framework_adapters())

    # Baseline generic component detectors (used as fallback for non-Python files)
    adapters.extend(
        [
            RegexAdapter(
                name="model_generic",
                component_type=ComponentType.MODEL,
                priority=110,
                patterns=(
                    re.compile(
                        # Match model name strings, not library names.
                        # - llama requires a dash+digit prefix to avoid matching llama_index.
                        # - o-series (o1, o3, o4 …) require a word boundary or letter-only
                        #   suffix to avoid matching hex strings like o37qlnifitdp.
                        r"\b(gpt-[\d][\w.-]*|claude-[\d][\w.-]*|gemini-[\d][\w.]*|"
                        r"llama-[\d][\w.-]*|mistral-[\w.-]+|o\d(?:-[a-z][a-z0-9-]*)?\b)\b",
                        re.IGNORECASE,
                    ),
                ),
                metadata={"normalizer": "model-name"},
            ),
            RegexAdapter(
                name="datastore_generic",
                component_type=ComponentType.DATASTORE,
                priority=130,
                patterns=(
                    re.compile(
                        r"\b(postgres|mysql|mongodb|redis|pinecone|faiss|chroma|weaviate|qdrant|milvus)\b",
                        re.IGNORECASE,
                    ),
                ),
                metadata={"normalizer": "datastore"},
            ),
            RegexAdapter(
                name="auth_generic",
                component_type=ComponentType.AUTH,
                priority=140,
                patterns=(
                    # Auth scheme identifiers — short, unambiguous
                    re.compile(r"\b(jwt|oauth2?|apikey|api_key|bearer)\b", re.IGNORECASE),
                    # Full authentication/authorization words — avoids gcloud auth, auth@v2, etc.
                    re.compile(r"\bauth(?:entication|orization|enticate|orize)\b", re.IGNORECASE),
                    # Compound token forms — avoids bare CI token vars like token=$TOKEN
                    re.compile(r"\b(?:access|refresh|api|auth|id)_token\b", re.IGNORECASE),
                ),
                canonical_name="auth:generic",
            ),
            RegexAdapter(
                name="privilege_generic",
                component_type=ComponentType.PRIVILEGE,
                priority=150,
                patterns=(
                    re.compile(
                        r"\b(rbac|least[_ ]privilege|privilege[_ ]escalation|access[_ ]control|role[_.]based)\b",
                        re.IGNORECASE,
                    ),
                ),
                canonical_name="privilege:generic",
            ),
            RegexAdapter(
                name="api_endpoint_generic",
                component_type=ComponentType.API_ENDPOINT,
                priority=160,
                patterns=(
                    re.compile(r"\b(GET|POST|PUT|DELETE|PATCH)\s+/[\w/{}:-]+"),
                    re.compile(r"@(app|router)\.(get|post|put|delete|patch)\(", re.IGNORECASE),
                ),
                canonical_name="api_endpoint:generic",
            ),
            RegexAdapter(
                name="deployment_generic",
                component_type=ComponentType.DEPLOYMENT,
                priority=170,
                patterns=(
                    re.compile(
                        r"\b(docker|kubernetes|helm|terraform|compose|deployment)\b", re.IGNORECASE
                    ),
                ),
                canonical_name="deployment:generic",
            ),
            RegexAdapter(
                name="prompt_generic",
                component_type=ComponentType.PROMPT,
                priority=180,
                patterns=(
                    re.compile(
                        r"\b(system[_ ]prompt|prompt[_ ]template"
                        r"|few[_. ]shot|chain[_. ]of[_. ]thought|prompt[_ ]injection)\b",
                        re.IGNORECASE,
                    ),
                ),
                canonical_name="prompt:generic",
            ),
        ]
    )

    return tuple(
        sorted(adapters, key=lambda adapter: (adapter.priority, canonicalize_text(adapter.name)))
    )
