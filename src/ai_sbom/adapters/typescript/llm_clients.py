"""Common LLM Clients TypeScript Adapter for Xelo SBOM.

Parsing is performed by ``ai_sbom.core.ts_parser`` (tree-sitter when
available, regex fallback otherwise).

Supports:
- OpenAI SDK (openai)
- Anthropic SDK (@anthropic-ai/sdk)
- Google Generative AI (@google/generative-ai)
- Azure OpenAI
- Cohere, Mistral, Groq, Together AI
"""

from __future__ import annotations

import re
from typing import Any

from ai_sbom.adapters.base import ComponentDetection
from ai_sbom.adapters.typescript._ts_regex import TSFrameworkAdapter
from ai_sbom.core.ts_parser import TSParseResult, parse_typescript
from ai_sbom.normalization import canonicalize_text
from ai_sbom.types import ComponentType


# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------

_PROVIDERS: dict[str, dict[str, list[str]]] = {
    "openai": {
        "packages": ["openai"],
        "classes": ["OpenAI", "AzureOpenAI", "AsyncOpenAI"],
    },
    "anthropic": {
        "packages": ["@anthropic-ai/sdk", "anthropic"],
        "classes": ["Anthropic", "AnthropicClient"],
    },
    "google": {
        "packages": ["@google/generative-ai", "@google/genai", "@google-cloud/vertexai"],
        "classes": ["GoogleGenerativeAI", "GoogleGenAI", "GenerativeModel", "VertexAI"],
    },
    "cohere": {
        "packages": ["cohere-ai", "@cohere-ai/cohere-js"],
        "classes": ["CohereClient", "Cohere"],
    },
    "mistral": {
        "packages": ["@mistralai/mistralai", "mistralai"],
        "classes": ["Mistral", "MistralClient"],
    },
    "groq": {
        "packages": ["groq-sdk", "@groq/groq-sdk"],
        "classes": ["Groq", "GroqClient"],
    },
    "together": {
        "packages": ["together-ai", "@together-ai/together"],
        "classes": ["Together", "TogetherClient"],
    },
}

_ALL_PACKAGES: list[str] = []
_ALL_CLASSES: list[str] = []
_PKG_TO_PROVIDER: dict[str, str] = {}
_CLS_TO_PROVIDER: dict[str, str] = {}

for _prov, _cfg in _PROVIDERS.items():
    for _pkg in _cfg["packages"]:
        _ALL_PACKAGES.append(_pkg)
        _PKG_TO_PROVIDER[_pkg] = _prov
    for _cls in _cfg["classes"]:
        _ALL_CLASSES.append(_cls)
        _CLS_TO_PROVIDER[_cls] = _prov

_MODEL_CARD_URLS: dict[str, str] = {
    "openai": "https://platform.openai.com/docs/models",
    "anthropic": "https://docs.anthropic.com/en/docs/about-claude/models",
    "google": "https://ai.google.dev/gemini-api/docs/models",
    "azure": "https://learn.microsoft.com/azure/ai-services/openai/concepts/models",
    "mistral": "https://docs.mistral.ai/getting-started/models/",
    "cohere": "https://docs.cohere.com/docs/models",
    "groq": "https://console.groq.com/docs/models",
    "together": "https://docs.together.ai/docs/inference-models",
}

_DEFAULT_ENDPOINTS: dict[str, str] = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
    "google": "https://generativelanguage.googleapis.com",
    "cohere": "https://api.cohere.ai",
    "mistral": "https://api.mistral.ai",
    "groq": "https://api.groq.com/openai/v1",
    "together": "https://api.together.xyz",
}

_MODEL_CALL_RE = re.compile(
    r"\b(chat\.completions\.create|completions\.create|messages\.create"
    r"|generateContent|getGenerativeModel|getTextEmbeddingModel)\b"
)


class LLMClientTSAdapter(TSFrameworkAdapter):
    """Detect common LLM SDK client usage in TypeScript/JavaScript files."""

    name = "llm_clients_ts"
    priority = 30
    handles_imports = _ALL_PACKAGES

    def extract(
        self,
        content: str,
        file_path: str,
        parse_result: Any,
    ) -> list[ComponentDetection]:
        result: TSParseResult = (
            parse_result
            if isinstance(parse_result, TSParseResult)
            else parse_typescript(content, file_path)
        )
        if not self._detect(result):
            return []

        detected: list[ComponentDetection] = []

        imported_providers: set[str] = set()
        for imp in result.imports:
            for pkg, prov in _PKG_TO_PROVIDER.items():
                if pkg in imp.module or imp.module == pkg:
                    imported_providers.add(prov)

        # --- Class instantiations: new OpenAI({ model: "..." }) ---
        for inst in result.instantiations:
            provider = _CLS_TO_PROVIDER.get(inst.class_name)
            if provider is None:
                continue
            # resolved_arguments has variable-referenced model names expanded
            model_name = self._resolve(inst, "model", "modelName", "modelId")
            if not model_name:
                continue
            is_azure = "Azure" in inst.class_name or "azure" in str(inst.resolved_arguments).lower()
            effective_provider = "azure" if is_azure else provider
            detected.append(
                ComponentDetection(
                    component_type=ComponentType.MODEL,
                    canonical_name=canonicalize_text(model_name.lower()),
                    display_name=model_name,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.90,
                    metadata={
                        "client_class": inst.class_name,
                        "provider": effective_provider,
                        "is_azure": is_azure,
                        "model_card_url": _MODEL_CARD_URLS.get(effective_provider),
                        "api_endpoint": _DEFAULT_ENDPOINTS.get(effective_provider),
                        "language": "typescript",
                    },
                    file_path=file_path,
                    line=inst.line_start,
                    snippet=inst.source_snippet or "",
                    evidence_kind="ast_instantiation",
                )
            )

        # --- API call patterns: client.chat.completions.create({ model: "gpt-4o" }) ---
        for call in result.function_calls:
            if not _MODEL_CALL_RE.search(call.function_name):
                continue
            model_name = self._resolve(call, "model", "modelId")
            if not model_name and call.positional_args:
                model_name = self._clean(call.positional_args[0])
            if not model_name:
                continue
            fn = call.function_name
            if "messages.create" in fn:
                provider = "anthropic"
            elif "generateContent" in fn or "getGenerativeModel" in fn:
                provider = "google"
            else:
                provider = "openai"
            detected.append(
                ComponentDetection(
                    component_type=ComponentType.MODEL,
                    canonical_name=canonicalize_text(model_name.lower()),
                    display_name=model_name,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.88,
                    metadata={
                        "api_call": fn,
                        "provider": provider,
                        "model_card_url": _MODEL_CARD_URLS.get(provider),
                        "api_endpoint": _DEFAULT_ENDPOINTS.get(provider),
                        "language": "typescript",
                    },
                    file_path=file_path,
                    line=call.line_start,
                    snippet=call.source_snippet or f"{fn}(...)",
                    evidence_kind="ast_call",
                )
            )

        return detected


# Backwards-compatible exports
LLM_CLIENT_TS_PACKAGES = _ALL_PACKAGES
LLM_CLIENT_TS_CLASSES = _ALL_CLASSES
