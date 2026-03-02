"""LLM client detection adapter.

Detects direct SDK client instantiations across all major AI providers:
- OpenAI: ``OpenAI()``, ``AsyncOpenAI()``, ``AzureOpenAI()``
- Anthropic: ``Anthropic()``, ``AsyncAnthropic()``
- Google: ``GenerativeModel()``, ``vertexai``
- Mistral, Cohere, Groq, Ollama, Bedrock
- API call patterns: ``client.chat.completions.create(model="...")``
"""
from __future__ import annotations

import re
from typing import Any

from ai_sbom.adapters.base import ComponentDetection, FrameworkAdapter
from ai_sbom.adapters.models_kb import (
    ALL_LLM_CLASSES,
    LANGCHAIN_LLM_CLASS_PROVIDERS,
    LLM_CLIENT_PATTERNS,
    get_model_details,
    infer_provider,
)
from ai_sbom.normalization import canonicalize_text
from ai_sbom.types import ComponentType


# API call patterns that specify a model
_MODEL_SPECIFYING_METHODS = re.compile(
    r"\b(chat\.completions\.create|completions\.create|messages\.create|generate_content)\b"
)

# Classes that are treated as model-specifying (even without explicit model arg)
_MODEL_SPECIFYING_CLASSES = {"GenerativeModel", "ChatModel", "TextGenerationModel"}


class LLMClientsAdapter(FrameworkAdapter):
    """Detect standalone LLM client usage across all major providers."""

    name = "llm_clients"
    priority = 90
    handles_imports = [
        "openai", "anthropic", "google.generativeai", "google.genai",
        "vertexai", "mistralai", "cohere", "groq", "ollama", "boto3",
    ]

    def extract(self, content: str, file_path: str, parse_result: Any) -> list[ComponentDetection]:
        if parse_result is None:
            return []

        detected: list[ComponentDetection] = [self._framework_node(file_path)]
        detected_providers: set[str] = set()

        # Determine which providers are imported
        for imp in parse_result.imports:
            module = imp.module or ""
            for provider, cfg in LLM_CLIENT_PATTERNS.items():
                if any(module == pat or module.startswith(pat + ".") for pat in cfg["imports"]):
                    detected_providers.add(provider)

        # Extract class instantiations
        for inst in parse_result.instantiations:
            # Direct SDK classes (OpenAI, Anthropic, etc.)
            if inst.class_name in ALL_LLM_CLASSES:
                provider = self._resolve_provider(inst.class_name, detected_providers,
                                                  parse_result)
                is_azure = "Azure" in inst.class_name
                args = inst.args or {}

                model_name = self._clean_str(
                    args.get("model")
                    or args.get("model_name")
                    or args.get("embedding_model")
                    or (args.get("model_name") if inst.class_name in _MODEL_SPECIFYING_CLASSES else None)
                )

                # Skip bare client objects without an explicit model
                if not model_name and inst.class_name not in _MODEL_SPECIFYING_CLASSES:
                    continue

                display = model_name or f"{provider}_client"
                details = get_model_details(display, "azure" if is_azure else provider, args)

                meta: dict[str, Any] = {
                    "client_class": inst.class_name,
                    "provider": "azure" if is_azure else provider,
                    "is_async": inst.class_name.startswith("Async"),
                    **{k: v for k, v in details.items() if v is not None},
                }
                if is_azure:
                    depl = self._clean_str(
                        args.get("azure_deployment") or args.get("deployment_name")
                    )
                    if depl:
                        meta["deployment_name"] = depl

                detected.append(ComponentDetection(
                    component_type=ComponentType.MODEL,
                    canonical_name=canonicalize_text(display.lower()),
                    display_name=display,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.90,
                    metadata=meta,
                    file_path=file_path,
                    line=inst.line,
                    snippet=f"{inst.class_name}(...)",
                    evidence_kind="ast_instantiation",
                ))

            # LangChain wrappers (ChatOpenAI, ChatAnthropic, etc.)
            elif inst.class_name in LANGCHAIN_LLM_CLASS_PROVIDERS:
                provider = LANGCHAIN_LLM_CLASS_PROVIDERS[inst.class_name]
                args = inst.args or {}
                model_name = self._clean_str(
                    args.get("model") or args.get("model_name")
                    or args.get("embedding_model") or args.get("deployment_name")
                ) or inst.class_name
                details = get_model_details(model_name, provider, args)

                detected.append(ComponentDetection(
                    component_type=ComponentType.MODEL,
                    canonical_name=canonicalize_text(model_name.lower()),
                    display_name=model_name,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.90,
                    metadata={
                        "class_name": inst.class_name,
                        "provider": provider,
                        **{k: v for k, v in details.items() if v is not None},
                    },
                    file_path=file_path,
                    line=inst.line,
                    snippet=f"{inst.class_name}(...)",
                    evidence_kind="ast_instantiation",
                ))

        # Extract API call patterns (client.chat.completions.create(model="gpt-4o"))
        for call in parse_result.function_calls:
            func = call.function_name or ""
            args = call.args or {}
            # Determine if this is a model-specifying call
            is_model_call = (
                "create" in func or "generate" in func
                or (call.receiver or "").lower() == "ollama"
            )
            if not is_model_call:
                continue

            model_name = self._clean_str(args.get("model") or args.get("model_name"))
            if not model_name:
                # Check positional args for model strings
                for pa in call.positional_args:
                    if isinstance(pa, str) and not pa.startswith("$"):
                        model_name = pa.strip("'\"")
                        break
            if not model_name:
                continue

            provider = (
                "ollama" if (call.receiver or "").lower() == "ollama"
                else infer_provider(model_name)
            )
            if provider == "unknown" and detected_providers:
                provider = sorted(detected_providers)[0]

            details = get_model_details(model_name, provider, {})

            detected.append(ComponentDetection(
                component_type=ComponentType.MODEL,
                canonical_name=canonicalize_text(model_name.lower()),
                display_name=model_name,
                adapter_name=self.name,
                priority=self.priority,
                confidence=0.95,
                metadata={
                    "source": "api_call",
                    "api_method": func,
                    "provider": provider,
                    **{k: v for k, v in details.items() if v is not None},
                },
                file_path=file_path,
                line=call.line,
                snippet=f"{func}(model={model_name!r})",
                evidence_kind="ast_call",
            ))

        return detected

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _clean_str(value: Any) -> str:
        if value is None:
            return ""
        s = str(value).strip("'\"` ")
        if s.startswith("$") or s in {"<complex>", "<lambda>", "<dict>", "<list>"}:
            return ""
        return s

    @staticmethod
    def _resolve_provider(class_name: str, detected: set[str], parse_result: Any) -> str:
        from ai_sbom.adapters.models_kb import _CLASS_TO_PROVIDERS
        candidates = _CLASS_TO_PROVIDERS.get(class_name, [])
        if not candidates:
            return "unknown"
        if len(candidates) == 1:
            return candidates[0]
        # Use import context to narrow down
        imported = {imp.module for imp in parse_result.imports}
        for cand in candidates:
            patterns = LLM_CLIENT_PATTERNS.get(cand, {}).get("imports", [])
            if any(any(imp == p or imp.startswith(p + ".") for p in patterns) for imp in imported):
                return cand
        for cand in candidates:
            if cand in detected:
                return cand
        return candidates[0]
