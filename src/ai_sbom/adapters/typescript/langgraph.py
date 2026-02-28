"""LangChain.js / LangGraph.js TypeScript Adapter for Xelo SBOM.

Parsing is performed by ``ai_sbom.core.ts_parser`` (tree-sitter when
available, regex fallback otherwise).

Supports:
- StateGraph, MessageGraph construction
- .addNode() graph node registration
- ChatOpenAI, ChatAnthropic, ChatGoogleGenerativeAI LLM wrappers
- ToolNode detection
- PromptTemplate, ChatPromptTemplate
"""

from __future__ import annotations

from typing import Any

from ai_sbom.adapters.base import ComponentDetection, RelationshipHint
from ai_sbom.adapters.typescript._ts_regex import TSFrameworkAdapter
from ai_sbom.core.ts_parser import TSParseResult, parse_typescript
from ai_sbom.normalization import canonicalize_text
from ai_sbom.types import ComponentType


_LANGCHAIN_PACKAGES = [
    "@langchain/langgraph",
    "@langchain/core",
    "@langchain/openai",
    "@langchain/anthropic",
    "@langchain/google-genai",
    "@langchain/community",
    "langchain",
]

_GRAPH_CLASSES = {"StateGraph", "MessageGraph", "Graph"}

_LLM_CLASSES: dict[str, str] = {
    "ChatOpenAI": "openai",
    "AzureChatOpenAI": "azure",
    "ChatAnthropic": "anthropic",
    "ChatGoogleGenerativeAI": "google",
    "ChatVertexAI": "google",
    "ChatOllama": "ollama",
    "ChatMistralAI": "mistral",
    "ChatCohere": "cohere",
    "ChatGroq": "groq",
}

_PROMPT_CLASSES = {
    "PromptTemplate",
    "ChatPromptTemplate",
    "SystemMessagePromptTemplate",
    "HumanMessagePromptTemplate",
    "FewShotPromptTemplate",
}


class LangGraphTSAdapter(TSFrameworkAdapter):
    """Detect LangGraph.js / LangChain.js assets in TypeScript/JavaScript files."""

    name = "langgraph_ts"
    priority = 15
    handles_imports = _LANGCHAIN_PACKAGES

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

        source = result.source or content
        detected: list[ComponentDetection] = [self._fw_node(file_path)]
        graph_canonicals: list[str] = []

        # --- Graph classes → AGENT nodes ---
        for inst in result.instantiations:
            if inst.class_name not in _GRAPH_CLASSES:
                continue
            var = self._assignment_name(source, inst.line_start) or f"langgraph_{inst.line_start}"
            canon = canonicalize_text(var)
            graph_canonicals.append(canon)
            detected.append(
                ComponentDetection(
                    component_type=ComponentType.AGENT,
                    canonical_name=canon,
                    display_name=var,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.90,
                    metadata={
                        "framework": "langgraph-js",
                        "graph_class": inst.class_name,
                        "language": "typescript",
                    },
                    file_path=file_path,
                    line=inst.line_start,
                    snippet=inst.source_snippet or "",
                    evidence_kind="ast_instantiation",
                )
            )

        # --- addNode() calls → graph node registrations ---
        for call in result.function_calls:
            if call.function_name != "addNode" and call.method_name != "addNode":
                continue
            node_name = call.positional_args[0] if call.positional_args else None
            node_name = self._clean(node_name) if node_name else ""
            if not node_name:
                continue
            canon = canonicalize_text(node_name)
            detected.append(
                ComponentDetection(
                    component_type=ComponentType.AGENT,
                    canonical_name=canon,
                    display_name=node_name,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.85,
                    metadata={
                        "framework": "langgraph-js",
                        "is_graph_node": True,
                        "language": "typescript",
                    },
                    file_path=file_path,
                    line=call.line_start,
                    snippet=f"addNode({node_name!r})",
                    evidence_kind="ast_call",
                )
            )

        # --- LLM wrapper classes → MODEL nodes ---
        for inst in result.instantiations:
            provider = _LLM_CLASSES.get(inst.class_name)
            if provider is None:
                continue
            # resolved_arguments has variable references expanded by the symbol table
            model_name = self._resolve(inst, "model", "modelName") or inst.class_name
            canon = canonicalize_text(model_name.lower())
            rels: list[RelationshipHint] = [
                RelationshipHint(
                    source_canonical=gc,
                    source_type=ComponentType.AGENT,
                    target_canonical=canon,
                    target_type=ComponentType.MODEL,
                    relationship_type="USES",
                )
                for gc in graph_canonicals
            ]
            detected.append(
                ComponentDetection(
                    component_type=ComponentType.MODEL,
                    canonical_name=canon,
                    display_name=model_name,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.85,
                    metadata={
                        "framework": "langchain-js",
                        "client_class": inst.class_name,
                        "provider": "azure" if "Azure" in inst.class_name else provider,
                        "language": "typescript",
                    },
                    file_path=file_path,
                    line=inst.line_start,
                    snippet=inst.source_snippet or "",
                    evidence_kind="ast_instantiation",
                    relationships=rels,
                )
            )

        # --- ToolNode → TOOL node ---
        for inst in result.instantiations:
            if inst.class_name != "ToolNode":
                continue
            detected.append(
                ComponentDetection(
                    component_type=ComponentType.TOOL,
                    canonical_name="toolnode",
                    display_name="ToolNode",
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.85,
                    metadata={"framework": "langgraph-js", "language": "typescript"},
                    file_path=file_path,
                    line=inst.line_start,
                    snippet=inst.source_snippet or "",
                    evidence_kind="ast_instantiation",
                )
            )

        # --- PromptTemplate instantiations → PROMPT nodes ---
        for inst in result.instantiations:
            if inst.class_name not in _PROMPT_CLASSES:
                continue
            template = self._resolve(inst, "template", "0") or ""
            name = template[:60] if len(template) > 10 else inst.class_name
            canon = canonicalize_text(name.lower())
            detected.append(
                ComponentDetection(
                    component_type=ComponentType.PROMPT,
                    canonical_name=canon,
                    display_name=name,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.80,
                    metadata={
                        "framework": "langchain-js",
                        "prompt_class": inst.class_name,
                        "language": "typescript",
                    },
                    file_path=file_path,
                    line=inst.line_start,
                    snippet=inst.source_snippet or "",
                    evidence_kind="ast_instantiation",
                )
            )

        return detected


# Export alias
LangChainTSAdapter = LangGraphTSAdapter
