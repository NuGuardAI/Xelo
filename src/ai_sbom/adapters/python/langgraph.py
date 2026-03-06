"""LangGraph framework adapter.

Extracts AI assets from LangGraph-based applications:
- ``StateGraph`` / ``MessageGraph`` instantiation → AGENT nodes
- ``.add_node()`` calls → AGENT nodes
- ``.add_edge()`` / ``.add_conditional_edges()`` → graph AGENT-INVOKES-AGENT hints
- ``ToolNode`` → TOOL nodes
- ``ChatOpenAI``, ``ChatAnthropic``, etc. → MODEL nodes (via models_kb)
- ``create_react_agent`` / factory functions → AGENT nodes
- ``SystemMessage`` / string literals → PROMPT nodes
"""

from __future__ import annotations

import re
from typing import Any

from ai_sbom.adapters.base import ComponentDetection, FrameworkAdapter, RelationshipHint
from ai_sbom.adapters.models_kb import (
    LANGCHAIN_LLM_CLASS_PROVIDERS,
    get_model_details,
)
from ai_sbom.normalization import canonicalize_text
from ai_sbom.types import ComponentType

# ---------------------------------------------------------------------------
# LangGraph-specific constants
# ---------------------------------------------------------------------------

_LANGGRAPH_IMPORTS = [
    "langgraph",
    "langgraph.graph",
    "langgraph.prebuilt",
    "langchain",
    "langchain_core",
    "langchain_openai",
    "langchain_anthropic",
    "langchain_community",
]

_STATEGRAPH_CLASSES = {"StateGraph", "MessageGraph", "Graph"}

_TOOLNODE_CLASSES = {"ToolNode"}

_AGENT_FACTORY_FUNCTIONS = {
    "create_react_agent",
    "create_tool_calling_agent",
    "create_openai_functions_agent",
    "create_openai_tools_agent",
    "create_structured_chat_agent",
}

_PROMPT_CLASSES = {
    "SystemMessage",
    "HumanMessagePromptTemplate",
    "AIMessagePromptTemplate",
    "ChatPromptTemplate",
    "PromptTemplate",
}

_TEMPLATE_VAR_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")

# Graph-internal node names that should never be emitted as AGENT nodes
_LANGGRAPH_INTERNAL_NODES = {"__start__", "__end__", "tools", "END", "START"}


class LangGraphAdapter(FrameworkAdapter):
    """Adapter for LangGraph / LangChain framework detection."""

    name = "langgraph"
    priority = 10
    handles_imports = _LANGGRAPH_IMPORTS

    def extract(
        self,
        content: str,
        file_path: str,
        parse_result: Any,
    ) -> list[ComponentDetection]:
        if parse_result is None:
            return []

        # Determine if langgraph is actually imported (vs just langchain)
        imported_modules = {imp.module or "" for imp in parse_result.imports}
        has_langgraph = any(
            m == "langgraph" or m.startswith("langgraph.") for m in imported_modules
        )
        # Emit the correct framework node
        if has_langgraph:
            framework_det = self._framework_node(file_path)
        else:
            # Only langchain imported — emit framework:langchain, not framework:langgraph
            from ai_sbom.types import ComponentType as _CT

            framework_det = ComponentDetection(
                component_type=_CT.FRAMEWORK,
                canonical_name="framework:langchain",
                display_name="framework:langchain",
                adapter_name=self.name,
                priority=self.priority,
                confidence=0.95,
                metadata={"framework": "langchain"},
                file_path=file_path,
                line=0,
                snippet="import langchain",
                evidence_kind="ast_import",
            )
        detected: list[ComponentDetection] = [framework_det]

        # Track node canonical names for relationship building
        agent_canonicals: list[str] = []
        model_canonicals: list[str] = []
        tool_canonicals: list[str] = []
        node_name_map: dict[str, str] = {}  # node_name → canonical_name

        # 1. .add_node() calls → AGENT (graph nodes)
        for call in parse_result.function_calls:
            if call.function_name != "add_node":
                continue
            node_name = None
            if call.positional_args:
                first = call.positional_args[0]
                if isinstance(first, str) and not first.startswith("$"):
                    node_name = first.strip("'\"")
            if not node_name:
                node_name = _clean(call.args.get("node") or call.args.get("name"))
            if not node_name or node_name in _LANGGRAPH_INTERNAL_NODES:
                continue
            canon = canonicalize_text(f"langgraph:{node_name}")
            det = ComponentDetection(
                component_type=ComponentType.AGENT,
                canonical_name=canon,
                display_name=node_name,
                adapter_name=self.name,
                priority=self.priority,
                confidence=0.85,
                metadata={"registration_method": "add_node", "framework": "langgraph"},
                file_path=file_path,
                line=call.line,
                snippet=f"add_node({node_name!r}, ...)",
                evidence_kind="ast_call",
            )
            detected.append(det)
            agent_canonicals.append(canon)
            node_name_map[node_name] = canon

        # 3. .add_edge() / .add_conditional_edges() → RelationshipHints
        for call in parse_result.function_calls:
            if call.function_name == "add_edge":
                src = _positional_str(call, 0) or _clean(call.args.get("source"))
                tgt = _positional_str(call, 1) or _clean(call.args.get("target"))
                if src and tgt:
                    src_canon = node_name_map.get(src, canonicalize_text(f"langgraph:{src}"))
                    tgt_canon = node_name_map.get(tgt, canonicalize_text(f"langgraph:{tgt}"))
                    # Attach as relationship hints on the first agent node
                    if detected:
                        detected[-1].relationships.append(
                            RelationshipHint(
                                source_canonical=src_canon,
                                source_type=ComponentType.AGENT,
                                target_canonical=tgt_canon,
                                target_type=ComponentType.AGENT,
                                relationship_type="CALLS",
                            )
                        )

        # 4. ToolNode instantiations → TOOL
        for inst in parse_result.instantiations:
            if inst.class_name in _TOOLNODE_CLASSES:
                var_name = inst.assigned_to or f"tools_{inst.line}"
                canon = canonicalize_text(f"langgraph:toolnode:{var_name}")
                det = ComponentDetection(
                    component_type=ComponentType.TOOL,
                    canonical_name=canon,
                    display_name=var_name,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.85,
                    metadata={"tool_type": "ToolNode", "framework": "langgraph"},
                    file_path=file_path,
                    line=inst.line,
                    snippet=f"{inst.class_name}(...)",
                    evidence_kind="ast_instantiation",
                )
                detected.append(det)
                tool_canonicals.append(canon)

        # 5. LangChain LLM wrapper instantiations → MODEL
        for inst in parse_result.instantiations:
            if inst.class_name not in LANGCHAIN_LLM_CLASS_PROVIDERS:
                continue
            provider = LANGCHAIN_LLM_CLASS_PROVIDERS[inst.class_name]
            args = inst.args or {}
            model_name = (
                _clean(
                    args.get("model")
                    or args.get("model_name")
                    or args.get("model_id")  # LangChain Bedrock uses model_id=
                    or args.get("deployment_name")
                )
                or inst.class_name
            )
            details = get_model_details(model_name, provider, args)
            canon = canonicalize_text(model_name.lower())

            rels: list[RelationshipHint] = []
            for agent_canon in agent_canonicals:
                rels.append(
                    RelationshipHint(
                        source_canonical=agent_canon,
                        source_type=ComponentType.AGENT,
                        target_canonical=canon,
                        target_type=ComponentType.MODEL,
                        relationship_type="USES",
                    )
                )

            det = ComponentDetection(
                component_type=ComponentType.MODEL,
                canonical_name=canon,
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
                relationships=rels,
            )
            detected.append(det)
            model_canonicals.append(canon)

        # 6. Agent factory functions (create_react_agent, etc.)
        for call in parse_result.function_calls:
            if call.function_name not in _AGENT_FACTORY_FUNCTIONS:
                continue
            agent_name = call.assigned_to or call.function_name
            canon = canonicalize_text(f"langgraph:{agent_name}")
            factory_rels: list[RelationshipHint] = []

            # First positional arg → LLM reference
            if call.positional_args:
                llm_ref = call.positional_args[0]
                if isinstance(llm_ref, str) and not llm_ref.startswith("$"):
                    model_canon = canonicalize_text(f"langchain:{llm_ref}")
                    factory_rels.append(
                        RelationshipHint(
                            source_canonical=canon,
                            source_type=ComponentType.AGENT,
                            target_canonical=model_canon,
                            target_type=ComponentType.MODEL,
                            relationship_type="USES",
                        )
                    )

            # Second positional arg → tools list
            if len(call.positional_args) >= 2:
                tools_ref = call.positional_args[1]
                if isinstance(tools_ref, list):
                    for tool_name in tools_ref:
                        if isinstance(tool_name, str) and not tool_name.startswith("$"):
                            tool_canon = canonicalize_text(f"langchain:tool:{tool_name}")
                            factory_rels.append(
                                RelationshipHint(
                                    source_canonical=canon,
                                    source_type=ComponentType.AGENT,
                                    target_canonical=tool_canon,
                                    target_type=ComponentType.TOOL,
                                    relationship_type="CALLS",
                                )
                            )

            detected.append(
                ComponentDetection(
                    component_type=ComponentType.AGENT,
                    canonical_name=canon,
                    display_name=agent_name,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.90,
                    metadata={
                        "factory_function": call.function_name,
                        "is_agent_graph": True,
                        "framework": "langchain",
                    },
                    file_path=file_path,
                    line=call.line,
                    snippet=f"{call.function_name}(...)",
                    evidence_kind="ast_call",
                    relationships=factory_rels,
                )
            )

        # 7. Prompt detection (SystemMessage, ChatPromptTemplate, large string literals)
        for inst in parse_result.instantiations:
            if inst.class_name not in _PROMPT_CLASSES:
                continue
            content_val = _clean(
                inst.args.get("content")
                or (inst.positional_args[0] if inst.positional_args else None)
            )
            if not content_val or len(content_val) < 40:
                continue
            role = _detect_role(inst.class_name)
            template_vars = _TEMPLATE_VAR_RE.findall(content_val)
            dname = _prompt_display_name(
                content_val, inst.assigned_to or inst.class_name, inst.line
            )
            canon = canonicalize_text(f"langchain:prompt:{inst.line}")
            detected.append(
                ComponentDetection(
                    component_type=ComponentType.PROMPT,
                    canonical_name=canon,
                    display_name=dname,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.80,
                    metadata={
                        "message_type": inst.class_name,
                        "role": role,
                        "content_preview": content_val[:500],
                        "content": content_val,
                        "char_count": len(content_val),
                        "is_template": bool(template_vars),
                        "template_variables": template_vars,
                    },
                    file_path=file_path,
                    line=inst.line,
                    snippet=f"{inst.class_name}(content=...)",
                    evidence_kind="ast_instantiation",
                )
            )

        # Large string literals that look like prompts
        for lit in parse_result.string_literals:
            if lit.is_docstring or len(lit.value) < 200:
                continue
            if not _is_prompt_literal(lit.value, lit.context or ""):
                continue
            template_vars = _TEMPLATE_VAR_RE.findall(lit.value)
            dname = _prompt_display_name(lit.value, lit.context or "", lit.line)
            canon = canonicalize_text(f"langchain:prompt:str:{lit.line}")
            detected.append(
                ComponentDetection(
                    component_type=ComponentType.PROMPT,
                    canonical_name=canon,
                    display_name=dname,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.60,
                    metadata={
                        "role": _detect_role_from_content(lit.value),
                        "content_preview": lit.value[:500],
                        "content": lit.value,
                        "char_count": len(lit.value),
                        "is_template": bool(template_vars),
                        "template_variables": template_vars,
                    },
                    file_path=file_path,
                    line=lit.line,
                    snippet=lit.value[:80] + ("..." if len(lit.value) > 80 else ""),
                    evidence_kind="ast_call",
                )
            )

        return detected


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clean(value: Any) -> str:
    if value is None:
        return ""
    s = str(value).strip("'\"` ")
    if s.startswith("$") or s in {"<complex>", "<lambda>", "<dict>", "<list>"}:
        return ""
    return s


def _positional_str(call: Any, idx: int) -> str:
    if call.positional_args and len(call.positional_args) > idx:
        v = call.positional_args[idx]
        if isinstance(v, str) and not v.startswith("$"):
            return v.strip("'\"")
    return ""


def _infer_var_from_source(source: str, line: int) -> str | None:
    lines = source.splitlines()
    if 1 <= line <= len(lines):
        m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", lines[line - 1])
        if m:
            return m.group(1)
    return None


def _prompt_display_name(content: str, context: str, line: int) -> str:
    """Derive a human-readable name for a detected prompt."""
    ctx = context.strip()
    if ctx:
        # Split camelCase/PascalCase into words before lowercasing
        ctx_words = re.sub(r"([a-z])([A-Z])", r"\1_\2", ctx)
        slug = re.sub(r"[^a-z0-9_]", "_", ctx_words.lower()).strip("_")
        if slug and slug not in {"prompt", "template", "message", "content", "text", "str"}:
            return slug.replace("_", " ").title()
    cl = content.lower()[:400]
    if re.search(r"\byou are\s", cl):
        return "System Prompt"
    if any(k in cl for k in ["answer the question", "given the context"]):
        return "RAG Prompt"
    if any(k in cl for k in ["example:", "input:", "output:"]):
        return "Few Shot Prompt"
    if "summarize" in cl:
        return "Summarize Prompt"
    if "translate" in cl:
        return "Translate Prompt"
    return f"Prompt {line}"


def _detect_role(class_name: str) -> str | None:
    if "System" in class_name:
        return "system"
    if "Human" in class_name:
        return "user"
    if "AI" in class_name:
        return "assistant"
    return None


def _detect_role_from_content(text: str) -> str | None:
    tl = text.lower()
    markers = {
        "system": ["system:", "you are", "as an ai", "your role"],
        "user": ["user:", "human:", "question:"],
        "assistant": ["assistant:", "ai:"],
    }
    for role, tokens in markers.items():
        if any(t in tl for t in tokens):
            return role
    return None


def _is_prompt_literal(text: str, context: str) -> bool:
    tl = text.lower()
    ctx = context.lower()
    # Tier 1 — explicit role markers in content (high confidence, no context needed)
    if any(m in tl for m in ["system:", "user:", "assistant:", "you are a ", "your task is"]):
        return True
    # Tier 2 — prompt-building context + template variables + length
    prompt_ctx = any(h in ctx for h in ["prompt", "system", "template"])
    non_prompt_ctx = any(
        h in ctx
        for h in [
            "description",
            "summary",
            "readme",
            "license",
            "doc",
            "log",
            "error",
        ]
    )
    if non_prompt_ctx:
        return False
    template_vars = _TEMPLATE_VAR_RE.findall(text)
    return prompt_ctx and bool(template_vars) and len(text) > 120
