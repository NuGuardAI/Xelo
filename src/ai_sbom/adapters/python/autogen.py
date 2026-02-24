"""AutoGen framework adapter.

Detects usage of Microsoft AutoGen (``autogen``, ``pyautogen``, ``autogen_agentchat``):
- ``ConversableAgent``, ``AssistantAgent``, ``UserProxyAgent`` → AGENT nodes
- ``GroupChat`` / ``GroupChatManager`` → AGENT (orchestrator) node
- ``llm_config`` dict with ``model`` → MODEL reference
- ``register_function`` / ``register_for_llm`` → TOOL nodes
- System messages / ``system_message`` argument → PROMPT nodes
"""
from __future__ import annotations

from typing import Any

from ai_sbom.adapters.base import ComponentDetection, FrameworkAdapter, RelationshipHint
from ai_sbom.adapters.models_kb import get_model_details, infer_provider
from ai_sbom.normalization import canonicalize_text
from ai_sbom.types import ComponentType

_AGENT_CLASSES = {
    "ConversableAgent",
    "AssistantAgent",
    "UserProxyAgent",
    "GPTAssistantAgent",
    "RetrieveAssistantAgent",
    "RetrieveUserProxyAgent",
    "CompressibleAgent",
    "TransformMessages",
}

_ORCHESTRATOR_CLASSES = {
    "GroupChat",
    "GroupChatManager",
    "RoundRobinGroupChat",
    "SelectorGroupChat",
    "Swarm",
}


class AutoGenAdapter(FrameworkAdapter):
    """Adapter for Microsoft AutoGen multi-agent framework."""

    name = "autogen"
    priority = 30
    handles_imports = ["autogen", "pyautogen", "autogen_agentchat", "autogen_ext",
                        "autogen_core"]

    def extract(
        self,
        content: str,
        file_path: str,
        parse_result: Any,
    ) -> list[ComponentDetection]:
        if parse_result is None:
            return []

        detected: list[ComponentDetection] = [self._framework_node(file_path)]
        agent_canonicals: list[str] = []

        for inst in parse_result.instantiations:
            # --- Agent classes ---
            if inst.class_name in _AGENT_CLASSES:
                args = inst.args or {}
                agent_name = _clean(
                    args.get("name")
                    or (inst.positional_args[0] if inst.positional_args else None)
                    or inst.assigned_to
                    or f"agent_{inst.line}"
                )
                system_msg = _clean(args.get("system_message") or args.get("instructions", ""))
                llm_config = args.get("llm_config")
                rels: list[RelationshipHint] = []
                canon = canonicalize_text(f"autogen:{agent_name}")

                # Extract model from llm_config dict
                model_name = ""
                if isinstance(llm_config, dict):
                    config_list = llm_config.get("config_list")
                    if isinstance(config_list, list) and config_list:
                        model_name = _clean(config_list[0].get("model") if isinstance(config_list[0], dict) else "")
                    if not model_name:
                        model_name = _clean(llm_config.get("model", ""))
                elif isinstance(llm_config, str) and not llm_config.startswith("$"):
                    model_name = llm_config

                if model_name:
                    provider = infer_provider(model_name)
                    model_canon = canonicalize_text(model_name.lower())
                    rels.append(RelationshipHint(
                        source_canonical=canon,
                        source_type=ComponentType.AGENT,
                        target_canonical=model_canon,
                        target_type=ComponentType.MODEL,
                        relationship_type="USES",
                    ))

                meta: dict[str, Any] = {
                    "class_name": inst.class_name,
                    "framework": "autogen",
                }
                if model_name:
                    meta["model"] = model_name
                    details = get_model_details(model_name, infer_provider(model_name))
                    meta.update({k: v for k, v in details.items() if v is not None})
                if system_msg:
                    meta["system_message_preview"] = system_msg[:200]

                detected.append(ComponentDetection(
                    component_type=ComponentType.AGENT,
                    canonical_name=canon,
                    display_name=agent_name,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.90,
                    metadata=meta,
                    file_path=file_path,
                    line=inst.line,
                    snippet=f"{inst.class_name}(name={agent_name!r})",
                    evidence_kind="ast_instantiation",
                    relationships=rels,
                ))
                agent_canonicals.append(canon)

                # System message → PROMPT
                if system_msg and len(system_msg) >= 30:
                    prompt_canon = canonicalize_text(f"autogen:prompt:{inst.line}")
                    detected.append(ComponentDetection(
                        component_type=ComponentType.PROMPT,
                        canonical_name=prompt_canon,
                        display_name=f"system_message_{inst.line}",
                        adapter_name=self.name,
                        priority=self.priority,
                        confidence=0.80,
                        metadata={
                            "role": "system",
                            "content_preview": system_msg[:200],
                            "char_count": len(system_msg),
                        },
                        file_path=file_path,
                        line=inst.line,
                        snippet=system_msg[:80],
                        evidence_kind="ast_instantiation",
                    ))

                # Model node if named
                if model_name:
                    provider = infer_provider(model_name)
                    details = get_model_details(model_name, provider)
                    model_canon = canonicalize_text(model_name.lower())
                    detected.append(ComponentDetection(
                        component_type=ComponentType.MODEL,
                        canonical_name=model_canon,
                        display_name=model_name,
                        adapter_name=self.name,
                        priority=self.priority,
                        confidence=0.88,
                        metadata={
                            "provider": provider,
                            **{k: v for k, v in details.items() if v is not None},
                        },
                        file_path=file_path,
                        line=inst.line,
                        snippet=f"llm_config={{model: {model_name!r}}}",
                        evidence_kind="ast_instantiation",
                    ))

            # --- Orchestrator classes ---
            elif inst.class_name in _ORCHESTRATOR_CLASSES:
                var_name = inst.assigned_to or f"group_{inst.line}"
                canon = canonicalize_text(f"autogen:group:{var_name}")
                agents_arg = inst.args.get("agents", [])
                group_rels: list[RelationshipHint] = []
                if isinstance(agents_arg, list):
                    for agent_ref in agents_arg:
                        if isinstance(agent_ref, str) and agent_ref.startswith("$"):
                            ref_name = agent_ref[1:]
                            ref_canon = canonicalize_text(f"autogen:{ref_name}")
                            group_rels.append(RelationshipHint(
                                source_canonical=canon,
                                source_type=ComponentType.AGENT,
                                target_canonical=ref_canon,
                                target_type=ComponentType.AGENT,
                                relationship_type="CALLS",
                            ))

                detected.append(ComponentDetection(
                    component_type=ComponentType.AGENT,
                    canonical_name=canon,
                    display_name=var_name,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.85,
                    metadata={
                        "orchestrator_type": inst.class_name,
                        "framework": "autogen",
                    },
                    file_path=file_path,
                    line=inst.line,
                    snippet=f"{inst.class_name}(...)",
                    evidence_kind="ast_instantiation",
                    relationships=group_rels,
                ))

        # register_function / register_for_llm → TOOL
        for call in parse_result.function_calls:
            if call.function_name in {"register_function", "register_for_llm",
                                       "register_for_execution"}:
                tool_name = _clean(
                    call.args.get("name")
                    or (call.positional_args[0] if call.positional_args else None)
                    or f"tool_{call.line}"
                )
                tool_canon = canonicalize_text(f"autogen:tool:{tool_name}")
                detected.append(ComponentDetection(
                    component_type=ComponentType.TOOL,
                    canonical_name=tool_canon,
                    display_name=tool_name,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.85,
                    metadata={"framework": "autogen", "registration": call.function_name},
                    file_path=file_path,
                    line=call.line,
                    snippet=f"{call.function_name}(...)",
                    evidence_kind="ast_call",
                ))

        return detected


def _clean(value: Any) -> str:
    if value is None:
        return ""
    s = str(value).strip("'\"` ")
    if s.startswith("$") or s in {"<complex>", "<lambda>", "<dict>", "<list>"}:
        return ""
    return s
