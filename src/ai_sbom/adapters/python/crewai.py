"""CrewAI framework adapter.

Detects usage of the ``crewai`` library:
- ``Agent(role=..., goal=..., backstory=...)`` → AGENT nodes
- ``Task(description=..., agent=...)`` → TOOL nodes (task-as-tool pattern)
- ``Crew(agents=[...], tasks=[...])`` → orchestrator AGENT node
- ``llm`` / ``llm_config`` arguments → MODEL references
- ``tools=[...]`` argument → TOOL references
"""
from __future__ import annotations

from typing import Any

from ai_sbom.adapters.base import ComponentDetection, FrameworkAdapter, RelationshipHint
from ai_sbom.adapters.models_kb import get_model_details, infer_provider
from ai_sbom.normalization import canonicalize_text
from ai_sbom.types import ComponentType


class CrewAIAdapter(FrameworkAdapter):
    """Adapter for the CrewAI multi-agent framework."""

    name = "crewai"
    priority = 50
    handles_imports = ["crewai", "crewai.agent", "crewai.task", "crewai.crew",
                        "crewai.tools", "crewai_tools"]

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
        task_canonicals: list[str] = []

        for inst in parse_result.instantiations:
            # ---- Agent ----
            if inst.class_name == "Agent":
                args = inst.args or {}
                role = _clean(args.get("role") or (inst.positional_args[0] if inst.positional_args else None))
                agent_name = _clean(args.get("name") or inst.assigned_to) or role or f"agent_{inst.line}"
                goal = _clean(args.get("goal", ""))
                backstory = _clean(args.get("backstory", ""))
                llm_ref = _clean(args.get("llm") or args.get("llm_config"))
                tools_raw = args.get("tools", [])

                canon = canonicalize_text(f"crewai:{agent_name}")
                rels: list[RelationshipHint] = []

                # Model reference from llm argument
                if llm_ref:
                    provider = infer_provider(llm_ref)
                    model_canon = canonicalize_text(llm_ref.lower())
                    rels.append(RelationshipHint(
                        source_canonical=canon,
                        source_type=ComponentType.AGENT,
                        target_canonical=model_canon,
                        target_type=ComponentType.MODEL,
                        relationship_type="USES",
                    ))
                    # Emit model node
                    details = get_model_details(llm_ref, provider)
                    detected.append(ComponentDetection(
                        component_type=ComponentType.MODEL,
                        canonical_name=model_canon,
                        display_name=llm_ref,
                        adapter_name=self.name,
                        priority=self.priority,
                        confidence=0.85,
                        metadata={"provider": provider,
                                   **{k: v for k, v in details.items() if v is not None}},
                        file_path=file_path,
                        line=inst.line,
                        snippet=f"Agent(llm={llm_ref!r})",
                        evidence_kind="ast_instantiation",
                    ))

                # Tool references
                if isinstance(tools_raw, list):
                    for tool_ref in tools_raw:
                        if isinstance(tool_ref, str) and not tool_ref.startswith("$"):
                            tool_canon = canonicalize_text(f"crewai:tool:{tool_ref}")
                            rels.append(RelationshipHint(
                                source_canonical=canon,
                                source_type=ComponentType.AGENT,
                                target_canonical=tool_canon,
                                target_type=ComponentType.TOOL,
                                relationship_type="CALLS",
                            ))

                meta: dict[str, Any] = {
                    "framework": "crewai",
                    "role": role,
                    "has_goal": bool(goal),
                    "has_backstory": bool(backstory),
                }
                if goal:
                    meta["goal_preview"] = goal[:200]
                if backstory:
                    meta["backstory_preview"] = backstory[:200]

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
                    snippet=f"Agent(role={role!r})",
                    evidence_kind="ast_instantiation",
                    relationships=rels,
                ))
                agent_canonicals.append(canon)

            # ---- Task ----
            elif inst.class_name == "Task":
                args = inst.args or {}
                description = _clean(args.get("description") or (
                    inst.positional_args[0] if inst.positional_args else None
                ))
                task_name = _clean(inst.assigned_to) or f"task_{inst.line}"
                canon = canonicalize_text(f"crewai:task:{task_name}")
                task_meta: dict[str, Any] = {
                    "framework": "crewai",
                    "task_type": "Task",
                }
                if description:
                    task_meta["description_preview"] = description[:200]

                detected.append(ComponentDetection(
                    component_type=ComponentType.TOOL,
                    canonical_name=canon,
                    display_name=task_name,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.80,
                    metadata=task_meta,
                    file_path=file_path,
                    line=inst.line,
                    snippet="Task(description=...)",
                    evidence_kind="ast_instantiation",
                ))
                task_canonicals.append(canon)

            # ---- Crew ----
            elif inst.class_name == "Crew":
                var_name = inst.assigned_to or f"crew_{inst.line}"
                canon = canonicalize_text(f"crewai:crew:{var_name}")
                agents_raw = inst.args.get("agents", [])
                tasks_raw = inst.args.get("tasks", [])
                crew_rels: list[RelationshipHint] = []

                for agent_ref in (agents_raw if isinstance(agents_raw, list) else []):
                    if isinstance(agent_ref, str) and agent_ref.startswith("$"):
                        ref_canon = canonicalize_text(f"crewai:{agent_ref[1:]}")
                        crew_rels.append(RelationshipHint(
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
                    confidence=0.88,
                    metadata={
                        "orchestrator_type": "Crew",
                        "framework": "crewai",
                        "agent_count": len(agents_raw) if isinstance(agents_raw, list) else 0,
                        "task_count": len(tasks_raw) if isinstance(tasks_raw, list) else 0,
                    },
                    file_path=file_path,
                    line=inst.line,
                    snippet="Crew(agents=[...])",
                    evidence_kind="ast_instantiation",
                    relationships=crew_rels,
                ))

            # ---- @tool decorated functions (crewai.tools.tool) ----
            elif inst.class_name in {"BaseTool", "Tool"}:
                tool_name = _clean(
                    inst.args.get("name")
                    or (inst.positional_args[0] if inst.positional_args else None)
                    or inst.assigned_to
                    or f"tool_{inst.line}"
                )
                canon = canonicalize_text(f"crewai:tool:{tool_name}")
                detected.append(ComponentDetection(
                    component_type=ComponentType.TOOL,
                    canonical_name=canon,
                    display_name=tool_name,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.85,
                    metadata={"framework": "crewai"},
                    file_path=file_path,
                    line=inst.line,
                    snippet=f"{inst.class_name}(name={tool_name!r})",
                    evidence_kind="ast_instantiation",
                ))

        return detected


def _clean(value: Any) -> str:
    if value is None:
        return ""
    s = str(value).strip("'\"` ")
    if s.startswith("$") or s in {"<complex>", "<lambda>", "<dict>", "<list>"}:
        return ""
    return s
