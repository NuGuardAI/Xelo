"""Azure AI Agent Service adapter.

Detects usage of the Azure AI Projects / Agents SDK:
- ``AIProjectClient.from_connection_string(...)`` / ``AIProjectClient(...)`` → FRAMEWORK
- ``AIAgentClient(...)`` / ``AgentsClient(...)`` → FRAMEWORK
- Tool class instantiations (``BingGroundingTool``, ``FunctionTool``, ``FileSearchTool``,
  ``CodeInterpreterTool``, ``AzureAISearchTool``) → TOOL nodes
- ``DefaultAzureCredential()`` / ``ManagedIdentityCredential()`` → AUTH nodes
- Agent name extracted from env-var or string args → AGENT node
"""
from __future__ import annotations

from typing import Any

from ai_sbom.adapters.base import ComponentDetection, FrameworkAdapter
from ai_sbom.normalization import canonicalize_text
from ai_sbom.types import ComponentType

# Main client class names that confirm the Azure AI Agent Service SDK is in use
_FRAMEWORK_INIT_CLASSES = {
    "AIProjectClient",
    "AIAgentClient",
    "AgentsClient",
    "AzureAIProjectClient",
}
# Static factory methods that also confirm the SDK
_FRAMEWORK_STATIC_METHODS = {"from_connection_string", "from_endpoint"}

# Built-in tool class names → TOOL nodes
_TOOL_CLASSES = {
    "BingGroundingTool",
    "FunctionTool",
    "FileSearchTool",
    "CodeInterpreterTool",
    "AzureAISearchTool",
    "SharePointTool",
    "MicrosoftFabricTool",
    "OpenApiTool",
    "ToolSet",
}

# Azure identity credential classes → AUTH nodes
_CREDENTIAL_CLASSES = {
    "DefaultAzureCredential",
    "ManagedIdentityCredential",
    "ClientSecretCredential",
    "WorkloadIdentityCredential",
    "EnvironmentCredential",
    "CertificateCredential",
    "InteractiveBrowserCredential",
}

# Env-var / string kwargs that commonly hold the agent model name
_MODEL_KWARGS = {"model", "deployment_name", "model_deployment_name", "ai_model_id"}
_AGENT_NAME_KWARGS = {"name", "agent_name"}


def _clean(val: Any) -> str:
    if val is None:
        return ""
    s = str(val)
    if s.startswith("$"):
        return ""
    return s.strip().strip("\"'")


class AzureAIAgentsAdapter(FrameworkAdapter):
    """Adapter for the Azure AI Agent Service (azure-ai-projects SDK)."""

    name = "azure_ai_agent_service"
    priority = 28
    handles_imports = [
        "azure.ai.projects",
        "azure.ai.agents",
        "azure.ai.projects.models",
        "azure.ai.agents.models",
        "azure.identity",
    ]

    def extract(
        self,
        content: str,
        file_path: str,
        parse_result: Any,
    ) -> list[ComponentDetection]:
        if parse_result is None:
            return []

        detected: list[ComponentDetection] = [self._framework_node(file_path)]

        # Pass 1: Scan instantiations for framework clients, tools, credentials
        for inst in parse_result.instantiations:
            cn = inst.class_name

            if cn in _TOOL_CLASSES:
                tool_display = _clean(inst.assigned_to or cn)
                detected.append(ComponentDetection(
                    component_type=ComponentType.TOOL,
                    canonical_name=canonicalize_text(f"azure_ai:{cn.lower()}:{tool_display}"),
                    display_name=cn,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.90,
                    metadata={"framework": "azure_ai_agent_service", "tool_class": cn},
                    file_path=file_path,
                    line=inst.line,
                    snippet=f"{cn}(...)",
                    evidence_kind="ast_instantiation",
                ))

            elif cn in _CREDENTIAL_CLASSES:
                detected.append(ComponentDetection(
                    component_type=ComponentType.AUTH,
                    canonical_name=canonicalize_text(f"azure_ai:auth:{cn.lower()}"),
                    display_name=cn,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.88,
                    metadata={"framework": "azure_ai_agent_service", "credential_type": cn},
                    file_path=file_path,
                    line=inst.line,
                    snippet=f"{cn}()",
                    evidence_kind="ast_instantiation",
                ))

        # Pass 2: Static factory calls (AIProjectClient.from_connection_string)
        # These appear as function_calls with receiver = "AIProjectClient"
        for call in parse_result.function_calls:
            if (
                call.function_name in _FRAMEWORK_STATIC_METHODS
                and call.receiver in _FRAMEWORK_INIT_CLASSES
            ):
                # Already have the framework node; no duplicate
                pass

            # agents.create / agents.create_agent → AGENT node extraction
            if call.function_name in {"create", "create_agent"} and call.receiver in {
                "agent",
                "agents",
                "client",
                "project_client",
            }:
                agent_name = ""
                for kw in _AGENT_NAME_KWARGS:
                    agent_name = _clean((call.args or {}).get(kw, ""))
                    if agent_name:
                        break
                if not agent_name:
                    agent_name = _clean(call.assigned_to or "enterprise_agent")

                model = ""
                for kw in _MODEL_KWARGS:
                    model = _clean((call.args or {}).get(kw, ""))
                    if model:
                        break

                canon = canonicalize_text(f"azure_ai:agent:{agent_name}")
                detected.append(ComponentDetection(
                    component_type=ComponentType.AGENT,
                    canonical_name=canon,
                    display_name=agent_name,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.82,
                    metadata={
                        "framework": "azure_ai_agent_service",
                        "model": model or None,
                    },
                    file_path=file_path,
                    line=call.line,
                    snippet=f"{call.receiver}.{call.function_name}(...)",
                    evidence_kind="ast_method_call",
                ))

        return detected
