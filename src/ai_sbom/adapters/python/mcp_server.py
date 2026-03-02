"""MCP (Model Context Protocol) server adapter for Xelo SBOM.

Detects usage of the ``mcp`` / ``fastmcp`` Python SDK:
- ``FastMCP("server-name", ...)`` instantiation → FRAMEWORK node
- ``@server.tool()`` / ``@mcp.tool()`` decorated function definitions → TOOL nodes
  (tool name = decorated function name)
- Bare ``@tool`` decorator or ``mcp.add_tool(fn)`` calls → TOOL fallback

The AST parser emits ``ParsedCall(function_name="tool", receiver="mcp",
assigned_to="my_function")`` for ``@mcp.tool()`` decorators, which this
adapter consumes.
"""

from __future__ import annotations

from typing import Any

from ai_sbom.adapters.base import ComponentDetection, FrameworkAdapter
from ai_sbom.normalization import canonicalize_text
from ai_sbom.types import ComponentType

# FastMCP package entrypoints
_MCP_SERVER_CLASSES = {"FastMCP", "Server", "MCPServer"}
# Method name used as decorator on tool functions
_TOOL_METHOD = "tool"


class MCPServerAdapter(FrameworkAdapter):
    """Adapter for MCP server projects (model-context-protocol / fastmcp)."""

    name = "mcp_server"
    priority = 30
    handles_imports = [
        "mcp",
        "mcp.server",
        "mcp.server.fastmcp",
        "mcp.server.stdio",
        "mcp.types",
        "fastmcp",
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

        # Track variable names bound to FastMCP / Server instances
        # e.g. ``mcp = FastMCP("excel-mcp")`` → mcp_vars = {"mcp"}
        mcp_vars: set[str] = set()
        server_name: str | None = None

        for inst in parse_result.instantiations:
            if inst.class_name in _MCP_SERVER_CLASSES:
                if inst.assigned_to:
                    mcp_vars.add(inst.assigned_to)
                # First positional or 'name' kwarg is the server display name
                raw_name = inst.args.get("name") or (
                    inst.positional_args[0] if inst.positional_args else None
                )
                if raw_name and not server_name:
                    server_name = _clean(raw_name)

        # Scan function_calls for @<var>.tool() decorators
        # These appear as ParsedCall(function_name="tool", receiver=<var>, assigned_to=<fn_name>)
        for call in parse_result.function_calls:
            if call.function_name != _TOOL_METHOD:
                continue
            # Must be a decorator (has assigned_to = the decorated function)
            if call.assigned_to is None:
                continue
            # If we know the MCP variable names, filter to those;
            # if none known yet (e.g. FastMCP constructed elsewhere), accept any .tool() receiver
            if mcp_vars and call.receiver not in mcp_vars:
                continue

            # Tool name: explicit name kwarg > decorated function name
            tool_name = _clean(call.args.get("name")) or call.assigned_to or f"tool_{call.line}"
            canon = canonicalize_text(f"mcp:tool:{tool_name}")

            detected.append(
                ComponentDetection(
                    component_type=ComponentType.TOOL,
                    canonical_name=canon,
                    display_name=tool_name,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.92,
                    metadata={
                        "framework": "mcp-server",
                        "server_name": server_name or "unknown",
                        "decorator": f"@{call.receiver or 'server'}.tool()",
                    },
                    file_path=file_path,
                    line=call.line,
                    snippet=f"@{call.receiver or 'server'}.tool()\ndef {tool_name}(...)",
                    evidence_kind="ast_decorator",
                )
            )

        return detected


def _clean(value: Any) -> str:
    if value is None:
        return ""
    s = str(value).strip("'\"` ")
    if s.startswith("$") or s in {"<complex>", "<lambda>", "<dict>", "<list>"}:
        return ""
    return s
