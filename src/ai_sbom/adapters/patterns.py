from __future__ import annotations

import re

from ai_sbom.types import ComponentType

PATTERNS: dict[ComponentType, tuple[re.Pattern[str], ...]] = {
    ComponentType.AGENT: (
        re.compile(r"\b(Agent|assistant|orchestrator)\b", re.IGNORECASE),
    ),
    ComponentType.FRAMEWORK: (
        re.compile(r"\b(langchain|langgraph|autogen|crewai|llamaindex|semantic_kernel)\b", re.IGNORECASE),
    ),
    ComponentType.MODEL: (
        re.compile(r"\b(gpt-[\w.-]+|claude-[\w.-]+|gemini[-\w.]+|llama[-\w.]+)\b", re.IGNORECASE),
    ),
    ComponentType.TOOL: (
        re.compile(r"\btool\b", re.IGNORECASE),
    ),
    ComponentType.DATASTORE: (
        re.compile(r"\b(postgres|mysql|mongodb|redis|pinecone|faiss|chroma)\b", re.IGNORECASE),
    ),
    ComponentType.AUTH: (
        re.compile(r"\b(jwt|oauth|apikey|api_key|token|auth)\b", re.IGNORECASE),
    ),
    ComponentType.PRIVILEGE: (
        re.compile(r"\b(admin|scope|role|rbac|permission|least privilege)\b", re.IGNORECASE),
    ),
    ComponentType.API_ENDPOINT: (
        re.compile(r"\b(GET|POST|PUT|DELETE|PATCH)\s+/[\w/{}:-]+"),
        re.compile(r"@(app|router)\.(get|post|put|delete|patch)\(", re.IGNORECASE),
    ),
    ComponentType.DEPLOYMENT: (
        re.compile(r"\b(docker|kubernetes|helm|terraform|compose|deployment)\b", re.IGNORECASE),
    ),
    ComponentType.PROMPT: (
        re.compile(r"\b(system prompt|prompt template|instructions?)\b", re.IGNORECASE),
    ),
}
