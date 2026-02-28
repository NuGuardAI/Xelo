import os

from pydantic import BaseModel, Field


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _default_llm_model() -> str:
    explicit = os.getenv("AISBOM_LLM_MODEL")
    if explicit:
        return explicit
    # Auto-detect Azure AI Foundry with Anthropic models
    if os.getenv("ANTHROPIC_FOUNDRY_RESOURCE"):
        model_name = os.getenv("ANTHROPIC_DEFAULT_HAIKU_MODEL", "claude-haiku-4-5")
        return f"anthropic/{model_name}"
    return "gpt-4o-mini"


def _azure_base(url: str) -> str:
    """Strip path from an Azure endpoint URL, leaving just scheme + host."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}/"


def _default_llm_api_key() -> str | None:
    explicit = os.getenv("AISBOM_LLM_API_KEY")
    if explicit:
        return explicit
    model = os.getenv("AISBOM_LLM_MODEL", "").lower()
    # Azure Kimi K2 — uses dedicated key
    if "kimi" in model:
        return os.getenv("AZURE_KIMI_K2_KEY")
    # Azure-hosted Anthropic (azure_ai/ prefix) — uses dedicated key
    if "claude" in model:
        return os.getenv("AZURE_ANTHROPIC_KEY")
    # Legacy: anthropic/ prefix via Azure AI Foundry
    if "anthropic" in model:
        return os.getenv("ANTHROPIC_FOUNDRY_API_KEY")
    # All other providers (azure/, openai, etc.) — let litellm read env vars directly
    return None


def _default_llm_api_base() -> str | None:
    explicit = os.getenv("AISBOM_LLM_API_BASE")
    if explicit:
        return explicit
    model = os.getenv("AISBOM_LLM_MODEL", "").lower()
    # Azure Kimi K2 — strip dedicated endpoint to base URL
    if "kimi" in model:
        ep = os.getenv("AZURE_KIMI_K2_ENDPOINT", "")
        return _azure_base(ep) if ep else None
    # Azure-hosted Anthropic (azure_ai/ prefix) — strip dedicated endpoint to base URL
    if "claude" in model:
        ep = os.getenv("AZURE_ANTHROPIC_ENDPOINT", "")
        return _azure_base(ep) if ep else None
    # Legacy: anthropic/ prefix via Azure AI Foundry resource name
    if "anthropic" in model:
        resource = os.getenv("ANTHROPIC_FOUNDRY_RESOURCE")
        if resource:
            return f"https://{resource}.services.ai.azure.com/anthropic"
    # All other providers — let litellm read their own env vars (AZURE_API_BASE, etc.)
    return None


def _default_google_api_key() -> str | None:
    """GCP API key for Vertex AI Gemini (?key= query param on aiplatform.googleapis.com)."""
    return os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_CLOUD_API_KEY") or None


def _default_vertex_location() -> str | None:
    return os.getenv("VERTEXAI_LOCATION") or None


class ExtractionConfig(BaseModel):
    max_files: int = Field(default=1000, ge=1, le=10000)
    max_file_size_bytes: int = Field(default=1024 * 1024, ge=1024)
    include_extensions: set[str] = Field(
        default_factory=lambda: {
            ".py", ".pyw",
            ".ts", ".tsx", ".js", ".jsx",
            ".ipynb",
            ".sql",
            ".json", ".yaml", ".yml", ".tf", ".md",
        }
    )
    deterministic_only: bool = Field(
        default_factory=lambda: _env_bool("AISBOM_DETERMINISTIC_ONLY", True)
    )
    # LLM enrichment (used when deterministic_only=False)
    llm_model: str = Field(default_factory=_default_llm_model)
    llm_api_key: str | None = Field(default_factory=_default_llm_api_key)
    llm_api_base: str | None = Field(default_factory=_default_llm_api_base)
    llm_budget_tokens: int = Field(
        default_factory=lambda: _env_int("AISBOM_LLM_BUDGET_TOKENS", 50_000)
    )
    # Vertex AI — direct httpx path (bypasses litellm when google_api_key is set)
    google_api_key: str | None = Field(default_factory=_default_google_api_key)
    vertex_location: str | None = Field(default_factory=_default_vertex_location)
