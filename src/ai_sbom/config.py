from pydantic import BaseModel, Field


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
    deterministic_only: bool = True
    # LLM enrichment (used when deterministic_only=False)
    llm_model: str = "gpt-4o-mini"
    llm_api_key: str | None = None
    llm_budget_tokens: int = 50_000
