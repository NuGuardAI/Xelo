from __future__ import annotations

from argparse import Namespace

from ai_sbom.cli import _build_extraction_config
from ai_sbom.config import ExtractionConfig


def _scan_args(
    *,
    deterministic_only: bool | None = None,
    llm_model: str | None = None,
    llm_budget_tokens: int | None = None,
    llm_api_key: str | None = None,
) -> Namespace:
    return Namespace(
        deterministic_only=deterministic_only,
        llm_model=llm_model,
        llm_budget_tokens=llm_budget_tokens,
        llm_api_key=llm_api_key,
    )


def test_extraction_config_respects_env_deterministic_false(monkeypatch) -> None:
    monkeypatch.setenv("AISBOM_DETERMINISTIC_ONLY", "false")
    cfg = ExtractionConfig()
    assert cfg.deterministic_only is False


def test_extraction_config_respects_env_deterministic_true(monkeypatch) -> None:
    monkeypatch.setenv("AISBOM_DETERMINISTIC_ONLY", "true")
    cfg = ExtractionConfig()
    assert cfg.deterministic_only is True


def test_cli_overrides_env_to_deterministic_true(monkeypatch) -> None:
    monkeypatch.setenv("AISBOM_DETERMINISTIC_ONLY", "false")
    cfg = _build_extraction_config(_scan_args(deterministic_only=True))
    assert cfg.deterministic_only is True


def test_cli_overrides_env_to_enable_llm(monkeypatch) -> None:
    monkeypatch.setenv("AISBOM_DETERMINISTIC_ONLY", "true")
    cfg = _build_extraction_config(_scan_args(deterministic_only=False))
    assert cfg.deterministic_only is False
