from __future__ import annotations

from argparse import Namespace

from ai_sbom.cli import _build_extraction_config
from ai_sbom.config import ExtractionConfig


def _scan_args(
    *,
    enable_llm: bool | None = None,
    llm_model: str | None = None,
    llm_budget_tokens: int | None = None,
    llm_api_key: str | None = None,
) -> Namespace:
    return Namespace(
        enable_llm=enable_llm,
        llm_model=llm_model,
        llm_budget_tokens=llm_budget_tokens,
        llm_api_key=llm_api_key,
    )


def test_extraction_config_respects_env_enable_llm_true(monkeypatch) -> None:
    monkeypatch.setenv("AISBOM_ENABLE_LLM", "true")
    cfg = ExtractionConfig()
    assert cfg.enable_llm is True


def test_extraction_config_respects_env_enable_llm_false(monkeypatch) -> None:
    monkeypatch.setenv("AISBOM_ENABLE_LLM", "false")
    cfg = ExtractionConfig()
    assert cfg.enable_llm is False


def test_cli_defaults_to_enable_llm_false_when_not_set(monkeypatch) -> None:
    monkeypatch.setenv("AISBOM_ENABLE_LLM", "true")
    cfg = _build_extraction_config(_scan_args(enable_llm=False))
    assert cfg.enable_llm is False


def test_cli_overrides_env_to_enable_llm(monkeypatch) -> None:
    monkeypatch.setenv("AISBOM_ENABLE_LLM", "false")
    cfg = _build_extraction_config(_scan_args(enable_llm=True))
    assert cfg.enable_llm is True


def test_legacy_deterministic_only_input_maps_to_enable_llm() -> None:
    cfg = ExtractionConfig(deterministic_only=False)
    assert cfg.enable_llm is True
