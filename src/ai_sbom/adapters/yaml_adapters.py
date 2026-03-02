"""YAML-based adapters for AI SBOM extraction.

Parses structured YAML configuration files used by AI frameworks.

Supported patterns
------------------
``CrewAIYAMLAdapter``:
    Detects agents defined in CrewAI ``config/agents.yaml`` files.
    Each top-level key with a ``role`` or ``goal`` sub-key is treated as
    an AGENT component.  Works for both the legacy single-crew layout and
    the new ``src/<package>/config/agents.yaml`` layout.

``AutoGenYAMLAdapter``:
    Detects agent configs from AutoGen-style YAML files (``OAI_CONFIG_LIST``
    or ``autogen_config`` keys with ``model`` entries).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from ai_sbom.adapters.base import ComponentDetection
from ai_sbom.types import ComponentType

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _try_load_yaml(content: str) -> Any:
    """Parse YAML content, returning None on failure."""
    try:
        import yaml  # type: ignore[import-untyped]

        return yaml.safe_load(content)
    except Exception as exc:  # noqa: BLE001
        _log.debug("YAML parse error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# CrewAI agents.yaml adapter
# ---------------------------------------------------------------------------


class CrewAIYAMLAdapter:
    """Detect CrewAI agents defined in YAML configuration files.

    CrewAI projects store agent definitions in ``config/agents.yaml``.
    The file is a mapping where each top-level key is the agent variable name
    and the value is a dict with at least ``role`` and/or ``goal`` fields.

    Example::

        researcher:
          role: Senior Research Analyst
          goal: Uncover cutting-edge developments in AI
          backstory: ...

    Matching heuristic: the path must contain ``agents.yaml`` (case-insensitive)
    and the parsed value must be a mapping of non-empty dicts that contain at
    least one of ``role``, ``goal``, or ``backstory``.
    """

    name = "crewai_yaml"
    priority = 35  # lower than python adapters but higher than regex-only

    #: Path fragment that must be present for this adapter to fire
    _PATH_PATTERN = re.compile(r"agents\.ya?ml$", re.IGNORECASE)

    def scan(self, content: str, rel_path: str) -> list[ComponentDetection]:
        """Return AGENT detections for each agent defined in a CrewAI YAML file.

        Parameters
        ----------
        content:
            Raw file text.
        rel_path:
            Path relative to the repo root (for evidence location).
        """
        path_str = str(rel_path)
        if not self._PATH_PATTERN.search(path_str):
            return []

        data = _try_load_yaml(content)
        if not isinstance(data, dict):
            return []

        detections: list[ComponentDetection] = []
        line_cache = _build_line_index(content)

        for agent_key, agent_val in data.items():
            if not isinstance(agent_val, dict):
                continue
            # Must have at least one of these canonical CrewAI agent fields
            if not any(k in agent_val for k in ("role", "goal", "backstory")):
                continue

            agent_name = str(agent_key).strip()
            if not agent_name:
                continue

            role = (agent_val.get("role") or "").strip()
            goal = (agent_val.get("goal") or "").strip()
            line = _find_key_line(line_cache, agent_name)

            det = ComponentDetection(
                component_type=ComponentType.AGENT,
                canonical_name=agent_name,
                display_name=agent_name,
                adapter_name=self.name,
                priority=self.priority,
                confidence=0.85,
                metadata={
                    "framework": "crewai",
                    "role": role or None,
                    "goal": goal or None,
                    "source": "yaml_config",
                },
                file_path=rel_path,
                line=line,
                snippet=f"{agent_name}: role={role[:60]!r}" if role else agent_name,
                evidence_kind="yaml",
            )
            detections.append(det)
            _log.debug("crewai_yaml: detected agent %r in %s (line %s)", agent_name, rel_path, line)

        return detections


# ---------------------------------------------------------------------------
# AutoGen config.yaml adapter
# ---------------------------------------------------------------------------

_AUTOGEN_PATH_RE = re.compile(
    r"(autogen|OAI_CONFIG|model_config).*\.ya?ml$"
    r"|config\.ya?ml$",  # generic config.yaml files may use autogen format
    re.IGNORECASE,
)
_AUTOGEN_MODEL_FIELDS = {"model", "engine", "api_engine"}

# Autogen provider prefix (identifies autogen-ext model config files)
_AUTOGEN_PROVIDER_PREFIX = "autogen_ext"
# Agent keys that indicate an AutoGen distributed chat agent definition
_AUTOGEN_AGENT_KEYS = {"description", "system_message", "human_input_mode", "is_termination_msg"}


class AutoGenYAMLAdapter:
    """Detect models and agents from AutoGen YAML configuration files.

    Handles two config varieties:

    1. **Model config** (``model_config.yaml`` / ``config.yaml`` with
       ``provider: autogen_ext.models.*``):
       Detects ``model`` entries inside ``config:`` blocks.

    2. **Agent config** (``config.yaml`` with top-level agent keys):
       Detects agents that have ``description`` and/or ``system_message``
       sub-keys — the AutoGen distributed group chat pattern.
    """

    name = "autogen_yaml"
    priority = 36

    def scan(self, content: str, rel_path: str) -> list[ComponentDetection]:
        path_str = str(rel_path)
        if not _AUTOGEN_PATH_RE.search(path_str):
            return []

        data = _try_load_yaml(content)
        if not isinstance(data, dict):
            return []

        detections: list[ComponentDetection] = []
        line_cache = _build_line_index(content)

        # Pattern 1: AutoGen model config with provider + config.model
        if self._is_autogen_model_config(data):
            config_block = data.get("config") or {}
            if isinstance(config_block, dict):
                for field in _AUTOGEN_MODEL_FIELDS:
                    model = (config_block.get(field) or "").strip()
                    if model:
                        line = _find_key_line(line_cache, model)
                        detections.append(
                            ComponentDetection(
                                component_type=ComponentType.MODEL,
                                canonical_name=model.lower(),
                                display_name=model,
                                adapter_name=self.name,
                                priority=self.priority,
                                confidence=0.85,
                                metadata={"framework": "autogen", "source": "yaml_config"},
                                file_path=rel_path,
                                line=line,
                                snippet=f"model: {model}",
                                evidence_kind="yaml",
                            )
                        )
            # Check model_config sub-block too
            mc = data.get("model_config") or {}
            if isinstance(mc, dict):
                cfg = mc.get("config") or {}
                if isinstance(cfg, dict):
                    model = (cfg.get("model") or "").strip()
                    if model:
                        line = _find_key_line(line_cache, model)
                        detections.append(
                            ComponentDetection(
                                component_type=ComponentType.MODEL,
                                canonical_name=model.lower(),
                                display_name=model,
                                adapter_name=self.name,
                                priority=self.priority,
                                confidence=0.85,
                                metadata={"framework": "autogen", "source": "yaml_config"},
                                file_path=rel_path,
                                line=line,
                                snippet=f"model: {model}",
                                evidence_kind="yaml",
                            )
                        )

        # Pattern 2: OAI_CONFIG_LIST style (list of dicts with model field)
        for key in ("config_list", "models"):
            sub = data.get(key)
            if isinstance(sub, list):
                seen: set[str] = set()
                for entry in sub:
                    if isinstance(entry, dict):
                        for field in _AUTOGEN_MODEL_FIELDS:
                            model = (entry.get(field) or "").strip()
                            if model and model not in seen:
                                seen.add(model)
                                line = _find_key_line(line_cache, model)
                                detections.append(
                                    ComponentDetection(
                                        component_type=ComponentType.MODEL,
                                        canonical_name=model.lower(),
                                        display_name=model,
                                        adapter_name=self.name,
                                        priority=self.priority,
                                        confidence=0.80,
                                        metadata={"framework": "autogen", "source": "yaml_config"},
                                        file_path=rel_path,
                                        line=line,
                                        snippet=f"model: {model}",
                                        evidence_kind="yaml",
                                    )
                                )

        # Pattern 3: AutoGen distributed chat agents (top-level keys with
        # description + system_message sub-keys)
        for key, val in data.items():
            if not isinstance(val, dict):
                continue
            if not any(k in val for k in _AUTOGEN_AGENT_KEYS):
                continue
            # Skip non-agent keys (host, group_chat_manager, client_config, etc.)
            if key in {
                "host",
                "client_config",
                "group_chat_manager",
                "model_config",
                "config_list",
                "models",
                "host",
                "ui_agent",
            }:
                continue
            agent_name = str(key).strip()
            if not agent_name:
                continue
            description = (val.get("description") or "").strip()
            line = _find_key_line(line_cache, agent_name)
            detections.append(
                ComponentDetection(
                    component_type=ComponentType.AGENT,
                    canonical_name=agent_name,
                    display_name=agent_name,
                    adapter_name=self.name,
                    priority=self.priority,
                    confidence=0.80,
                    metadata={
                        "framework": "autogen",
                        "description": description[:100] if description else None,
                        "source": "yaml_config",
                    },
                    file_path=rel_path,
                    line=line,
                    snippet=f"{agent_name}: description={description[:60]!r}"
                    if description
                    else agent_name,
                    evidence_kind="yaml",
                )
            )
            _log.debug("autogen_yaml: agent %r in %s", agent_name, rel_path)

        return detections

    def _is_autogen_model_config(self, data: dict) -> bool:
        """Check if the YAML looks like an AutoGen model config."""
        provider = str(data.get("provider") or "")
        if _AUTOGEN_PROVIDER_PREFIX in provider:
            return True
        mc = data.get("model_config") or {}
        if isinstance(mc, dict):
            provider2 = str(mc.get("provider") or "")
            if _AUTOGEN_PROVIDER_PREFIX in provider2:
                return True
        return False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_line_index(content: str) -> list[str]:
    """Split content into lines (1-indexed via list[0] = line 1)."""
    return ["<dummy>"] + content.splitlines()


def _find_key_line(line_cache: list[str], key: str) -> int:
    """Return 1-based line number where ``key:`` first appears, or 1."""
    # Quick linear scan — YAML config files are small
    prefix = key + ":"
    for i, line in enumerate(line_cache[1:], start=1):
        stripped = line.strip()
        if stripped.startswith(prefix) or stripped == key + ":":
            return i
    return 1
