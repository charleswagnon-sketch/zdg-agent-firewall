"""Settings for the OpenClaw runtime adapter."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings


SUPPORTED_OPENCLAW_VERSION = "2026-03"


class OpenClawSettings(BaseSettings):
    """Adapter-local settings loaded from environment."""

    openclaw_tool_map_path: str = str(Path(__file__).with_name("tool_map.yaml"))
    openclaw_zdg_base_url: str = "http://localhost:8000"
    openclaw_zdg_timeout: float = 5.0
    openclaw_fail_mode: Literal["closed", "open"] = "closed"
    openclaw_agent_id_field: str = "assistant_id"
    openclaw_version: str = SUPPORTED_OPENCLAW_VERSION

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}

    @property
    def tool_map_path_resolved(self) -> str:
        return str(Path(self.openclaw_tool_map_path).expanduser().resolve())


@lru_cache()
def get_openclaw_settings() -> OpenClawSettings:
    """Return the cached adapter settings instance."""

    return OpenClawSettings()
