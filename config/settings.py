from __future__ import annotations

from functools import lru_cache
from typing import Dict, List

from pydantic import Field

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:
    from pydantic import BaseSettings  # type: ignore
    SettingsConfigDict = None  # type: ignore


class FirewallSettings(BaseSettings):
    app_name: str = "AI Firewall"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000

    rate_limit_requests: int = 100
    rate_limit_window: int = 60

    block_threshold: float = 0.8
    challenge_threshold: float = 0.6
    allow_threshold: float = 0.3

    agent_weights: dict = Field(
        default_factory=lambda: {
            "threat_intel": 0.2,
            "anomaly_detection": 0.2,
            "bot_detection": 0.2,
            "prompt_injection": 0.2,
            "jailbreak": 0.2,
        }
    )

    geo_blocked_countries: list[str] = Field(default_factory=list)

    enable_threat_intel: bool = True
    enable_anomaly_detection: bool = True
    enable_bot_detection: bool = True

    log_level: str = "INFO"
    log_file: str = "logs/firewall.log"

    max_body_size: int = 10240

    whitelist_ips: list[str] = Field(default_factory=list)
    blacklist_ips: list[str] = Field(default_factory=list)

    cors_origins: list[str] = Field(default_factory=lambda: ["*"])

    if SettingsConfigDict is not None:
        model_config = SettingsConfigDict(
            env_prefix="FIREWALL_",
            env_file=".env",
            env_file_encoding="utf-8",
            case_sensitive=False,
            extra="ignore",
        )
    else:
        class Config:
            env_prefix = "FIREWALL_"
            env_file = ".env"
            env_file_encoding = "utf-8"
            case_sensitive = False
            extra = "ignore"


@lru_cache()
def get_settings() -> FirewallSettings:
    return FirewallSettings()
