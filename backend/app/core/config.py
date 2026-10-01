"""Application configuration loaded from environment variables / .env file."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(BACKEND_DIR / ".env",),
        env_file_encoding="utf-8",
        env_prefix="TIM_",
        extra="ignore",
    )

    app_name: str = "Threat Infrastructure Mapper"
    version: str = "1.0.0"
    environment: str = Field(default="development", description="development | test | production")
    debug: bool = False

    # --- HTTP server ---
    host: str = "127.0.0.1"
    port: int = 8000
    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # --- MongoDB ---
    mongo_uri: str = "mongodb://127.0.0.1:27017"
    mongo_db: str = "tim"

    # --- Security ---
    secret_key: str = Field(default="change-me-in-env-file-please-0123456789abcdef", min_length=32)
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 60 * 8
    admin_username: str = "admin"
    admin_password: str = "ChangeMe!2026"
    admin_email: str = "admin@tim.local"

    # --- Collection ---
    http_timeout_seconds: float = 20.0
    max_html_bytes: int = 5 * 1024 * 1024
    max_redirects: int = 10
    allow_private_targets: bool = Field(
        default=False, description="Allow collection against private/loopback addresses (SSRF guard)"
    )
    screenshots_enabled: bool = True
    screenshot_timeout_ms: int = 30000
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    )

    # --- Pipeline ---
    max_concurrent_investigations: int = 4
    provider_timeout_seconds: float = 25.0
    default_cache_ttl_hours: int = 24
    max_pivot_expansion: int = 25

    # --- Uploads ---
    max_upload_bytes: int = 15 * 1024 * 1024

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip().startswith("["):
            return [v.strip() for v in value.split(",") if v.strip()]
        return value

    @property
    def is_test(self) -> bool:
        return self.environment == "test"


@lru_cache
def get_settings() -> Settings:
    return Settings()
