"""
core/config.py
==============
Central configuration management for the AI Bug Bounty Scanner.
Loads settings from environment variables and config.yaml.
"""

import os
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import validator


BASE_DIR = Path(__file__).parent.parent


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ── App ──────────────────────────────────────────────────────────────────
    APP_NAME: str = "AI Bug Bounty Scanner"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    SECRET_KEY: str = "change-this-in-production"

    # ── Database ──────────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://user:password@localhost/bugbounty"
    DATABASE_POOL_SIZE: int = 10

    # ── API ───────────────────────────────────────────────────────────────────
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    # ── Scanner ───────────────────────────────────────────────────────────────
    MAX_SCAN_DEPTH: int = 5
    MAX_THREADS: int = 20
    REQUEST_TIMEOUT: int = 30
    MAX_RETRIES: int = 3
    RATE_LIMIT_RPS: int = 10  # requests per second
    USER_AGENT: str = (
        "Mozilla/5.0 (compatible; BugBountyScanner/1.0; "
        "+https://github.com/bugbounty-scanner)"
    )

    # ── AI Engine ─────────────────────────────────────────────────────────────
    AI_CONFIDENCE_THRESHOLD: float = 0.65
    AI_LEARNING_ENABLED: bool = True
    AI_MODEL_PATH: str = str(BASE_DIR / "ai_engine" / "models")

    # ── Reporting ─────────────────────────────────────────────────────────────
    REPORTS_DIR: str = str(BASE_DIR / "reports")
    REPORT_FORMATS: List[str] = ["html", "json", "markdown"]

    class Config:
        env_file = ".env"
        case_sensitive = True


@dataclass
class ScanConfig:
    """Per-scan configuration object."""

    target: str
    depth: int = 3
    threads: int = 10
    timeout: int = 30
    modules: List[str] = field(default_factory=lambda: [
        "recon", "crawl", "sqli", "xss", "cmdi",
        "idor", "auth", "upload", "traversal", "api"
    ])
    output_formats: List[str] = field(default_factory=lambda: ["html", "json"])
    follow_redirects: bool = True
    verify_ssl: bool = False
    auth_token: Optional[str] = None
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    exclude_paths: List[str] = field(default_factory=list)
    continuous_mode: bool = False
    scan_interval: int = 3600  # seconds


def load_yaml_config(path: str = None) -> dict:
    """Load configuration from YAML file."""
    config_path = path or (BASE_DIR / "config.yaml")
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            return yaml.safe_load(f) or {}
    return {}


# Global settings instance
settings = Settings()
