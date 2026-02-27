# backend/src/socrates/config.py
#
# Loads all application settings from environment variables / .env file.
# NOTE: Prototype — minimal settings.
# Production would add: database URL, rate limiting, logging config.

from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    # Auth
    secret_key:                  str = "dev-secret-key-change-in-production"
    algorithm:                   str = "HS256"
    access_token_expire_minutes: int = 30

    # File upload
    upload_dir: str = str(
        Path(__file__).parents[3] / "data" / "uploads"
    )

    # Anthropic — optional, mock used if not set
    anthropic_api_key: str = ""

    # App
    environment: str = "development"

    class Config:
        env_file = Path(__file__).parents[3] / ".env"
        extra    = "ignore"


settings = Settings()