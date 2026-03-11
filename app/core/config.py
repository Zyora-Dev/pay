"""
Zyora Pay - Configuration
Centralized payment service at pay.zyora.cloud
"""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # App
    APP_NAME: str = "Zyora Pay"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/zyora_pay"

    # CORS - comma-separated origins
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:6006,https://ztunnel.dev,https://zyora.cloud"

    # Admin credentials for managing the pay service
    ADMIN_SECRET: str = "change-me-in-production"

    # HMAC secret for signing webhook callbacks to client apps
    WEBHOOK_SECRET: str = "webhook-hmac-secret-change-me"

    @property
    def async_database_url(self) -> str:
        """Ensure DATABASE_URL uses asyncpg driver (Render gives postgresql://)."""
        url = self.DATABASE_URL
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
        return url

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
