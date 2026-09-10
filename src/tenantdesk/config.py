from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = (
        "postgresql+asyncpg://tenantdesk_app:tenantdesk_app@database:5432/tenantdesk"
    )
    jwt_secret: str = Field(
        default="local-demo-tenantdesk-replace-before-deployment", min_length=32
    )
    token_minutes: int = Field(default=60, ge=1, le=1440)
    worker_database_url: str = (
        "postgresql+asyncpg://tenantdesk_worker:tenantdesk_worker@database:5432/tenantdesk"
    )
    testing: bool = False
    worker_interval: float = Field(default=1, ge=0.05, le=60)


settings = Settings()
