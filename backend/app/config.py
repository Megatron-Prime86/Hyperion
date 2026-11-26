from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite+aiosqlite:///./hyperion.db"
    redis_url: str = "redis://localhost:6379/0"
    celery_task_always_eager: bool = True
    llm_provider: str = "mock"
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"
    anthropic_base_url: str = "https://api.anthropic.com"
    llm_model: str = ""
    correlation_window_minutes: int = 30
    abuseipdb_api_key: str = ""
    intel_timeout_seconds: float = 3.0
    llm_timeout_seconds: float = 30.0

    @property
    def database_backend(self) -> str:
        url = self.database_url.lower()
        if url.startswith("postgres"):
            return "postgresql"
        if url.startswith("sqlite"):
            return "sqlite"
        return "other"

    @property
    def llm_mode(self) -> str:
        provider = (self.llm_provider or "mock").lower()
        if provider == "openai" and self.openai_api_key:
            return "openai"
        if provider == "anthropic" and self.anthropic_api_key:
            return "anthropic"
        return "mock"


settings = Settings()
