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
    virustotal_api_key: str = ""
    otx_api_key: str = ""
    urlhaus_api_key: str = ""
    intel_timeout_seconds: float = 5.0
    intel_cache_hours: int = 24
    intel_max_lookups: int = 8  # live indicators looked up per alert (quota guard)
    llm_timeout_seconds: float = 30.0
    dedup_window_minutes: int = 60
    # SLA targets in minutes per risk tier ("tier=minutes,...")
    sla_ack_minutes: str = "critical=15,high=60,medium=240,low=1440"
    sla_resolve_minutes: str = "critical=240,high=480,medium=1440,low=4320"
    # Notifications (a channel is skipped when not configured)
    dashboard_url: str = "http://localhost:3000"
    notify_min_tier: str = "critical"
    slack_webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "hyperion@localhost"
    smtp_starttls: bool = True
    notify_email_to: str = ""
    # Response playbooks: dry-run only unless execution is explicitly enabled
    playbook_enable_execution: bool = False
    playbook_webhook_url: str = ""
    playbook_protected_users: str = "root,administrator,admin,system"
    # Analyst feedback loop: a rule analysts keep dismissing (or escalating) adjusts triage scores.
    feedback_min_decisions: int = 3
    feedback_ratio: float = 0.8
    feedback_fp_penalty: int = 25
    feedback_boost: int = 10
    llm_max_deviation: int = 40  # LLM score may differ from the rule-based baseline by at most this much
    auto_migrate: bool = True
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    # Auth: blank secrets are generated at startup and logged once.
    ingest_api_key: str = ""
    jwt_secret: str = ""
    jwt_expire_minutes: int = 480
    admin_username: str = "admin"
    admin_password: str = ""
    analyst_username: str = "analyst"
    analyst_password: str = ""

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
