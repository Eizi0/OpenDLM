from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPENDLM_")

    database_url: str = "postgresql+psycopg://opendlm:opendlm@db:5432/opendlm"
    demo: bool = False
    hibp_api_key: str = ""
    notify_urls: str = ""  # URLs Apprise séparées par des virgules
    scheduler_enabled: bool = True
    scan_hour: int = 6
    timezone: str = "Europe/Paris"
    user_agent: str = "OpenDLM/0.1 (self-hosted leak monitor)"

    @property
    def notify_url_list(self) -> list[str]:
        return [u.strip() for u in self.notify_urls.split(",") if u.strip()]


settings = Settings()
