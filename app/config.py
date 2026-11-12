from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPENDLM_")

    data_dir: str = "/data"  # holds the master key (secret.key) used to encrypt secrets stored in the database
    secret_key: str = ""  # optional: master key from the environment instead of the data volume
    language: str = "en"  # default interface language (en | fr)
    database_url: str = "postgresql+psycopg://opendlm:opendlm@db:5432/opendlm"
    demo: bool = False
    hibp_api_key: str = ""
    notify_urls: str = ""  # comma-separated Apprise URLs
    hudson_rock_free_enabled: bool = True  # keyless Hudson Rock tools; ignored once an official key is set
    leakcheck_enabled: bool = False  # per-address source: sends hashes of monitored addresses
    xposedornot_enabled: bool = False  # per-address source: sends monitored addresses
    hudson_rock_key: str = ""  # Hudson Rock (Cavalier v3) API key
    ransomware_live_key: str = ""  # ransomware.live PRO API key (free)
    news_interval_minutes: int = 30
    news_retention_days: int = 90
    allow_private_feeds: bool = False  # allow feeds on the internal network
    report_daily: bool = True
    report_monthly: bool = True
    report_hour: int = 7
    report_send_empty: bool = True  # an "all clear" report doubles as a heartbeat
    alert_min_severity: str = "low"  # low | high | critical: immediate alert threshold
    scheduler_enabled: bool = True
    cookie_secure: bool = False  # true behind an HTTPS proxy
    scan_hour: int = 6
    timezone: str = "Europe/Paris"
    user_agent: str = "OpenDLM/0.1 (self-hosted leak monitor)"

    @property
    def notify_url_list(self) -> list[str]:
        return [u.strip() for u in self.notify_urls.split(",") if u.strip()]


settings = Settings()
