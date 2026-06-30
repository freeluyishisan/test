from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for East-8 weather trader."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: str = "development"
    app_timezone: str = "Asia/Hong_Kong"
    log_level: str = "INFO"

    paper_trading: bool = True
    enable_live_trading: bool = False

    bankroll_usdc: float = 1000.0
    min_edge_to_trade: float = 0.08
    strong_edge: float = 0.12
    max_trade_size_usdc: float = 20.0
    daily_loss_limit_usdc: float = 100.0
    max_data_staleness_seconds: int = 180

    polymarket_enabled: bool = False

    hko_textonly_url: str = "https://www.hko.gov.hk/textonly/v2/forecast/text_readings_e.htm"
    hko_csv_url: str = "https://www.hko.gov.hk/wxinfo/awsgis/hko.csv"


settings = Settings()
