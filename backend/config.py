from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    groq_api_key: str = ""
    groq_model: str = "llama-3.1-8b-instant"
    app_env: str = "development"
    app_port: int = 8000
    company_db_path: str = "./data/company.db"
    security_db_path: str = "./data/security.db"
    llm_timeout_seconds: int = 15
    risk_flag_threshold: float = 0.6

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()