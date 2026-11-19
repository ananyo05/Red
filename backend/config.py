"""
Configuration settings for RedLoop.

Centralizes all model selections, API keys, rate limits, and persistence paths.
Model names can be updated here as Groq updates its supported catalog.
Check console.groq.com for the latest available models.
"""

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


# Base paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DEFAULT_CACHE_DIR = DATA_DIR / "cache"
DEFAULT_DB_PATH = DATA_DIR / "redloop.db"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Groq API Configuration
    groq_api_key: str = Field(default="", alias="GROQ_API_KEY")
    mock_llm: bool = Field(default=True, alias="MOCK_LLM")

    # Model Catalog
    # Weak defender: faster, more susceptible to prompt injection
    weak_defender_model: str = "llama-3.1-8b-instant"
    # Strong defender: larger reasoning capacity, more resistant
    strong_defender_model: str = "llama-3.3-70b-versatile"
    # Attacker model used for automated red-teaming (Part 2)
    attacker_model: str = Field(default="llama-3.3-70b-versatile", alias="ATTACKER_MODEL")
    # Judge model used when LLM secondary evaluation is enabled
    judge_model: str = "llama-3.3-70b-versatile"

    # Attacker configuration (Part 2)
    default_attack_budget: int = 8
    default_initial_candidates: int = 4
    api_call_warning_threshold: int = 40

    # Rate Limiting (Groq free tier default: 25 requests/min)
    rate_limit_rpm: int = Field(default=25, alias="RATE_LIMIT_RPM")

    # Local Persistence
    cache_dir: Path = DEFAULT_CACHE_DIR
    database_path: Path = DEFAULT_DB_PATH

    # Server settings
    host: str = Field(default="0.0.0.0", alias="HOST")
    port: int = Field(default=8000, alias="PORT")

    @property
    def is_mock(self) -> bool:
        """Mock mode is active if explicitly set to True or if Groq API key is missing."""
        return self.mock_llm or not bool(self.groq_api_key.strip())

    @property
    def available_models(self) -> list[str]:
        return [self.weak_defender_model, self.strong_defender_model]


settings = Settings()

# Ensure directories exist
settings.cache_dir.mkdir(parents=True, exist_ok=True)
settings.database_path.parent.mkdir(parents=True, exist_ok=True)

