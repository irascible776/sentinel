from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Gateway Network Configuration
    GATEWAY_HOST: str = "127.0.0.1"
    GATEWAY_PORT: int = 8000
    GATEWAY_DEBUG: bool = True
    GATEWAY_ADMIN_KEY: str = "gw-admin-secret-key-dtu138"

    # Upstream LLM Configuration
    UPSTREAM_PROVIDER: str = "gemini"  # "gemini", "mock", "openai", "ollama"
    UPSTREAM_BASE_URL: str = "https://generativelanguage.googleapis.com/v1beta/openai"
    UPSTREAM_API_KEY: str = ""
    UPSTREAM_MODEL: str = "gemini-1.5-flash"

    # Dedicated Google Gemini Configuration
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-1.5-flash"
    GEMINI_BASE_URL: str = "https://generativelanguage.googleapis.com/v1beta/openai"

    # ML & Detection Engine Configuration
    HF_MODEL_NAME: str = "protectai/deberta-v3-base-prompt-injection-v2"
    DETECTION_DEVICE: str = "cpu"
    SLIDING_WINDOW_MINUTES: int = 10
    THREAT_RULES_PATH: str = "core/detection/threat_rules.json"

    # Security Vectors & Canary Configuration
    CANARY_TOKEN_PREFIX: str = "CANARY-SECRET-"
    DATABASE_URL: str = "sqlite:///./gateway.db"
    DASHBOARD_PORT: int = 8501
    AUDIO_SAMPLE_RATE: int = 16000

settings = Settings()

