from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Gateway Network Configuration
    GATEWAY_HOST: str = "127.0.0.1"
    GATEWAY_PORT: int = 8000
    GATEWAY_DEBUG: bool = True
    GATEWAY_ADMIN_KEY: str

    # Upstream LLM Configuration
    UPSTREAM_PROVIDER: str = "openai"  # "openai", "ollama", or "mock"
    UPSTREAM_BASE_URL: str = "https://api.openai.com/v1"
    UPSTREAM_API_KEY: str = ""
    UPSTREAM_MODEL: str = "gpt-3.5-turbo"

    # Canary Configuration
    CANARY_TOKEN_PREFIX: str = "CANARY-SECRET-"

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
