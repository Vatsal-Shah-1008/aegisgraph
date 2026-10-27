import os
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseModel):
    APP_NAME: str = "AegisGraph"
    APP_SUBTITLE: str = "Vatsal Shah's Autonomous Recon & Threat Graph Platform"
    VERSION: str = "2.4.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "production")
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    ALLOWED_ORIGINS: list[str] = [
        origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "*").split(",")
    ]
    DEFAULT_DOMAIN: str = os.getenv("DEFAULT_DOMAIN", "example.com")
    # Optional LLM API key for enhanced natural language analysis
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    SOCKET_TIMEOUT: float = 3.5

settings = Settings()
