from pydantic import AnyHttpUrl
from typing import List
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Cybersecurity Monitoring System"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Real-time network threat detection API"
    SQLALCHEMY_DATABASE_URL: str = "sqlite+aiosqlite:///./security.db"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    # For PostgreSQL use:
    # DATABASE_URL: PostgresDsn = "postgresql+asyncpg://user:password@localhost/dbname"

    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:4000 ",
        "http://127.0.0.1:4000",
    ]


    REQUIRE_SOCKET_AUTH: bool = True
    PROJECT_NAME: str = "eCyber"
    NETWORK_INTERFACE: str = "Wi-Fi"  # or your interface
    DEBUG: bool = False
    DOCS: bool = True  # Disable in production
    PRODUCTION: bool = False

    # Redis for production scaling
    REDIS_URL: str = "redis://localhost:6379/0"

    class Config:
        case_sensitive = True
        env_file = ".env"


settings = Settings()
