import os
from pydantic_settings import BaseSettings
from pydantic import AnyUrl
from typing import List, Optional, Dict, Any
from dotenv import load_dotenv
import logging
import logging.config
import json
from pathlib import Path

# Load environment variables from .env file
load_dotenv()


class Settings(BaseSettings):
    # Application Configuration
    PROJECT_NAME: str = "eCyber"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Comprehensive Network Security Monitoring System"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    # Server Configuration
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", 8000))
    WORKERS: int = int(os.getenv("WORKERS", 1))
    RELOAD: bool = DEBUG

    # Database Configuration (SQLite)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./cyberwatch.db")
    DB_POOL_SIZE: int = int(os.getenv("DB_POOL_SIZE", 5))
    DB_MAX_OVERFLOW: int = int(os.getenv("DB_MAX_OVERFLOW", 10))
    DB_ECHO: bool = DEBUG  # Show SQL queries in debug mode

    # Security Configuration
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-key-change-me!")
    ALLOWED_HOSTS: List[str] = json.loads(os.getenv("ALLOWED_HOSTS", '["*"]'))
    CORS_ORIGINS: List[str] = json.loads(os.getenv("CORS_ORIGINS", '["*"]'))
    WS_TOKEN: str = os.getenv("WS_TOKEN", "websocket-secret-token")

    # SSL Configuration
    USE_SSL: bool = os.getenv("USE_SSL", "false").lower() == "true"
    SSL_CERT_PATH: Optional[str] = os.getenv("SSL_CERT_PATH")
    SSL_KEY_PATH: Optional[str] = os.getenv("SSL_KEY_PATH")
    SSL_CA_PATH: Optional[str] = os.getenv("SSL_CA_PATH")

    # Monitoring Configuration
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT: str = os.getenv("LOG_FORMAT", "json")
    PROMETHEUS_ENABLED: bool = os.getenv("PROMETHEUS_ENABLED", "true").lower() == "true"

    # Network Monitoring Configuration
    MONITOR_INTERFACE: str = os.getenv("MONITOR_INTERFACE", "eth0")
    CAPTURE_FILTER: str = os.getenv("CAPTURE_FILTER", "tcp or udp or icmp")
    PORT_SCAN_THRESHOLD: int = int(os.getenv("PORT_SCAN_THRESHOLD", 5))
    HOST_SCAN_THRESHOLD: int = int(os.getenv("HOST_SCAN_THRESHOLD", 10))

    # Authentication
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "changeme")
    JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", 30))

    # File paths
    DB_FILE_PATH: str = os.getenv("DB_FILE_PATH", "./cyberwatch.db")
    LOG_DIR: str = os.getenv("LOG_DIR", "./logs")

    class Config:
        case_sensitive = True
        env_file = ".env"
        env_file_encoding = "utf-8"


def get_logging_config(settings: Settings) -> Dict[str, Any]:
    """Generate logging configuration based on settings"""
    # Ensure log directory exists
    Path(settings.LOG_DIR).mkdir(parents=True, exist_ok=True)

    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json" if settings.LOG_FORMAT == "json" else "standard": {
                "()": (
                    "pythonjsonlogger.jsonlogger.JsonFormatter"
                    if settings.LOG_FORMAT == "json"
                    else "logging.Formatter"
                ),
                "fmt": "%(asctime)s %(levelname)s %(name)s %(message)s",
                "datefmt": "%Y-%m-%dT%H:%M:%SZ",
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "json" if settings.LOG_FORMAT == "json" else "standard",
                "stream": "ext://sys.stdout",
            },
            "file": {
                "class": "logging.handlers.RotatingFileHandler",
                "formatter": "json" if settings.LOG_FORMAT == "json" else "standard",
                "filename": f"{settings.LOG_DIR}/cyberwatch.log",
                "maxBytes": 10485760,  # 10MB
                "backupCount": 5,
                "encoding": "utf8",
            },
        },
        "loggers": {
            "": {  # root logger
                "handlers": ["console", "file"],
                "level": settings.LOG_LEVEL,
                "propagate": False,
            },
            "uvicorn.error": {
                "level": settings.LOG_LEVEL,
                "handlers": ["console"],
                "propagate": False,
            },
            "uvicorn.access": {
                "level": settings.LOG_LEVEL,
                "handlers": ["console"],
                "propagate": False,
            },
        },
    }


def ensure_db_exists(db_path: str):
    """Ensure SQLite database file exists and is writable"""
    try:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        if not Path(db_path).exists():
            Path(db_path).touch()
            logging.info(f"Created new SQLite database at {db_path}")
    except Exception as e:
        logging.error(f"Failed to initialize SQLite database: {str(e)}")
        raise


# Initialize settings
settings = Settings()

# Ensure database file exists
ensure_db_exists(settings.DB_FILE_PATH)

# Configure logging
logging_config = get_logging_config(settings)
logging.config.dictConfig(logging_config)

# Log important settings (masking sensitive ones)
logging.info(f"Starting {settings.PROJECT_NAME} v{settings.VERSION}")
logging.info(f"Environment: {settings.ENVIRONMENT}")
logging.info(f"Debug mode: {settings.DEBUG}")
logging.info(f"Database: SQLite at {settings.DB_FILE_PATH}")
logging.info(f"Allowed hosts: {settings.ALLOWED_HOSTS}")
logging.info(f"CORS origins: {settings.CORS_ORIGINS}")
logging.info(f"SSL enabled: {settings.USE_SSL}")
