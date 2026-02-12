"""Configuration management for JWT Auth Service."""
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # JWT Configuration
    secret_key: str = "your-secret-key-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_seconds: int = 604800  # 7 days = 604800 seconds
    
    # Alternative time units (set ONE of these, leave others as 0)
    refresh_token_expire_hours: int = 0
    refresh_token_expire_days: int = 0
    refresh_token_expire_weeks: int = 0
    
    # External User Service Configuration
    user_service_url: str = "http://localhost:8001"
    user_service_api_key: Optional[str] = None
    user_service_timeout: int = 10
    
    # Redis Configuration
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: Optional[str] = None
    redis_prefix: str = "jwt_auth:"
    
    # Token Storage Configuration
    rotate_refresh_token: bool = True
    max_active_refresh_per_user: int = 5  # 0 = unlimited
    
    # Logging Configuration
    log_level: str = "INFO"
    
    model_config = SettingsConfigDict(
        env_file_encoding="utf-8",
        case_sensitive=False
    )
    
    def get_refresh_token_expire_seconds(self) -> int:
        """Calculate refresh token expiry in seconds from configured units."""
        if self.refresh_token_expire_weeks > 0:
            return self.refresh_token_expire_weeks * 604800  # 7 days per week
        elif self.refresh_token_expire_days > 0:
            return self.refresh_token_expire_days * 86400  # 1 day = 86400 seconds
        elif self.refresh_token_expire_hours > 0:
            return self.refresh_token_expire_hours * 3600  # 1 hour = 3600 seconds
        else:
            return self.refresh_token_expire_seconds


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get application settings."""
    return settings
