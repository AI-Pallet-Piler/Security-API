"""Token-related models for JWT Auth Service."""
from typing import Optional
from pydantic import BaseModel, Field
from datetime import datetime


class RefreshTokenData(BaseModel):
    """Refresh token data stored in Redis."""
    user_id: str = Field(..., description="User ID")
    email: str = Field(..., description="User email")
    role: str = Field(..., description="User role")
    device: Optional[str] = Field(None, description="Device identifier")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: int = Field(..., description="Expiration timestamp")


class RefreshTokenRequest(BaseModel):
    """Refresh token request model."""
    refresh_token: str = Field(..., description="Refresh token")


class RevokeTokenRequest(BaseModel):
    """Token revocation request model."""
    refresh_token: Optional[str] = Field(None, description="Token to revoke")
    jti: Optional[str] = Field(None, description="Token ID to revoke")


class RevokeAllRequest(BaseModel):
    """Revoke all tokens request model."""
    user_id: str = Field(..., description="User ID to revoke all tokens for")


class LogoutRequest(BaseModel):
    """Logout request model."""
    refresh_token: Optional[str] = Field(None, description="Refresh token")
    all_devices: bool = Field(default=False, description="Logout from all devices")


class BanUserRequest(BaseModel):
    """Ban user request model (admin only)."""
    user_id: str = Field(..., description="User ID to ban")
    reason: str = Field(..., description="Ban reason")
    duration_minutes: int = Field(default=0, description="Ban duration (0 = permanent)")


class BanStatusResponse(BaseModel):
    """Ban status response model."""
    banned: bool = Field(..., description="Whether user is banned")
    reason: Optional[str] = Field(None, description="Ban reason")
    expires_at: Optional[int] = Field(None, description="Ban expiration timestamp")


class TokenMetadata(BaseModel):
    """Token metadata model."""
    jti: str = Field(..., description="Token ID")
    user_id: str = Field(..., description="User ID")
    type: str = Field(..., description="Token type (access/refresh)")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: int = Field(..., description="Expiration timestamp")
