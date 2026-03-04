"""User model for JWT Auth Service."""
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class User(BaseModel):
    """User model representing authenticated user data."""
    id: str = Field(..., description="User ID from external service")
    email: str = Field(..., description="User email address")
    role: str = Field(..., description="User role for RBAC")
    badge_number: Optional[str] = Field(
        None,
        description="Badge number (for picker identification)"
    )
    hashed_password: Optional[str] = Field(
        None, 
        description="Hashed password (from external service)"
    )
    
    model_config = ConfigDict(from_attributes=True)


class UserLogin(BaseModel):
    """User login request model."""
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="User password")


class UserBadgeLogin(BaseModel):
    """Badge-based login request model for pickers."""
    badge_number: str = Field(..., description="User badge number")


class UserCreate(BaseModel):
    """User creation request model."""
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="User password")
    role: str = Field(default="user", description="User role")


class TokenPayload(BaseModel):
    """JWT token payload model."""
    sub: str = Field(..., description="User ID")
    email: str = Field(..., description="User email")
    role: str = Field(..., description="User role")
    jti: str = Field(..., description="Token ID for revocation")
    type: str = Field(default="access", description="Token type")
    exp: int = Field(..., description="Expiration timestamp")
    iat: int = Field(..., description="Issued at timestamp")


class RefreshPayload(BaseModel):
    """Refresh token payload model."""
    sub: str = Field(..., description="User ID")
    jti: str = Field(..., description="Token ID for revocation")
    type: str = Field(default="refresh", description="Token type")
    exp: int = Field(..., description="Expiration timestamp")
    iat: int = Field(..., description="Issued at timestamp")


class TokenResponse(BaseModel):
    """Token response model."""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="Refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration in seconds")


class ValidateTokenResponse(BaseModel):
    """Token validation response model."""
    valid: bool = Field(..., description="Whether token is valid")
    payload: Optional[dict] = Field(None, description="Decoded token payload")
    error: Optional[str] = Field(None, description="Error message if invalid")


class ErrorResponse(BaseModel):
    """Error response model."""
    detail: str = Field(..., description="Error message")
    code: Optional[str] = Field(None, description="Error code")
