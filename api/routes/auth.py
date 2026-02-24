"""Authentication API routes."""
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.responses import JSONResponse

from config import get_settings
from models.user import (
    UserLogin,
    UserBadgeLogin,
    TokenResponse,
    ValidateTokenResponse,
    ErrorResponse
)
from models.token import (
    RefreshTokenRequest,
    RevokeTokenRequest,
    LogoutRequest,
    RevokeAllRequest,
    BanUserRequest,
    BanStatusResponse
)
from services.token_service import token_service
from services.redis_client import redis_client
from services.user_service_client import user_service_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/v1", tags=["Authentication"])


@router.post(
    "/login",
    response_model=TokenResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid credentials"}
    },
    summary="User login",
    description="Authenticate user and receive access and refresh tokens"
)
async def login(request: UserLogin) -> TokenResponse:
    """
    Authenticate user with email and password.
    
    Returns:
        TokenResponse with access_token, refresh_token, and expiration
    """
    # Validate credentials against external user service
    user = await user_service_client.validate_credentials(
        email=request.email,
        password=request.password
    )
    
    if user is None:
        logger.warning(f"Failed login attempt for: {request.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Create tokens
    settings = get_settings()
    access_token, access_jti = token_service.create_access_token(
        user_id=user.id,
        email=user.email,
        role=user.role
    )
    refresh_token, refresh_jti = token_service.create_refresh_token(
        user_id=user.id
    )
    
    # Store refresh token in Redis
    await redis_client.store_refresh_token(
        jti=refresh_jti,
        user_id=user.id,
        email=user.email,
        role=user.role,
        expires_in_seconds=settings.refresh_token_expire_days * 86400
    )
    
    logger.info(f"User logged in: {user.email} (role: {user.role})")
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60
    )


@router.post(
    "/login-badge",
    response_model=TokenResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid badge number"}
    },
    summary="Badge-based login for pickers",
    description="Authenticate picker with badge number and receive access and refresh tokens"
)
async def login_badge(request: UserBadgeLogin) -> TokenResponse:
    """
    Authenticate user with badge number (for pickers).
    
    Returns:
        TokenResponse with access_token, refresh_token, and expiration
    """
    # Get user by badge number from external user service
    user = await user_service_client.get_user_by_badge(
        badge_number=request.badge_number
    )
    
    if user is None:
        logger.warning(f"Failed badge login attempt for: {request.badge_number}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid badge number"
        )
    
    # Create tokens
    settings = get_settings()
    access_token, access_jti = token_service.create_access_token(
        user_id=user.id,
        email=user.email,
        role=user.role
    )
    refresh_token, refresh_jti = token_service.create_refresh_token(
        user_id=user.id
    )
    
    # Store refresh token in Redis
    await redis_client.store_refresh_token(
        jti=refresh_jti,
        user_id=user.id,
        email=user.email,
        role=user.role,
        expires_in_seconds=settings.refresh_token_expire_days * 86400
    )
    
    logger.info(f"Picker logged in via badge: {request.badge_number} (user: {user.email}, role: {user.role})")
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid refresh token"}
    },
    summary="Refresh access token",
    description="Use refresh token to get new access and refresh tokens"
)
async def refresh_token(request: RefreshTokenRequest) -> TokenResponse:
    """
    Refresh access token using refresh token.
    
    Returns:
        TokenResponse with new access_token, refresh_token, and expiration
    """
    # Validate refresh token
    payload = await token_service.validate_refresh_token(request.refresh_token)
    
    if payload is None:
        logger.warning("Invalid refresh token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    
    user_id = payload.get("sub")
    jti = payload.get("jti")
    
    # Get user details
    user = await user_service_client.get_user_by_id(user_id)
    if user is None:
        logger.error(f"User not found for refresh: {user_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    # Rotate tokens
    access_token, refresh_token, new_jti = await token_service.rotate_refresh_token(
        old_refresh_token=request.refresh_token,
        user_id=user.id,
        email=user.email,
        role=user.role
    )
    
    settings = get_settings()
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60
    )


@router.post(
    "/validate",
    response_model=ValidateTokenResponse,
    summary="Validate token",
    description="Validate a JWT token and return its payload"
)
async def validate_token(
    token: str,
    check_blacklist: bool = True
) -> ValidateTokenResponse:
    """
    Validate a JWT token.
    
    Args:
        token: The JWT token to validate
        check_blacklist: Whether to check if token is blacklisted
        
    Returns:
        ValidateTokenResponse with validity and payload
    """
    payload = await token_service.verify_token(token, check_blacklist=check_blacklist)
    
    if payload is None:
        return ValidateTokenResponse(
            valid=False,
            payload=None,
            error="Invalid or expired token"
        )
    
    # Remove sensitive fields
    safe_payload = {
        "sub": payload.get("sub"),
        "email": payload.get("email"),
        "role": payload.get("role"),
        "jti": payload.get("jti"),
        "type": payload.get("type"),
        "exp": payload.get("exp"),
        "iat": payload.get("iat")
    }
    
    return ValidateTokenResponse(
        valid=True,
        payload=safe_payload
    )


@router.post(
    "/logout",
    responses={
        200: {"description": "Successfully logged out"}
    },
    summary="Logout",
    description="Logout from current device (revoke refresh token)"
)
async def logout(request: LogoutRequest) -> JSONResponse:
    """
    Logout from current device.
    
    If refresh_token is provided, it will be revoked.
    If all_devices is True, all user tokens will be revoked.
    """
    # Check if user is banned
    if request.user_id:
        is_banned, _ = await redis_client.is_user_banned(request.user_id)
        if is_banned:
            # Already banned, just return success
            return JSONResponse(
                status_code=200,
                content={"success": True, "message": "Already logged out"}
            )
    
    if request.all_devices and request.user_id:
        # Revoke all user tokens
        count = await redis_client.revoke_all_user_tokens(request.user_id)
        logger.info(f"Logged out all devices for user: {request.user_id} ({count} tokens revoked)")
    elif request.refresh_token:
        # Revoke specific token
        payload = token_service.decode_token(request.refresh_token)
        if payload:
            jti = payload.get("jti")
            await redis_client.delete_refresh_token(jti)
            await redis_client.blacklist_token(jti)
            logger.info(f"Logged out token: {jti}")
    
    return JSONResponse(
        status_code=200,
        content={"success": True, "message": "Successfully logged out"}
    )


@router.post(
    "/revoke",
    responses={
        200: {"description": "Token revoked successfully"}
    },
    summary="Revoke token",
    description="Revoke a specific refresh token by JTI"
)
async def revoke_token(request: RevokeTokenRequest) -> JSONResponse:
    """
    Revoke a specific refresh token.
    
    Can provide either refresh_token or jti.
    """
    jti = None
    
    if request.jti:
        jti = request.jti
    elif request.refresh_token:
        payload = token_service.decode_token(request.refresh_token)
        if payload:
            jti = payload.get("jti")
    
    if jti:
        # Delete from Redis
        deleted = await redis_client.delete_refresh_token(jti)
        # Add to blacklist
        await redis_client.blacklist_token(jti)
        
        logger.info(f"Token revoked: {jti} (deleted: {deleted})")
    
    return JSONResponse(
        status_code=200,
        content={"success": True, "message": "Token revoked successfully"}
    )


@router.post(
    "/revoke-all",
    responses={
        200: {"description": "All tokens revoked"}
    },
    summary="Revoke all user tokens",
    description="Revoke all refresh tokens for a specific user"
)
async def revoke_all_tokens(request: RevokeAllRequest) -> JSONResponse:
    """
    Revoke all refresh tokens for a user.
    """
    count = await redis_client.revoke_all_user_tokens(request.user_id)
    
    logger.info(f"Revoked {count} tokens for user: {request.user_id}")
    
    return JSONResponse(
        status_code=200,
        content={
            "success": True, 
            "message": f"Revoked {count} tokens",
            "revoked_count": count
        }
    )


# Admin endpoints

@router.post(
    "/ban-user",
    responses={
        200: {"description": "User banned successfully"}
    },
    summary="Ban user",
    description="Ban a user (admin only)"
)
async def ban_user(request: BanUserRequest) -> JSONResponse:
    """
    Ban a user, revoking all their tokens.
    
    This is an admin endpoint that should be protected in production.
    """
    expires_at = await redis_client.ban_user(
        user_id=request.user_id,
        reason=request.reason,
        duration_minutes=request.duration_minutes
    )
    
    # Revoke all user tokens
    await redis_client.revoke_all_user_tokens(request.user_id)
    
    logger.info(f"User banned: {request.user_id} (reason: {request.reason})")
    
    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "message": "User banned successfully",
            "expires_at": expires_at if request.duration_minutes == 0 else None
        }
    )


@router.get(
    "/ban-status/{user_id}",
    response_model=BanStatusResponse,
    summary="Check ban status",
    description="Check if a user is banned"
)
async def check_ban_status(user_id: str) -> BanStatusResponse:
    """
    Check if a user is currently banned.
    """
    is_banned, reason = await redis_client.is_user_banned(user_id)
    
    return BanStatusResponse(
        banned=is_banned,
        reason=reason
    )
