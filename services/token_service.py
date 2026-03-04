"""Token service for JWT generation and validation."""
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError

from config import get_settings
from models.user import TokenPayload, RefreshPayload
from services.redis_client import redis_client

logger = logging.getLogger(__name__)


class TokenService:
    """Service for JWT token operations."""
    
    def __init__(self):
        self.settings = get_settings()
    
    def _generate_jti(self) -> str:
        """Generate a unique JWT ID."""
        return str(uuid.uuid4())
    
    def create_access_token(
        self, 
        user_id: str, 
        email: str, 
        role: str,
        expires_delta: Optional[timedelta] = None
    ) -> tuple[str, str]:
        """
        Create a new access token.
        
        Returns:
            tuple: (access_token, jti)
        """
        if expires_delta is None:
            expires_delta = timedelta(minutes=self.settings.access_token_expire_minutes)
        
        jti = self._generate_jti()
        now = datetime.now(timezone.utc)
        
        payload = {
            "sub": user_id,
            "email": email,
            "role": role,
            "jti": jti,
            "type": "access",
            "exp": int((now + expires_delta).timestamp()),
            "iat": int(now.timestamp())
        }
        
        access_token = jwt.encode(
            payload, 
            self.settings.secret_key, 
            algorithm=self.settings.algorithm
        )
        
        logger.debug(f"Created access token for user: {user_id}")
        return access_token, jti
    
    def create_refresh_token(
        self, 
        user_id: str,
        expires_delta: Optional[timedelta] = None
    ) -> tuple[str, str]:
        """
        Create a new refresh token.
        
        Returns:
            tuple: (refresh_token, jti)
        """
        if expires_delta is None:
            seconds = self.settings.get_refresh_token_expire_seconds()
            expires_delta = timedelta(seconds=seconds)
        
        jti = self._generate_jti()
        now = datetime.now(timezone.utc)
        
        payload = {
            "sub": user_id,
            "jti": jti,
            "type": "refresh",
            "exp": int((now + expires_delta).timestamp()),
            "iat": int(now.timestamp())
        }
        
        refresh_token = jwt.encode(
            payload, 
            self.settings.secret_key, 
            algorithm=self.settings.algorithm
        )
        
        logger.debug(f"Created refresh token for user: {user_id}")
        return refresh_token, jti
    
    def decode_token(self, token: str) -> Dict[str, Any]:
        """
        Decode a JWT token without verification.
        
        Returns:
            dict: Decoded token payload
        """
        return jwt.decode(
            token, 
            self.settings.secret_key, 
            algorithms=[self.settings.algorithm],
            options={"verify_exp": False}
        )
    
    async def verify_token(self, token: str, check_blacklist: bool = True) -> Optional[Dict[str, Any]]:
        """
        Verify a JWT token.
        
        Args:
            token: The JWT token to verify
            check_blacklist: Whether to check if token is blacklisted
            
        Returns:
            dict: Decoded payload if valid, None if invalid
        """
        try:
            # First decode without verification to get JTI
            payload = jwt.decode(
                token, 
                self.settings.secret_key, 
                algorithms=[self.settings.algorithm],
                options={"verify_exp": False}
            )
            
            jti = payload.get("jti")
            if not jti:
                logger.warning("Token has no JTI")
                return None
            
            # Check blacklist if requested
            if check_blacklist:
                is_blacklisted = await redis_client.is_blacklisted(jti)
                if is_blacklisted:
                    logger.warning(f"Token is blacklisted: {jti}")
                    return None
            
            # Now verify with expiration check
            payload = jwt.decode(
                token, 
                self.settings.secret_key, 
                algorithms=[self.settings.algorithm]
            )
            
            return payload
            
        except ExpiredSignatureError:
            logger.debug("Token has expired")
            return None
        except InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None
    
    async def validate_refresh_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """
        Validate a refresh token against Redis storage.
        
        Returns:
            dict: Token payload if valid, None if invalid
        """
        try:
            payload = jwt.decode(
                refresh_token,
                self.settings.secret_key,
                algorithms=[self.settings.algorithm],
                options={"verify_exp": False}
            )
            
            if payload.get("type") != "refresh":
                logger.warning("Token is not a refresh token")
                return None
            
            jti = payload.get("jti")
            if not jti:
                return None
            
            # Check if token exists in Redis
            token_data = await redis_client.get_refresh_token(jti)
            if not token_data:
                logger.debug(f"Refresh token not found in Redis: {jti}")
                return None
            
            return payload
            
        except InvalidTokenError as e:
            logger.warning(f"Invalid refresh token: {e}")
            return None
    
    async def rotate_refresh_token(
        self, 
        old_refresh_token: str, 
        user_id: str, 
        email: str, 
        role: str
    ) -> tuple[str, str, str]:
        """
        Rotate refresh token: invalidate old, create new.
        
        Returns:
            tuple: (new_access_token, new_refresh_token, new_jti)
        """
        # Get old token payload
        payload = jwt.decode(
            old_refresh_token,
            self.settings.secret_key,
            algorithms=[self.settings.algorithm],
            options={"verify_exp": False}
        )
        old_jti = payload.get("jti")
        
        # Delete old token from Redis
        await redis_client.delete_refresh_token(old_jti)
        
        # Blacklist old access token (if any)
        await redis_client.blacklist_token(old_jti)
        
        # Create new tokens
        access_token, access_jti = self.create_access_token(user_id, email, role)
        refresh_token, refresh_jti = self.create_refresh_token(user_id)
        
        # Store new refresh token
        await redis_client.store_refresh_token(
            jti=refresh_jti,
            user_id=user_id,
            email=email,
            role=role
        )
        
        logger.info(f"Rotated tokens for user: {user_id}")
        return access_token, refresh_token, refresh_jti
    
    def get_token_expiration(self, token: str) -> Optional[int]:
        """Get token expiration timestamp."""
        try:
            payload = jwt.decode(
                token,
                self.settings.secret_key,
                algorithms=[self.settings.algorithm],
                options={"verify_exp": False}
            )
            return payload.get("exp")
        except InvalidTokenError:
            return None


# Global token service instance
token_service = TokenService()
