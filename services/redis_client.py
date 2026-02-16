"""Redis client for token storage and management."""
import json
import logging
from typing import Optional, List
from datetime import datetime, timezone
import redis.asyncio as redis

from config import get_settings
from models.token import RefreshTokenData, TokenMetadata

logger = logging.getLogger(__name__)


class RedisClient:
    """Async Redis client for token storage."""
    
    def __init__(self):
        self.settings = get_settings()
        self.prefix = self.settings.redis_prefix
        self._client: Optional[redis.Redis] = None
    
    async def connect(self) -> None:
        """Connect to Redis."""
        try:
            self._client = redis.Redis(
                host=self.settings.redis_host,
                port=self.settings.redis_port,
                db=self.settings.redis_db,
                password=self.settings.redis_password,
                decode_responses=True
            )
            # Test connection
            await self._client.ping()
            logger.info(f"Connected to Redis at {self.settings.redis_host}:{self.settings.redis_port}")
        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._client:
            await self._client.close()
            logger.info("Disconnected from Redis")
    
    def _key(self, key_type: str, identifier: str) -> str:
        """Generate prefixed key."""
        return f"{self.prefix}{key_type}:{identifier}"
    
    # Refresh Token Operations
    
    async def store_refresh_token(
        self, 
        jti: str, 
        user_id: str, 
        email: str, 
        role: str,
        device: Optional[str] = None,
        expires_in_seconds: int = 604800  # 7 days
    ) -> None:
        """Store a refresh token in Redis."""
        key = self._key("refresh", jti)
        data = RefreshTokenData(
            user_id=user_id,
            email=email,
            role=role,
            device=device,
            created_at=datetime.now(timezone.utc),
            expires_at=int(datetime.now(timezone.utc).timestamp()) + expires_in_seconds
        )
        await self._client.setex(key, expires_in_seconds, data.model_dump_json())
        logger.debug(f"Stored refresh token: {jti}")
    
    async def get_refresh_token(self, jti: str) -> Optional[RefreshTokenData]:
        """Get refresh token data from Redis."""
        key = self._key("refresh", jti)
        data = await self._client.get(key)
        if data:
            return RefreshTokenData.model_validate_json(data)
        return None
    
    async def delete_refresh_token(self, jti: str) -> bool:
        """Delete a refresh token from Redis."""
        key = self._key("refresh", jti)
        result = await self._client.delete(key)
        logger.debug(f"Deleted refresh token: {jti} (found: {result > 0})")
        return result > 0
    
    async def refresh_token_exists(self, jti: str) -> bool:
        """Check if a refresh token exists."""
        key = self._key("refresh", jti)
        return await self._client.exists(key) > 0
    
    # Blacklist Operations
    
    async def blacklist_token(
        self, 
        jti: str, 
        expires_in_seconds: int = 900  # 15 minutes
    ) -> None:
        """Add a token to the blacklist."""
        key = self._key("blacklist", jti)
        await self._client.setex(key, expires_in_seconds, "revoked")
        logger.debug(f"Blacklisted token: {jti}")
    
    async def is_blacklisted(self, jti: str) -> bool:
        """Check if a token is blacklisted."""
        key = self._key("blacklist", jti)
        return await self._client.exists(key) > 0
    
    # User Ban Operations
    
    async def ban_user(
        self, 
        user_id: str, 
        reason: str, 
        duration_minutes: int = 0
    ) -> int:
        """Ban a user."""
        key = self._key("banned", user_id)
        expires_at = 0 if duration_minutes == 0 else int(datetime.now(timezone.utc).timestamp()) + (duration_minutes * 60)
        data = {
            "reason": reason,
            "expires_at": expires_at,
            "banned_at": datetime.now(timezone.utc).isoformat()
        }
        
        if duration_minutes == 0:
            # Permanent ban
            await self._client.set(key, json.dumps(data))
            ttl = -1
        else:
            await self._client.setex(key, duration_minutes * 60, json.dumps(data))
            ttl = duration_minutes * 60
        
        logger.info(f"Banned user: {user_id} (duration: {ttl}s)")
        return expires_at
    
    async def unban_user(self, user_id: str) -> bool:
        """Unban a user."""
        key = self._key("banned", user_id)
        result = await self._client.delete(key)
        logger.info(f"Unbanned user: {user_id}")
        return result > 0
    
    async def is_user_banned(self, user_id: str) -> tuple[bool, Optional[str]]:
        """Check if a user is banned."""
        key = self._key("banned", user_id)
        data = await self._client.get(key)
        if data:
            ban_data = json.loads(data)
            return True, ban_data.get("reason")
        return False, None
    
    # User Token Management
    
    async def revoke_all_user_tokens(self, user_id: str) -> int:
        """Revoke all refresh tokens for a user."""
        pattern = self._key("refresh", f"*:{user_id}")
        count = 0
        
        # Note: This is a simplified implementation
        # In production, you might want to maintain a user -> tokens index
        async for key in self._client.scan_iter(match=f"{self.prefix}refresh:*"):
            data = await self._client.get(key)
            if data:
                token_data = json.loads(data)
                if token_data.get("user_id") == user_id:
                    jti = key.split(":")[-1]
                    await self._client.delete(key)
                    # Also blacklist
                    await self.blacklist_token(jti)
                    count += 1
        
        logger.info(f"Revoked {count} tokens for user: {user_id}")
        return count
    
    async def get_user_refresh_tokens(self, user_id: str) -> List[TokenMetadata]:
        """Get all active refresh tokens for a user."""
        tokens = []
        async for key in self._client.scan_iter(match=f"{self.prefix}refresh:*"):
            data = await self._client.get(key)
            if data:
                token_data = json.loads(data)
                if token_data.get("user_id") == user_id:
                    jti = key.split(":")[-1]
                    tokens.append(TokenMetadata(
                        jti=jti,
                        user_id=user_id,
                        type="refresh",
                        created_at=datetime.fromisoformat(token_data.get("created_at", datetime.now(timezone.utc).isoformat())),
                        expires_at=token_data.get("expires_at", 0)
                    ))
        return tokens


# Global Redis client instance
redis_client = RedisClient()
