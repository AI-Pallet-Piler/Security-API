"""External user service client for authentication."""
import logging
from typing import Optional
import httpx

from config import get_settings
from models.user import User

logger = logging.getLogger(__name__)


class UserServiceClient:
    """Client for external user service integration."""
    
    def __init__(self):
        self.settings = get_settings()
        self.base_url = self.settings.user_service_url
        self.timeout = self.settings.user_service_timeout
        self.api_key = self.settings.user_service_api_key
    
    def _get_headers(self) -> dict:
        """Get headers for API requests."""
        headers = {
            "Content-Type": "application/json"
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers
    
    async def validate_credentials(self, email: str, password: str) -> Optional[User]:
        """
        Validate user credentials against external service.
        
        Args:
            email: User email
            password: Plain text password
            
        Returns:
            User object if valid, None if invalid
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/auth/validate",
                    json={"email": email, "password": password},
                    headers=self._get_headers()
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return User(
                        id=data.get("id", ""),
                        email=data.get("email", email),
                        role=data.get("role", "user"),
                        hashed_password=data.get("hashed_password")
                    )
                elif response.status_code == 401:
                    logger.debug(f"Invalid credentials for user: {email}")
                    return None
                else:
                    logger.error(f"User service error: {response.status_code} - {response.text}")
                    return None
                    
        except httpx.RequestError as e:
            logger.error(f"Failed to connect to user service: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in user service client: {e}")
            return None
    
    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        """
        Get user by ID from external service.
        
        Args:
            user_id: User ID
            
        Returns:
            User object if found, None if not found
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/api/users/{user_id}",
                    headers=self._get_headers()
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return User(
                        id=data.get("id", user_id),
                        email=data.get("email", ""),
                        role=data.get("role", "user"),
                        hashed_password=data.get("hashed_password")
                    )
                elif response.status_code == 404:
                    logger.debug(f"User not found: {user_id}")
                    return None
                else:
                    logger.error(f"User service error: {response.status_code}")
                    return None
                    
        except httpx.RequestError as e:
            logger.error(f"Failed to connect to user service: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in user service client: {e}")
            return None
    
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email from external service.
        
        Args:
            email: User email
            
        Returns:
            User object if found, None if not found
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/api/users/by-email",
                    params={"email": email},
                    headers=self._get_headers()
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return User(
                        id=data.get("id", ""),
                        email=data.get("email", email),
                        role=data.get("role", "user"),
                        hashed_password=data.get("hashed_password")
                    )
                elif response.status_code == 404:
                    logger.debug(f"User not found: {email}")
                    return None
                else:
                    logger.error(f"User service error: {response.status_code}")
                    return None
                    
        except httpx.RequestError as e:
            logger.error(f"Failed to connect to user service: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in user service client: {e}")
            return None
    
    async def get_user_by_badge(self, badge_number: str) -> Optional[User]:
        """
        Get user by badge number from external service.
        
        Args:
            badge_number: User badge number
            
        Returns:
            User object if found, None if not found
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/api/v1/users/badge/{badge_number}",
                    headers=self._get_headers()
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return User(
                        id=str(data.get("user_id", "")),
                        email=data.get("email", ""),
                        role=data.get("role", "user"),
                        badge_number=data.get("badge_number", badge_number),
                        hashed_password=data.get("hashed_password")
                    )
                elif response.status_code == 404:
                    logger.debug(f"User not found with badge: {badge_number}")
                    return None
                else:
                    logger.error(f"User service error: {response.status_code}")
                    return None
                    
        except httpx.RequestError as e:
            logger.error(f"Failed to connect to user service: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in user service client: {e}")
            return None


# Global user service client instance
user_service_client = UserServiceClient()
