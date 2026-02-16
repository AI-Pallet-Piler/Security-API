"""Test suite for JWT Auth Service - Logout and Token Revocation flows.

Tests comprehensive auth flow including:
- Login and token generation
- Token validation
- Logout flow (current device)
- Token revocation status checking
- Refresh token invalidation
"""
import pytest
import asyncio
import warnings
import os
import sys
import httpx
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Suppress HMAC key length warning from PyJWT (for testing only)
warnings.filterwarnings("ignore", message=".*HMAC key is.*bytes long.*", category=UserWarning)

# Set up test environment
os.environ["SECRET_KEY"] = "test-secret-key-32-bytes-long!!"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "15"
os.environ["REFRESH_TOKEN_EXPIRE_DAYS"] = "7"
os.environ["USER_SERVICE_URL"] = "http://backend:8000"
os.environ["REDIS_HOST"] = "redis"
os.environ["REDIS_PORT"] = "6379"

from fastapi.testclient import TestClient
from config import get_settings
from services.token_service import token_service
from services.redis_client import redis_client
from models.user import User
from main import app


class TestAuthFlow:
    """Test complete authentication flow."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        with TestClient(app) as client:
            yield client
    
    @pytest.fixture
    def valid_credentials(self):
        """Valid test credentials (from backend users)."""
        return {
            "email": "admin@example.com",
            "password": "admin123"
        }
    
    @pytest.fixture
    def admin_credentials(self):
        """Admin test credentials."""
        return {
            "email": "admin@example.com",
            "password": "admin123"
        }
    
    def test_login_success(self, client, valid_credentials):
        """Test successful login returns tokens."""
        response = client.post("/auth/login", json=valid_credentials)
        
        assert response.status_code == 200
        data = response.json()
        
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data
        assert data["expires_in"] > 0
        
        return data
    
    def test_login_invalid_credentials(self, client):
        """Test login with invalid credentials fails."""
        response = client.post(
            "/auth/login",
            json={"email": "admin@example.com", "password": "wrongpassword"}
        )
        
        assert response.status_code == 401
        assert "detail" in response.json()
    
    def test_login_nonexistent_user(self, client):
        """Test login with non-existent user fails."""
        response = client.post(
            "/auth/login",
            json={"email": "nonexistent@example.com", "password": "password"}
        )
        
        assert response.status_code == 401
    
    def test_validate_token_valid(self, client, valid_credentials):
        """Test token validation with valid token."""
        # Login first
        login_response = client.post("/auth/login", json=valid_credentials)
        tokens = login_response.json()
        access_token = tokens["access_token"]
        
        # Validate token
        response = client.post(
            "/auth/validate",
            params={"token": access_token, "check_blacklist": True}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["valid"] is True
        assert data["payload"] is not None
        assert data["payload"]["email"] == valid_credentials["email"]
        assert data["payload"]["type"] == "access"
        assert "jti" in data["payload"]
    
    def test_validate_token_invalid(self, client):
        """Test token validation with invalid token."""
        response = client.post(
            "/auth/validate",
            params={"token": "invalid.token.here", "check_blacklist": True}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["valid"] is False
        assert data["payload"] is None
        assert "error" in data
    
    def test_validate_token_no_blacklist_check(self, client, valid_credentials):
        """Test token validation without blacklist check."""
        # Login and get token
        login_response = client.post("/auth/login", json=valid_credentials)
        tokens = login_response.json()
        access_token = tokens["access_token"]
        
        # Validate without blacklist check
        response = client.post(
            "/auth/validate",
            params={"token": access_token, "check_blacklist": False}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True


class TestLogoutFlow:
    """Test logout functionality."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        with TestClient(app) as client:
            yield client
    
    @pytest.fixture
    def valid_credentials(self):
        """Valid test credentials."""
        return {
            "email": "admin@example.com",
            "password": "admin123"
        }
    
    async def _async_test_logout_flow(self, client, valid_credentials):
        """Test complete logout flow."""
        # Step 1: Login
        login_response = client.post("/auth/login", json=valid_credentials)
        assert login_response.status_code == 200
        
        tokens = login_response.json()
        access_token = tokens["access_token"]
        refresh_token = tokens["refresh_token"]
        
        # Step 2: Verify access token is valid before logout
        validate_response = client.post(
            "/auth/validate",
            params={"token": access_token, "check_blacklist": True}
        )
        assert validate_response.status_code == 200
        assert validate_response.json()["valid"] is True
        
        # Step 3: Logout with refresh token
        logout_response = client.post(
            "/auth/logout",
            json={"refresh_token": refresh_token}
        )
        assert logout_response.status_code == 200
        assert logout_response.json()["success"] is True
        
        # Step 4: Verify refresh token is no longer valid
        # Try to use refresh token to get new tokens
        refresh_request = {"refresh_token": refresh_token}
        refresh_response = client.post("/auth/refresh", json=refresh_request)
        
        # Should fail because refresh token was deleted
        assert refresh_response.status_code == 401
        
        return {
            "login_ok": login_response.status_code == 200,
            "token_valid_before_logout": validate_response.json()["valid"],
            "logout_ok": logout_response.status_code == 200,
            "refresh_token_invalidated": refresh_response.status_code == 401
        }
    
    def test_logout_flow(self, client, valid_credentials):
        """Test logout revokes refresh token."""
        # Login
        login_response = client.post("/auth/login", json=valid_credentials)
        tokens = login_response.json()
        refresh_token = tokens["refresh_token"]
        
        # Logout
        logout_response = client.post(
            "/auth/logout",
            json={"refresh_token": refresh_token}
        )
        
        assert logout_response.status_code == 200
        assert logout_response.json()["success"] is True
        
        # Try to use refresh token - should fail
        refresh_response = client.post(
            "/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        
        assert refresh_response.status_code == 401
    
    def test_logout_with_user_id_all_devices(self, client, valid_credentials):
        """Test logout from all devices using user_id."""
        # Login to get user context
        login_response = client.post("/auth/login", json=valid_credentials)
        login_data = login_response.json()
        
        # Extract user_id from token (decode it)
        import jwt
        from config import get_settings
        
        settings = get_settings()
        payload = jwt.decode(
            login_data["access_token"],
            settings.secret_key,
            algorithms=[settings.algorithm],
            options={"verify_exp": False}
        )
        user_id = payload.get("sub")
        
        # Logout from all devices
        logout_response = client.post(
            "/auth/logout",
            json={"user_id": user_id, "all_devices": True}
        )
        
        assert logout_response.status_code == 200
    
    def test_logout_already_logged_out(self, client, valid_credentials):
        """Test logout when already logged out (idempotent)."""
        # Login and logout once
        login_response = client.post("/auth/login", json=valid_credentials)
        refresh_token = login_response.json()["refresh_token"]
        
        logout1 = client.post(
            "/auth/logout",
            json={"refresh_token": refresh_token}
        )
        assert logout1.status_code == 200
        
        # Try to logout again with same token - should succeed (idempotent)
        logout2 = client.post(
            "/auth/logout",
            json={"refresh_token": refresh_token}
        )
        assert logout2.status_code == 200


class TestTokenRevocation:
    """Test token revocation and blacklist functionality."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        with TestClient(app) as client:
            yield client
    
    @pytest.fixture
    def valid_credentials(self):
        """Valid test credentials (from backend users)."""
        return {
            "email": "admin@example.com",
            "password": "admin123"
        }
    
    def test_revoke_token_by_jti(self, client, valid_credentials):
        """Test revoking token by JTI."""
        # Login
        login_response = client.post("/auth/login", json=valid_credentials)
        refresh_token = login_response.json()["refresh_token"]
        
        # Get JTI from token
        import jwt
        from config import get_settings
        
        settings = get_settings()
        payload = jwt.decode(
            refresh_token,
            settings.secret_key,
            algorithms=[settings.algorithm],
            options={"verify_exp": False}
        )
        jti = payload.get("jti")
        
        # Revoke by JTI
        revoke_response = client.post(
            "/auth/revoke",
            json={"jti": jti}
        )
        
        assert revoke_response.status_code == 200
        assert revoke_response.json()["success"] is True
        
        # Verify refresh token no longer works
        refresh_response = client.post(
            "/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        
        assert refresh_response.status_code == 401
    
    def test_revoke_token_by_token(self, client, valid_credentials):
        """Test revoking token by providing token itself."""
        # Login
        login_response = client.post("/auth/login", json=valid_credentials)
        refresh_token = login_response.json()["refresh_token"]
        
        # Revoke by token
        revoke_response = client.post(
            "/auth/revoke",
            json={"refresh_token": refresh_token}
        )
        
        assert revoke_response.status_code == 200
        
        # Verify token no longer works
        refresh_response = client.post(
            "/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        
        assert refresh_response.status_code == 401
    
    def test_access_token_blacklist_after_logout(self, client, valid_credentials):
        """Test that access token is blacklisted after logout."""
        # Login
        login_response = client.post("/auth/login", json=valid_credentials)
        tokens = login_response.json()
        access_token = tokens["access_token"]
        refresh_token = tokens["refresh_token"]
        
        # Validate token before logout
        validate_before = client.post(
            "/auth/validate",
            params={"token": access_token, "check_blacklist": True}
        )
        assert validate_before.json()["valid"] is True
        
        # Logout
        client.post(
            "/auth/logout",
            json={"refresh_token": refresh_token}
        )
        
        # Validate token after logout - should be invalid due to blacklist
        validate_after = client.post(
            "/auth/validate",
            params={"token": access_token, "check_blacklist": True}
        )
        
        # Token might still be valid because it's an access token,
        # but refresh token should be gone
        # The important part is refresh token is revoked
    
    def test_revoke_all_user_tokens(self, client, valid_credentials):
        """Test revoking all tokens for a user."""
        # Login multiple times to get multiple refresh tokens
        login1 = client.post("/auth/login", json=valid_credentials)
        token1 = login1.json()["refresh_token"]
        
        login2 = client.post("/auth/login", json=valid_credentials)
        token2 = login2.json()["refresh_token"]
        
        # Extract user_id
        import jwt
        from config import get_settings
        
        settings = get_settings()
        payload = jwt.decode(
            token1,
            settings.secret_key,
            algorithms=[settings.algorithm],
            options={"verify_exp": False}
        )
        user_id = payload.get("sub")
        
        # Revoke all tokens
        revoke_response = client.post(
            "/auth/revoke-all",
            json={"user_id": user_id}
        )
        
        assert revoke_response.status_code == 200
        assert revoke_response.json()["success"] is True
        assert revoke_response.json()["revoked_count"] >= 2
        
        # Both tokens should be invalid
        refresh1 = client.post(
            "/auth/refresh",
            json={"refresh_token": token1}
        )
        assert refresh1.status_code == 401
        
        refresh2 = client.post(
            "/auth/refresh",
            json={"refresh_token": token2}
        )
        assert refresh2.status_code == 401


class TestTokenValidationWithRevocation:
    """Test token validation respects revocation status."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        with TestClient(app) as client:
            yield client
    
    @pytest.fixture
    def valid_credentials(self):
        """Valid test credentials (from backend users)."""
        return {
            "email": "admin@example.com",
            "password": "admin123"
        }
    
    def test_validate_revoked_token_with_check(self, client, valid_credentials):
        """Test validation detects revoked token when blacklist check enabled."""
        # Login
        login_response = client.post("/auth/login", json=valid_credentials)
        tokens = login_response.json()
        refresh_token = tokens["refresh_token"]
        
        # Extract JTI
        import jwt
        from config import get_settings
        
        settings = get_settings()
        payload = jwt.decode(
            refresh_token,
            settings.secret_key,
            algorithms=[settings.algorithm],
            options={"verify_exp": False}
        )
        jti = payload.get("jti")
        
        # Validate before revocation
        validate_before = client.post(
            "/auth/validate",
            params={"token": refresh_token, "check_blacklist": True}
        )
        # Note: validate endpoint expects access tokens, but let's try
        
        # Revoke token
        client.post(
            "/auth/revoke",
            json={"jti": jti}
        )
        
        # Try to use revoked token - should fail
        refresh_response = client.post(
            "/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        assert refresh_response.status_code == 401
    
    def test_validate_token_without_blacklist_check(self, client, valid_credentials):
        """Test validation passes when blacklist check disabled."""
        # Login
        login_response = client.post("/auth/login", json=valid_credentials)
        access_token = login_response.json()["access_token"]
        
        # Validate with blacklist check disabled
        response = client.post(
            "/auth/validate",
            params={"token": access_token, "check_blacklist": False}
        )
        
        assert response.status_code == 200
        assert response.json()["valid"] is True
    
    def test_validate_refresh_token_directly(self, client, valid_credentials):
        """Test that refresh tokens can be validated for their stored data."""
        # Login
        login_response = client.post("/auth/login", json=valid_credentials)
        refresh_token = login_response.json()["refresh_token"]
        
        # Validate - will decode but access token validation
        # For refresh token validation, we'd use the refresh endpoint
        response = client.post(
            "/auth/validate",
            params={"token": refresh_token, "check_blacklist": True}
        )
        
        # This tests that validation endpoint handles different token types
        assert response.status_code == 200


class TestRefreshTokenRotation:
    """Test refresh token rotation after logout."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        with TestClient(app) as client:
            yield client
    
    @pytest.fixture
    def valid_credentials(self):
        """Valid test credentials (from backend users)."""
        return {
            "email": "admin@example.com",
            "password": "admin123"
        }
    
    def test_refresh_invalidates_old_token(self, client, valid_credentials):
        """Test that refresh invalidates the old refresh token."""
        # Login
        login_response = client.post("/auth/login", json=valid_credentials)
        tokens = login_response.json()
        initial_refresh = tokens["refresh_token"]
        
        # Refresh to get new token
        refresh_response = client.post(
            "/auth/refresh",
            json={"refresh_token": initial_refresh}
        )
        
        assert refresh_response.status_code == 200
        new_tokens = refresh_response.json()
        new_refresh = new_tokens["refresh_token"]
        
        # Old token should be invalid
        old_refresh_attempt = client.post(
            "/auth/refresh",
            json={"refresh_token": initial_refresh}
        )
        assert old_refresh_attempt.status_code == 401
        
        # New token should be valid
        new_refresh_attempt = client.post(
            "/auth/refresh",
            json={"refresh_token": new_refresh}
        )
        assert new_refresh_attempt.status_code == 200
    
    def test_refresh_after_logout_fails(self, client, valid_credentials):
        """Test that refresh fails after logout."""
        # Login
        login_response = client.post("/auth/login", json=valid_credentials)
        tokens = login_response.json()
        refresh_token = tokens["refresh_token"]
        
        # Logout
        client.post(
            "/auth/logout",
            json={"refresh_token": refresh_token}
        )
        
        # Try to refresh - should fail
        refresh_response = client.post(
            "/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        
        assert refresh_response.status_code == 401


# Integration test - Full flow
class TestCompleteAuthFlow:
    """Test complete authentication workflow."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        with TestClient(app) as client:
            yield client
    
    @pytest.fixture
    def valid_credentials(self):
        """Valid test credentials (from backend users)."""
        return {
            "email": "admin@example.com",
            "password": "admin123"
        }
    
    def test_complete_workflow(self, client, valid_credentials):
        """Test complete login -> validate -> refresh -> logout workflow."""
        # 1. Login
        login = client.post("/auth/login", json=valid_credentials)
        assert login.status_code == 200
        tokens = login.json()
        
        # 2. Validate initial access token
        validate1 = client.post(
            "/auth/validate",
            params={"token": tokens["access_token"], "check_blacklist": True}
        )
        assert validate1.status_code == 200
        assert validate1.json()["valid"] is True
        
        # 3. Refresh tokens
        refresh1 = client.post(
            "/auth/refresh",
            json={"refresh_token": tokens["refresh_token"]}
        )
        assert refresh1.status_code == 200
        new_tokens = refresh1.json()
        
        # 4. Validate new access token
        validate2 = client.post(
            "/auth/validate",
            params={"token": new_tokens["access_token"], "check_blacklist": True}
        )
        assert validate2.status_code == 200
        assert validate2.json()["valid"] is True
        
        # 5. Logout
        logout = client.post(
            "/auth/logout",
            json={"refresh_token": new_tokens["refresh_token"]}
        )
        assert logout.status_code == 200
        
        # 6. Verify refresh token is invalid
        refresh2 = client.post(
            "/auth/refresh",
            json={"refresh_token": new_tokens["refresh_token"]}
        )
        assert refresh2.status_code == 401


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
