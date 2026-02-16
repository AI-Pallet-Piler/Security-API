"""Test suite for JWT Auth Service."""
from datetime import datetime, timedelta, timezone

import pytest
import asyncio
import warnings
import os

# Suppress HMAC key length warning from PyJWT (for testing only - not a security issue in tests)
warnings.filterwarnings("ignore", message=".*HMAC key is.*bytes long.*", category=UserWarning)

# Set up test environment
os.environ["SECRET_KEY"] = "test-secret-key-32-bytes-long!!"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "15"
os.environ["REFRESH_TOKEN_EXPIRE_DAYS"] = "7"

from fastapi.testclient import TestClient
from httpx import AsyncClient

from config import get_settings, Settings
from services.token_service import TokenService
from services.redis_client import RedisClient
from services.user_service_client import UserServiceClient
from models.user import User
from main import app


# Fixtures
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def settings():
    """Get test settings."""
    return Settings(
        secret_key="test-secret-key-32-bytes-long!!",
        algorithm="HS256",
        access_token_expire_minutes=15,
        refresh_token_expire_days=7,
        redis_host="localhost",
        redis_port=6379,
        user_service_url="http://localhost:8001"
    )


@pytest.fixture
def token_service(settings):
    """Create token service with test settings."""
    return TokenService()


@pytest.fixture
def mock_user():
    """Create mock user."""
    return User(
        id="test-user-1",
        email="test@example.com",
        role="user",
        hashed_password="hashedpassword"
    )


class TestConfig:
    """Tests for configuration loading."""
    
    def test_default_values(self):
        """Test that default values are set correctly."""
        settings = Settings()
        assert settings.algorithm == "HS256"
        assert settings.access_token_expire_minutes == 15
        assert settings.refresh_token_expire_days == 7
    
    def test_environment_override(self, monkeypatch):
        """Test that environment variables override defaults."""
        monkeypatch.setenv("SECRET_KEY", "env-secret")
        monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
        
        # Reload settings
        from importlib import reload
        import config
        reload(config)
        
        settings = config.get_settings()
        assert settings.secret_key == "env-secret"
        assert settings.access_token_expire_minutes == 30


class TestTokenService:
    """Tests for token generation and validation."""
    
    def test_create_access_token(self, token_service, mock_user):
        """Test access token creation."""
        access_token, jti = token_service.create_access_token(
            user_id=mock_user.id,
            email=mock_user.email,
            role=mock_user.role
        )
        
        assert access_token is not None
        assert isinstance(access_token, str)
        assert jti is not None
        assert isinstance(jti, str)
    
    def test_create_refresh_token(self, token_service, mock_user):
        """Test refresh token creation."""
        refresh_token, jti = token_service.create_refresh_token(
            user_id=mock_user.id
        )
        
        assert refresh_token is not None
        assert isinstance(refresh_token, str)
        assert jti is not None
    
    def test_decode_token(self, token_service, mock_user):
        """Test token decoding."""
        access_token, _ = token_service.create_access_token(
            user_id=mock_user.id,
            email=mock_user.email,
            role=mock_user.role
        )
        
        payload = token_service.decode_token(access_token)
        
        assert payload is not None
        assert payload["sub"] == mock_user.id
        assert payload["email"] == mock_user.email
        assert payload["role"] == mock_user.role
        assert payload["type"] == "access"
    
    def test_token_contains_required_claims(self, token_service, mock_user):
        """Test that tokens contain all required claims."""
        access_token, _ = token_service.create_access_token(
            user_id=mock_user.id,
            email=mock_user.email,
            role=mock_user.role
        )
        
        payload = token_service.decode_token(access_token)
        
        required_claims = ["sub", "email", "role", "jti", "type", "exp", "iat"]
        for claim in required_claims:
            assert claim in payload, f"Missing claim: {claim}"
    
    def test_token_expiration(self, token_service, mock_user):
        """Test that token has correct expiration."""
        access_token, _ = token_service.create_access_token(
            user_id=mock_user.id,
            email=mock_user.email,
            role=mock_user.role
        )
        
        payload = token_service.decode_token(access_token)
        
        exp_timestamp = payload["exp"]
        iat_timestamp = payload["iat"]
        
        # Check that expiration is in the future
        now = datetime.now(timezone.utc).timestamp()
        assert exp_timestamp > now
        
        # Check that expiration matches configured value
        settings = get_settings()
        expected_expires_in = settings.access_token_expire_minutes * 60
        actual_expires_in = exp_timestamp - iat_timestamp
        
        tolerance = 10  # 10 seconds tolerance
        assert abs(actual_expires_in - expected_expires_in) < tolerance
    
    def test_custom_expiration(self, token_service, mock_user):
        """Test custom expiration delta."""
        custom_delta = timedelta(minutes=30)
        
        access_token, _ = token_service.create_access_token(
            user_id=mock_user.id,
            email=mock_user.email,
            role=mock_user.role,
            expires_delta=custom_delta
        )
        
        payload = token_service.decode_token(access_token)
        now = datetime.now(timezone.utc).timestamp()
        exp_timestamp = payload["exp"]
        
        expected_exp = now + (30 * 60)  # 30 minutes
        tolerance = 10  # 10 seconds tolerance
        assert abs(exp_timestamp - expected_exp) < tolerance


class TestAPIRoutes:
    """Tests for API endpoints."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)
    
    def test_root_endpoint(self, client):
        """Test root health check."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "JWT Auth Service"
        assert data["status"] == "running"
    
    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
    
    def test_login_missing_credentials(self, client):
        """Test login with missing credentials."""
        response = client.post("/auth/login", json={})
        assert response.status_code == 422  # Validation error
    
    def test_login_invalid_json(self, client):
        """Test login with invalid JSON."""
        response = client.post(
            "/auth/login",
            content="invalid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422


class TestTokenExpiration:
    """Tests specifically for token expiration."""
    
    def test_access_token_expiration_time(self, token_service, mock_user):
        """Test that access token expires in correct time."""
        settings = get_settings()
        
        access_token, _ = token_service.create_access_token(
            user_id=mock_user.id,
            email=mock_user.email,
            role=mock_user.role
        )
        
        payload = token_service.decode_token(access_token)
        exp = payload["exp"]
        iat = payload["iat"]
        
        # Expiration should be approximately 15 minutes (900 seconds)
        expected_expires_in = settings.access_token_expire_minutes * 60
        actual_expires_in = exp - iat
        
        tolerance = 5  # 5 seconds tolerance
        assert abs(actual_expires_in - expected_expires_in) < tolerance
    
    def test_refresh_token_expiration_time(self, token_service, mock_user):
        """Test that refresh token expires in correct time."""
        settings = get_settings()
        
        refresh_token, _ = token_service.create_refresh_token(
            user_id=mock_user.id
        )
        
        payload = token_service.decode_token(refresh_token)
        exp = payload["exp"]
        iat = payload["iat"]
        
        # Expiration should be approximately 7 days
        expected_expires_in = settings.refresh_token_expire_days * 86400  # seconds in a day
        actual_expires_in = exp - iat
        
        tolerance = 60  # 60 seconds tolerance
        assert abs(actual_expires_in - expected_expires_in) < tolerance
    
    def test_refresh_token_type_claim(self, token_service, mock_user):
        """Test that refresh token has correct type claim."""
        refresh_token, _ = token_service.create_refresh_token(
            user_id=mock_user.id
        )
        
        payload = token_service.decode_token(refresh_token)
        assert payload["type"] == "refresh"
    
    def test_access_token_type_claim(self, token_service, mock_user):
        """Test that access token has correct type claim."""
        access_token, _ = token_service.create_access_token(
            user_id=mock_user.id,
            email=mock_user.email,
            role=mock_user.role
        )
        
        payload = token_service.decode_token(access_token)
        assert payload["type"] == "access"


class TestJTI:
    """Tests for JWT ID (JTI) functionality."""
    
    def test_jti_is_unique(self, token_service, mock_user):
        """Test that each token gets a unique JTI."""
        token1, jti1 = token_service.create_access_token(
            user_id=mock_user.id,
            email=mock_user.email,
            role=mock_user.role
        )
        token2, jti2 = token_service.create_access_token(
            user_id=mock_user.id,
            email=mock_user.email,
            role=mock_user.role
        )
        
        assert jti1 != jti2, "Each token should have a unique JTI"
    
    def test_refresh_token_jti_is_unique(self, token_service, mock_user):
        """Test that each refresh token gets a unique JTI."""
        token1, jti1 = token_service.create_refresh_token(
            user_id=mock_user.id
        )
        token2, jti2 = token_service.create_refresh_token(
            user_id=mock_user.id
        )
        
        assert jti1 != jti2, "Each refresh token should have a unique JTI"
    
    def test_jti_format(self, token_service, mock_user):
        """Test that JTI is a valid UUID."""
        import uuid
        
        _, jti = token_service.create_access_token(
            user_id=mock_user.id,
            email=mock_user.email,
            role=mock_user.role
        )
        
        # Should not raise an exception
        uuid.UUID(jti)


# Run tests with: pytest test_jwt_auth.py -v
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
