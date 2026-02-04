"""Mock External User Service for Testing.

This mock service simulates the external user service that the JWT Auth Service
integrates with for authentication.
"""
import logging
import bcrypt
from datetime import datetime
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Mock User Service",
    description="Mock external user service for testing JWT Auth Service",
    version="1.0.0"
)

# Generate fresh bcrypt hashes for test passwords
HASHED_PASSWORD_USER = bcrypt.hashpw(b"testpassword", bcrypt.gensalt()).decode()
HASHED_PASSWORD_ADMIN = bcrypt.hashpw(b"adminpassword", bcrypt.gensalt()).decode()

print(f"Generated user hash: {HASHED_PASSWORD_USER}")
print(f"Generated admin hash: {HASHED_PASSWORD_ADMIN}")

# Mock database
mock_users_db = {
    "user1": {
        "id": "user1",
        "email": "test@example.com",
        "username": "testuser",
        "hashed_password": HASHED_PASSWORD_USER,
        "role": "user",
        "created_at": datetime.utcnow().isoformat()
    },
    "admin1": {
        "id": "admin1",
        "email": "admin@example.com",
        "username": "adminuser",
        "hashed_password": HASHED_PASSWORD_ADMIN,
        "role": "admin",
        "created_at": datetime.utcnow().isoformat()
    }
}


class LoginRequest(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    role: str
    hashed_password: str | None = None
    created_at: str


@app.post("/api/auth/validate", response_model=dict)
async def validate_credentials(request: LoginRequest):
    """Validate user credentials.
    
    This endpoint is called by the JWT Auth Service to verify
    user email and password.
    """
    # Find user by email
    user = None
    for user_id, user_data in mock_users_db.items():
        if user_data["email"] == request.email:
            user = user_data
            break
    
    if not user:
        logger.warning(f"Login failed: user not found - {request.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Verify password
    if not bcrypt.checkpw(request.password.encode(), user["hashed_password"].encode()):
        logger.warning(f"Login failed: wrong password - {request.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    logger.info(f"User validated: {request.email}")
    
    return {
        "id": user["id"],
        "email": user["email"],
        "role": user["role"],
        "hashed_password": user["hashed_password"]
    }


@app.get("/api/users/{user_id}", response_model=UserResponse)
async def get_user_by_id(user_id: str):
    """Get user by ID."""
    if user_id not in mock_users_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user = mock_users_db[user_id]
    return UserResponse(
        id=user["id"],
        email=user["email"],
        username=user["username"],
        role=user["role"],
        hashed_password=None,
        created_at=user["created_at"]
    )


@app.get("/api/users/by-email", response_model=UserResponse)
async def get_user_by_email(email: str):
    """Get user by email."""
    for user_id, user_data in mock_users_db.items():
        if user_data["email"] == email:
            return UserResponse(
                id=user_data["id"],
                email=user_data["email"],
                username=user_data["username"],
                role=user_data["role"],
                hashed_password=None,
                created_at=user_data["created_at"]
            )
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="User not found"
    )


@app.get("/", tags=["Health"])
async def root():
    return {
        "service": "Mock User Service",
        "status": "running"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "mock_user_service:app",
        host="0.0.0.0",
        port=8001,
        reload=True
    )
