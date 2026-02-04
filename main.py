"""JWT Auth Service - Main FastAPI Application."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import get_settings
from api.routes.auth import router as auth_router
from services.redis_client import redis_client

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup and shutdown."""
    # Startup
    logger.info("Starting JWT Auth Service...")
    
    try:
        await redis_client.connect()
        logger.info("Connected to Redis")
    except Exception as e:
        logger.warning(f"Failed to connect to Redis: {e}")
        logger.warning("Service will run without Redis (limited functionality)")
    
    yield
    
    # Shutdown
    logger.info("Shutting down JWT Auth Service...")
    await redis_client.disconnect()


# Create FastAPI application
app = FastAPI(
    title="JWT Auth Service",
    description="A dedicated authentication service for JWT token generation and validation with refresh support",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)


@app.get("/", tags=["Health"])
async def root():
    """Root endpoint - health check."""
    return {
        "service": "JWT Auth Service",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    redis_status = "connected" if redis_client._client else "disconnected"
    
    return {
        "status": "healthy",
        "redis": redis_status
    }


@app.get("/ready", tags=["Health"])
async def readiness_check():
    """Readiness check endpoint."""
    # Check Redis connection
    try:
        if redis_client._client:
            await redis_client._client.ping()
            redis_status = "ready"
        else:
            redis_status = "not configured"
    except Exception as e:
        redis_status = f"error: {str(e)}"
    
    return {
        "ready": redis_status == "ready",
        "redis": redis_status
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
