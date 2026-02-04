# JWT Token Service Architecture (Complete)

## Final Architecture Summary

### Gateway Pattern (All Auth Endpoints)
The API gateway acts as a **transparent proxy** - it forwards all auth requests to the auth service without modification.

```
User → Gateway → Auth Service → Redis → Response → Gateway → User
```

### All Auth Endpoints (Forwarded by Gateway)
| Endpoint | Description | Gateway Action |
|----------|-------------|----------------|
| `POST /auth/login` | Get tokens | Forward |
| `POST /auth/refresh` | Rotate tokens | Forward |
| `POST /auth/validate` | Check token | Forward |
| `POST /auth/logout` | Current device | Forward |
| `POST /auth/logout-all` | All devices | Forward |
| `POST /admin/ban-user` | Ban user | Forward |

## Token Storage (Redis with JTI)

```python
# Key Structure
refresh:{jti} → {user_id, email, role, device, expires_at}
blacklist:{jti} → "revoked" (TTL = remaining access token time)
user_banned:{user_id} → {reason, expires_at}
```

## Token Rotation Flow

```
Login:      access_token + refresh_token:A → Redis stores A
Refresh 1:  use A → invalidate A → return access_token + refresh_token:B
Refresh 2:  use B → invalidate B → return access_token + refresh_token:C
```

## Logout Options

| Endpoint | Effect |
|----------|--------|
| `POST /auth/logout` | Revoke current refresh token + blacklist access token |
| `POST /auth/logout-all` | Revoke ALL user's refresh tokens |
| `POST /admin/ban-user` | Ban user + revoke all tokens |

## User Model

```python
class User(BaseModel):
    email: str
    hashed_password: str  # Validated via external service
    role: str
```

## Implementation Files

```
├── config.py              # Configuration
├── main.py               # FastAPI app
├── models/
│   ├── user.py          # User model
│   └── token.py        # Token models
├── services/
│   ├── token_service.py # JWT generation/validation
│   └── redis_client.py  # Redis operations
├── api/
│   ├── routes/
│   │   └── auth.py     # Auth endpoints
│   └── deps.py         # Dependencies
└── utils/
    └── password.py     # Password helpers
```

## Ready for Implementation

The architecture is complete and ready for code implementation.
