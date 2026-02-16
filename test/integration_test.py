"""
Integration test for JWT Auth Service - Logout and Token Revocation flows.

Tests the complete auth flow with running containers.
- Login with backend users
- Token validation
- Logout flow
- Token revocation verification
"""
import requests
import json
import jwt
import time

# Configuration
SECURITY_API_URL = "http://localhost:8090"
BACKEND_URL = "http://localhost:8000"

# Existing backend users (from add_initial_users.py)
TEST_USERS = {
    "admin": {"email": "admin@example.com", "password": "admin123"},
    "manager": {"email": "manager@example.com", "password": "manager123"},
    "picker": {"email": "picker@example.com", "password": "picker123"}
}


def test_login():
    """Test login returns tokens."""
    print("\n=== TEST 1: Login Flow ===")
    response = requests.post(
        f"{SECURITY_API_URL}/auth/login",
        json=TEST_USERS["admin"]
    )
    print(f"Login response status: {response.status_code}")
    assert response.status_code == 200, f"Login failed: {response.text}"
    
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    
    print(f"✓ Login successful")
    print(f"  - Access token: {data['access_token'][:20]}...")
    print(f"  - Refresh token: {data['refresh_token'][:20]}...")
    print(f"  - Expires in: {data['expires_in']} seconds")
    
    return data


def test_validate_token(access_token):
    """Test token validation."""
    print("\n=== TEST 2: Token Validation ===")
    response = requests.post(
        f"{SECURITY_API_URL}/auth/validate",
        params={"token": access_token, "check_blacklist": True}
    )
    print(f"Validate response status: {response.status_code}")
    assert response.status_code == 200
    
    data = response.json()
    assert data["valid"] is True
    assert data["payload"] is not None
    assert data["payload"]["email"] == TEST_USERS["admin"]["email"]
    
    print(f"✓ Token is valid")
    print(f"  - User: {data['payload']['email']}")
    print(f"  - Role: {data['payload']['role']}")
    print(f"  - Type: {data['payload']['type']}")


def test_logout_flow(refresh_token):
    """Test logout revokes token."""
    print("\n=== TEST 3: Logout Flow ===")
    
    # Logout with refresh token
    response = requests.post(
        f"{SECURITY_API_URL}/auth/logout",
        json={"refresh_token": refresh_token}
    )
    print(f"Logout response status: {response.status_code}")
    assert response.status_code == 200, f"Logout failed: {response.text}"
    
    data = response.json()
    assert data["success"] is True
    print(f"✓ Logout successful")
    
    # Try to use revoked refresh token
    refresh_response = requests.post(
        f"{SECURITY_API_URL}/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    print(f"Refresh after logout status: {refresh_response.status_code}")
    assert refresh_response.status_code == 401, "Should not allow refresh after logout"
    print(f"✓ Refresh token properly revoked")


def test_token_revocation_by_jti():
    """Test revoking a token by JTI."""
    print("\n=== TEST 4: Token Revocation by JTI ===")
    
    # Login
    login_response = requests.post(
        f"{SECURITY_API_URL}/auth/login",
        json=TEST_USERS["manager"]
    )
    tokens = login_response.json()
    refresh_token = tokens["refresh_token"]
    
    # Decode to get JTI
    # Note: Using unverified decode since we don't need to verify in testing
    payload = jwt.decode(
        refresh_token,
        options={"verify_signature": False}
    )
    jti = payload.get("jti")
    print(f"Token JTI: {jti}")
    
    # Verify token works before revocation
    refresh_before = requests.post(
        f"{SECURITY_API_URL}/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    assert refresh_before.status_code == 200, "Token should work before revocation"
    print(f"✓ Token valid before revocation")
    
    # Revoke token by JTI
    revoke_response = requests.post(
        f"{SECURITY_API_URL}/auth/revoke",
        json={"jti": jti}
    )
    print(f"Revoke response status: {revoke_response.status_code}")
    assert revoke_response.status_code == 200, f"Revocation failed: {revoke_response.text}"
    print(f"✓ Token revoked successfully")
    
    # Verify token no longer works
    refresh_after = requests.post(
        f"{SECURITY_API_URL}/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    assert refresh_after.status_code == 401, "Token should be invalid after revocation"
    print(f"✓ Revoked token rejected by API")


def test_revoke_all_user_tokens():
    """Test revoking all tokens for a user."""
    print("\n=== TEST 5: Revoke All User Tokens ===")
    
    # Login multiple times
    login1 = requests.post(f"{SECURITY_API_URL}/auth/login", json=TEST_USERS["picker"])
    token1 = login1.json()["refresh_token"]
    
    login2 = requests.post(f"{SECURITY_API_URL}/auth/login", json=TEST_USERS["picker"])
    token2 = login2.json()["refresh_token"]
    
    # Get user_id from first token
    payload = jwt.decode(token1, options={"verify_signature": False})
    user_id = payload.get("sub")
    print(f"User ID: {user_id}")
    
    # Revoke all tokens for user
    revoke_response = requests.post(
        f"{SECURITY_API_URL}/auth/revoke-all",
        json={"user_id": user_id}
    )
    print(f"Revoke all response status: {revoke_response.status_code}")
    assert revoke_response.status_code == 200, f"Revoke all failed: {revoke_response.text}"
    
    data = revoke_response.json()
    print(f"✓ Revoked {data['revoked_count']} tokens")
    
    # Both tokens should be invalid
    refresh1 = requests.post(f"{SECURITY_API_URL}/auth/refresh", json={"refresh_token": token1})
    assert refresh1.status_code == 401, "First token should be invalid"
    
    refresh2 = requests.post(f"{SECURITY_API_URL}/auth/refresh", json={"refresh_token": token2})
    assert refresh2.status_code == 401, "Second token should be invalid"
    
    print(f"✓ All user tokens properly revoked")


def test_refresh_token_rotation():
    """Test that refresh invalidates old token."""
    print("\n=== TEST 6: Refresh Token Rotation ===")
    
    # Login
    login = requests.post(
        f"{SECURITY_API_URL}/auth/login",
        json=TEST_USERS["admin"]
    )
    old_refresh = login.json()["refresh_token"]
    print(f"Initial refresh token: {old_refresh[:20]}...")
    
    # First refresh
    refresh1 = requests.post(
        f"{SECURITY_API_URL}/auth/refresh",
        json={"refresh_token": old_refresh}
    )
    assert refresh1.status_code == 200
    new_refresh1 = refresh1.json()["refresh_token"]
    print(f"✓ First refresh successful: {new_refresh1[:20]}...")
    
    # Try to use old token - should fail
    refresh_old = requests.post(
        f"{SECURITY_API_URL}/auth/refresh",
        json={"refresh_token": old_refresh}
    )
    assert refresh_old.status_code == 401, "Old refresh token should be invalid"
    print(f"✓ Old refresh token properly invalidated")
    
    # Use new token
    refresh2 = requests.post(
        f"{SECURITY_API_URL}/auth/refresh",
        json={"refresh_token": new_refresh1}
    )
    assert refresh2.status_code == 200
    new_refresh2 = refresh2.json()["refresh_token"]
    print(f"✓ New refresh token valid: {new_refresh2[:20]}...")


def test_logout_all_devices():
    """Test logout from all devices."""
    print("\n=== TEST 7: Logout from All Devices ===")
    
    # Login multiple times (2 sessions)
    login1 = requests.post(f"{SECURITY_API_URL}/auth/login", json=TEST_USERS["manager"])
    token1 = login1.json()["refresh_token"]
    
    login2 = requests.post(f"{SECURITY_API_URL}/auth/login", json=TEST_USERS["manager"])
    token2 = login2.json()["refresh_token"]
    
    # Get user_id
    payload = jwt.decode(token1, options={"verify_signature": False})
    user_id = payload.get("sub")
    
    # Both tokens should work before logout-all
    refresh1_before = requests.post(f"{SECURITY_API_URL}/auth/refresh", json={"refresh_token": token1})
    refresh2_before = requests.post(f"{SECURITY_API_URL}/auth/refresh", json={"refresh_token": token2})
    assert refresh1_before.status_code == 200
    assert refresh2_before.status_code == 200
    print(f"✓ Both tokens valid before logout-all")
    
    # Logout all devices
    logout_all = requests.post(
        f"{SECURITY_API_URL}/auth/logout",
        json={"user_id": user_id, "all_devices": True}
    )
    assert logout_all.status_code == 200
    print(f"✓ Logout from all devices successful")
    
    # Both tokens should be invalid after logout-all
    refresh1_after = requests.post(f"{SECURITY_API_URL}/auth/refresh", json={"refresh_token": token1})
    refresh2_after = requests.post(f"{SECURITY_API_URL}/auth/refresh", json={"refresh_token": token2})
    assert refresh1_after.status_code == 401
    assert refresh2_after.status_code == 401
    print(f"✓ All tokens revoked after logout-all")


def main():
    """Run all tests."""
    print("=" * 60)
    print("JWT AUTH SERVICE - LOGOUT & REVOCATION FLOW TESTS")
    print("=" * 60)
    
    try:
        # Test 1: Login
        tokens = test_login()
        
        # Test 2: Validate token
        test_validate_token(tokens["access_token"])
        
        # Test 3: Logout flow
        test_logout_flow(tokens["refresh_token"])
        
        # Test 4: Token revocation by JTI
        test_token_revocation_by_jti()
        
        # Test 5: Revoke all user tokens
        test_revoke_all_user_tokens()
        
        # Test 6: Refresh token rotation
        test_refresh_token_rotation()
        
        # Test 7: Logout all devices
        test_logout_all_devices()
        
        print("\n" + "=" * 60)
        print("✓ ALL TESTS PASSED!")
        print("=" * 60)
        return 0
        
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
