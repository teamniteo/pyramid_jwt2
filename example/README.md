# pyramid-jwt2 Example Application

A minimal Pyramid application demonstrating all capabilities of pyramid-jwt2.

## Features Demonstrated

- ✅ JWT token creation with custom claims
- ✅ Bearer token authentication
- ✅ Token expiration (1 hour)
- ✅ ACL-based permissions (`authenticated`, `admin`)
- ✅ Custom validation callback (logout timestamp checking)
- ✅ Protected endpoints
- ✅ Role-based access control

## Running the Example

```bash
# From the pyramid_jwt2 directory
python -m example

# Or directly
python example/__init__.py
```

The server will start at `http://localhost:6543`

## API Endpoints

### Public Endpoints

#### `GET /` - Home
Returns API information.

```bash
curl http://localhost:6543/
```

#### `POST /login` - Login
Get a JWT token by providing credentials.

**Request:**
```bash
curl -X POST http://localhost:6543/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "secret123"}'
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "user-1",
    "email": "alice@example.com",
    "role": "admin"
  }
}
```

### Protected Endpoints

#### `GET /profile` - User Profile
Requires: `authenticated` permission

```bash
curl http://localhost:6543/profile \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

**Response:**
```json
{
  "userid": "user-1",
  "email": "alice@example.com",
  "role": "admin",
  "issued_at": 1234567890,
  "expires_at": 1234571490
}
```

#### `GET /admin` - Admin Area
Requires: `admin` permission (only users with `role: admin`)

```bash
curl http://localhost:6543/admin \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

**Response:**
```json
{
  "message": "Welcome to admin area",
  "userid": "user-1",
  "all_users": ["alice@example.com", "bob@example.com"]
}
```

#### `POST /logout` - Logout
Requires: `authenticated` permission

Invalidates all tokens issued before the logout timestamp.

```bash
curl -X POST http://localhost:6543/logout \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

## Test Users

| Email | Password | Role | Can Access Admin |
|-------|----------|------|------------------|
| alice@example.com | secret123 | admin | ✅ Yes |
| bob@example.com | password | user | ❌ No |

## Complete Example Flow

```bash
# 1. Login as Alice (admin)
TOKEN=$(curl -s -X POST http://localhost:6543/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "secret123"}' \
  | jq -r '.token')

echo "Token: $TOKEN"

# 2. Access profile
curl -s http://localhost:6543/profile \
  -H "Authorization: Bearer $TOKEN" | jq

# 3. Access admin endpoint (works because Alice is admin)
curl -s http://localhost:6543/admin \
  -H "Authorization: Bearer $TOKEN" | jq

# 4. Logout
curl -s -X POST http://localhost:6543/logout \
  -H "Authorization: Bearer $TOKEN" | jq

# 5. Try to access profile again (should fail - token invalidated)
curl -s http://localhost:6543/profile \
  -H "Authorization: Bearer $TOKEN"
```

## Testing Permissions

### Bob cannot access admin endpoint:

```bash
# Login as Bob
BOB_TOKEN=$(curl -s -X POST http://localhost:6543/login \
  -H "Content-Type: application/json" \
  -d '{"email": "bob@example.com", "password": "password"}' \
  | jq -r '.token')

# Try to access admin (will fail with 403 Forbidden)
curl -s http://localhost:6543/admin \
  -H "Authorization: Bearer $BOB_TOKEN"
```

### No token = 403 Forbidden:

```bash
curl -s http://localhost:6543/profile
# Returns: 403 Forbidden
```

### Invalid token = 403 Forbidden:

```bash
curl -s http://localhost:6543/profile \
  -H "Authorization: Bearer invalid-token-here"
# Returns: 403 Forbidden
```

## Key Implementation Details

### Token Validation Callback

The example implements a `validate_token` callback that checks if the user has logged out:

```python
def validate_token(userid: str, request: Request) -> list | None:
    """Check if token is still valid (user hasn't logged out)."""
    if userid in LOGGED_OUT:
        iat = request.jwt_claims.get("iat")
        if iat and iat < LOGGED_OUT[userid]:
            return None  # Token issued before logout
    return []  # Valid
```

### ACL Permissions

The `RootFactory` defines two permission levels:

- **`authenticated`**: All logged-in users
- **`admin`**: Only users with `role: admin` in their JWT claims

```python
class RootFactory:
    @property
    def __acl__(self):
        userid = self.request.authenticated_userid
        if userid:
            acl = [(Allow, userid, "authenticated")]
            if self.request.jwt_claims.get("role") == "admin":
                acl.append((Allow, userid, "admin"))
            return acl
        return []
```

## Production Considerations

This is a minimal example. For production use:

1. **Use a strong secret**: Don't hardcode secrets, use environment variables
2. **Use a database**: Store user data and logout timestamps in a database
3. **Use HTTPS**: Always use HTTPS in production
4. **Hash passwords**: Use bcrypt/argon2 for password hashing
5. **Rate limiting**: Add rate limiting to login endpoint
6. **Token refresh**: Implement refresh tokens for better UX
7. **CORS**: Configure CORS if building a separate frontend
