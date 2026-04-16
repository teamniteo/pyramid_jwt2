"""Minimal Pyramid app demonstrating pyramid-jwt2 capabilities."""
# ruff: noqa: T201, ARG001, S106

from datetime import UTC, datetime, timedelta
from wsgiref.simple_server import make_server

import jwt
from pyramid.authorization import Allow, Authenticated
from pyramid.config import Configurator
from pyramid.httpexceptions import HTTPUnauthorized
from pyramid.request import Request
from pyramid.view import view_config

from pyramid_jwt2 import set_jwt_authentication_policy

# Fake user database
USERS = {
    "user-1": {"email": "alice@example.com", "password": "secret123", "role": "admin"},
    "user-2": {"email": "bob@example.com", "password": "password", "role": "user"},
}

# Track logged out users (in production, use database)
LOGGED_OUT = {}


class RootFactory:
    """ACL root factory for permissions."""

    def __init__(self, request: Request) -> None:
        """Initialize with request."""
        self.request = request

    @property
    def __acl__(self) -> list:
        """Define access control list."""
        return [
            (Allow, Authenticated, "authenticated"),
            (Allow, "role:admin", "admin"),
        ]


def load_user_from_fake_db(userid: str, request: Request) -> dict | None:
    """Load user from fake database.

    Args:
        userid: User ID from JWT token
        request: Pyramid request

    Returns:
        User dict if found, None otherwise
    """
    return USERS.get(userid)


def validate_token(user: dict | None, request: Request) -> bool:
    """Validate JWT token - check if user logged out.

    Args:
        user: User dict from load_user_from_fake_db
        request: Pyramid request

    Returns:
        True if valid, False if invalid
    """
    if user is None:
        return False  # User not found

    userid = user["id"]

    # Check if user has logged out
    if userid in LOGGED_OUT:
        # Token was issued before logout
        try:
            # Get token issue time
            iat = request.jwt_claims.get("iat")
            if iat and iat < LOGGED_OUT[userid]:
                return False  # Token issued before logout
        except (KeyError, jwt.InvalidTokenError):
            return False

    return True  # Token is valid


def get_principals_for_user(request: Request, user: dict | None) -> set[str]:
    """Add role-based principals.

    Args:
        request: Pyramid request
        user: User dict from user_loader

    Returns:
        Set of principals to add (e.g., {'role:admin', 'role:user'})
    """
    if user is None:
        return set()

    role = user.get("role")
    if role:
        return {f"role:{role}"}
    return set()


@view_config(route_name="home", request_method="GET", renderer="json")
def home(request: Request) -> dict:
    """Public home endpoint."""
    return {
        "message": "Welcome to pyramid-jwt2 example",
        "endpoints": {
            "POST /login": "Login with email/password to get JWT token",
            "GET /profile": "Get your profile (requires authentication)",
            "GET /admin": "Admin-only endpoint (requires admin role)",
            "POST /logout": "Logout and invalidate token",
        },
    }


@view_config(route_name="login", request_method="POST", renderer="json")
def login(request: Request) -> dict:
    """Login endpoint - returns JWT token."""
    try:
        body = request.json_body
        email = body.get("email")
        password = body.get("password")
    except Exception:  # noqa: BLE001
        raise HTTPUnauthorized(json_body={"error": "Invalid request"}) from None

    # Find user by email
    userid = None
    user = None
    for uid, user_data in USERS.items():
        if user_data["email"] == email:
            userid = uid
            user = user_data
            break

    # Validate credentials
    if not user or user["password"] != password:
        raise HTTPUnauthorized(json_body={"error": "Invalid credentials"})

    # Create JWT token with 1 hour expiration
    token = request.create_jwt_token(
        userid,
        expiration=timedelta(hours=1),
    )

    return {
        "token": token,
        "user": {"id": userid, "email": email, "role": user["role"]},
    }


@view_config(
    route_name="profile",
    request_method="GET",
    renderer="json",
    permission="authenticated",
)
def profile(request: Request) -> dict:
    """Protected endpoint - requires authentication."""
    userid = request.authenticated_userid
    user = request.identity["user"]
    claims = request.jwt_claims

    return {
        "userid": userid,
        "email": user.get("email"),
        "role": user.get("role"),
        "issued_at": claims.get("iat"),
        "expires_at": claims.get("exp"),
    }


@view_config(
    route_name="admin",
    request_method="GET",
    renderer="json",
    permission="admin",
)
def admin_only(request: Request) -> dict:
    """Admin-only endpoint."""
    return {
        "message": "Welcome to admin area",
        "userid": request.authenticated_userid,
        "all_users": [user["email"] for user in USERS.values()],
    }


@view_config(
    route_name="logout",
    request_method="POST",
    renderer="json",
    permission="authenticated",
)
def logout(request: Request) -> dict:
    """Logout endpoint - invalidates current token."""
    userid = request.authenticated_userid

    # Mark user as logged out at current timestamp
    LOGGED_OUT[userid] = int(datetime.now(UTC).timestamp())

    return {"message": "Logged out successfully"}


def main() -> None:
    """Run the example application."""
    with Configurator() as config:
        # Configure JWT authentication
        set_jwt_authentication_policy(
            config,
            secret="super-secret-key-change-in-production",
            user_loader=load_user_from_fake_db,
            custom_token_validation=validate_token,
            additional_principals=get_principals_for_user,
        )

        # Set ACL root factory
        config.set_root_factory(RootFactory)

        # Add routes
        config.add_route("home", "/")
        config.add_route("login", "/login")
        config.add_route("profile", "/profile")
        config.add_route("admin", "/admin")
        config.add_route("logout", "/logout")

        # Scan for views
        config.scan()

        # Create WSGI app
        app = config.make_wsgi_app()

    # Serve the app
    print("\n" + "=" * 60)
    print("pyramid-jwt2 Example App")
    print("=" * 60)
    print("Server running at: http://localhost:6543")
    print("\nExample requests:")
    print("\n1. Login as Alice (admin):")
    print("   curl -X POST http://localhost:6543/login \\")
    print('     -H "Content-Type: application/json" \\')
    print('     -d \'{"email": "alice@example.com", "password": "secret123"}\'')
    print("\n2. Login as Bob (user):")
    print("   curl -X POST http://localhost:6543/login \\")
    print('     -H "Content-Type: application/json" \\')
    print('     -d \'{"email": "bob@example.com", "password": "password"}\'')
    print("\n3. Access profile (use token from login):")
    print("   curl http://localhost:6543/profile \\")
    print('     -H "Authorization: Bearer YOUR_TOKEN_HERE"')
    print("\n4. Access admin endpoint (requires admin role):")
    print("   curl http://localhost:6543/admin \\")
    print('     -H "Authorization: Bearer YOUR_TOKEN_HERE"')
    print("\n5. Logout:")
    print("   curl -X POST http://localhost:6543/logout \\")
    print('     -H "Authorization: Bearer YOUR_TOKEN_HERE"')
    print("\n" + "=" * 60 + "\n")

    server = make_server("localhost", 6543, app)
    server.serve_forever()


if __name__ == "__main__":
    main()
