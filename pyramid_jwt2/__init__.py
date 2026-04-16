"""Custom JWT authentication for Pyramid."""

import typing as t
from datetime import UTC, datetime, timedelta

import jwt
from pyramid.authorization import ACLHelper, Authenticated, Everyone
from pyramid.interfaces import ISecurityPolicy
from pyramid.request import Request
from zope.interface import implementer

if t.TYPE_CHECKING:
    from pyramid.config import Configurator


@implementer(ISecurityPolicy)
class JWTSecurityPolicy:
    """JWT-based security policy for Pyramid."""

    def __init__(  # noqa: PLR0913
        self,
        secret: str,
        user_loader: t.Callable[[str, Request], t.Any],
        algorithm: str = "HS512",
        auth_type: str = "Bearer",
        custom_token_validation: t.Callable[[t.Any, Request], bool] | None = None,
        additional_principals: t.Callable[[Request, t.Any], set[str]] | None = None,
    ) -> None:
        """Initialize JWT security policy.

        Args:
            secret: Secret key for signing/verifying JWTs
            user_loader: Required callback(userid, request) -> user object or None
                Use it to load user from e.g. database to have it available in
                request.identity["user"]. Return None if user doesn't exist
            algorithm: JWT algorithm (default: HS512)
            auth_type: Authorization header type (default: Bearer)
            custom_token_validation: Optional callback(user, request) -> bool
                Returns True if token is valid, False if invalid
            additional_principals: Optional callback(request, user) -> set[str]
                Returns additional principals to add (e.g., role-based principals)
        """
        self.secret = secret
        self.user_loader = user_loader
        self.algorithm = algorithm
        self.auth_type = auth_type
        self.custom_token_validation = custom_token_validation
        self.additional_principals = additional_principals
        self.helper = ACLHelper()

    def _get_token(self, request: Request) -> str | None:
        """Extract JWT token from Authorization header."""
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return None

        try:
            auth_type, token = auth_header.split(" ", 1)
        except ValueError:
            return None

        if auth_type != self.auth_type:
            return None

        return token

    def _decode_token(self, token: str) -> dict[str, t.Any] | None:
        """Decode and validate JWT token."""
        try:
            return jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
            )
        except jwt.InvalidTokenError:
            return None

    def identity(self, request: Request) -> dict[str, t.Any] | None:
        """Extract and validate identity from request."""
        token = self._get_token(request)
        if not token:
            return None

        claims = self._decode_token(token)
        if not claims:
            return None

        # Store claims on request for later access
        request.jwt_claims = claims

        userid = claims.get("sub")
        if not userid:
            return None

        # Load user from database
        user = self.user_loader(userid, request)
        if user is None:
            return None  # User not found = invalid token

        # Run validation callback that can invalidate the token
        if self.custom_token_validation:
            is_valid = self.custom_token_validation(user, request)
            if not is_valid:
                return None  # Token invalidated by callback

        return {"userid": userid, "claims": claims, "user": user}

    def authenticated_userid(self, request: Request) -> str | None:
        """Return the authenticated user ID from the request."""
        identity = request.identity
        if identity is None:
            return None
        return identity.get("userid")

    def permits(
        self,
        request: Request,
        context: t.Any,
        permission: str,
    ) -> t.Literal["Allow", "Deny", "ACLDenied"]:
        """Check if the request has permission in the given context."""
        identity = request.identity
        principals = {Everyone}

        if identity is not None:
            principals.add(Authenticated)
            principals.add(identity["userid"])

            # Add custom principals from callback
            if self.additional_principals:
                user = identity.get("user")
                custom_principals = self.additional_principals(request, user)
                if custom_principals:
                    principals.update(custom_principals)

        return self.helper.permits(context, principals, permission)

    def remember(
        self,
        request: Request,
        userid: str,
        **kw: t.Any,
    ) -> list[tuple[str, str]]:
        """Not implemented for JWT.

        Use create_jwt_token() to generate tokens instead.

        Raises:
            NotImplementedError: Always raised as JWT doesn't use headers for auth
        """
        msg = "Use create_jwt_token() to generate tokens instead of remember()"
        raise NotImplementedError(msg)

    def forget(self, request: Request, **kw: t.Any) -> list[tuple[str, str]]:
        """Not implemented for JWT.

        JWT logout is handled via validation callbacks, not by clearing headers.

        Raises:
            NotImplementedError: Always raised as JWT is stateless
        """
        msg = "JWT logout should be handled via validation callback, not forget()"
        raise NotImplementedError(msg)


def create_jwt_token(
    request: Request,
    userid: str,
    expiration: timedelta | None = None,
    **claims: t.Any,
) -> str:
    """Create a JWT token.

    Args:
        request: Pyramid request
        userid: User ID (will be stored in 'sub' claim)
        expiration: Token expiration timedelta
        **claims: Additional claims to include in token
    """
    policy = request.registry.queryUtility(ISecurityPolicy)
    if not isinstance(policy, JWTSecurityPolicy):
        msg = "JWTSecurityPolicy not configured"
        raise TypeError(msg)

    now = datetime.now(UTC)
    payload = {
        "sub": userid,
        "iat": now,
        **claims,
    }

    if expiration:
        payload["exp"] = now + expiration

    return jwt.encode(payload, policy.secret, algorithm=policy.algorithm)


def jwt_claims_from_token(request: Request, token: str) -> dict[str, t.Any]:
    """Decode and validate a JWT token, returning claims.

    Args:
        request: Pyramid request
        token: JWT token string

    Returns:
        Decoded claims dict

    Raises:
        jwt.InvalidTokenError: If token is invalid or expired
    """
    policy = request.registry.queryUtility(ISecurityPolicy)
    if not isinstance(policy, JWTSecurityPolicy):
        msg = "JWTSecurityPolicy not configured"
        raise TypeError(msg)

    return jwt.decode(token, policy.secret, algorithms=[policy.algorithm])


def includeme(config: "Configurator") -> None:
    """Pyramid configuration hook."""
    # This is a placeholder - applications should call
    # set_jwt_authentication_policy() directly


def set_jwt_authentication_policy(  # noqa: PLR0913
    config: "Configurator",
    secret: str,
    user_loader: t.Callable[[str, Request], t.Any],
    algorithm: str = "HS512",
    auth_type: str = "Bearer",
    custom_token_validation: t.Callable[[t.Any, Request], bool] | None = None,
    additional_principals: t.Callable[[Request, t.Any], set[str]] | None = None,
) -> None:
    """Configure JWT authentication policy.

    Args:
        config: Pyramid configurator
        secret: Secret key for signing/verifying JWTs
        user_loader: Required callback(userid, request) -> user object or None
            Loads user from database. Return None if user doesn't exist.
        algorithm: JWT algorithm (default: HS512)
        auth_type: Authorization header type (default: Bearer)
        custom_token_validation: Optional callback(user, request) -> bool
            Returns True if token is valid, False if invalid
        additional_principals: Optional callback(request, user) -> set[str]
            Returns additional principals to add (e.g., role-based principals)
    """
    policy = JWTSecurityPolicy(
        secret=secret,
        user_loader=user_loader,
        algorithm=algorithm,
        auth_type=auth_type,
        custom_token_validation=custom_token_validation,
        additional_principals=additional_principals,
    )
    config.set_security_policy(policy)

    # Add request methods for creating and decoding tokens
    config.add_request_method(create_jwt_token, "create_jwt_token")
    config.add_request_method(jwt_claims_from_token, "jwt_claims_from_token")
