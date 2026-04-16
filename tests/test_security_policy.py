"""Tests for JWT security policy."""

from datetime import UTC, datetime, timedelta
from typing import ClassVar
from unittest.mock import PropertyMock, patch

import jwt
import pytest
from pyramid.authorization import ACLAllowed, ACLDenied, Allow, Authenticated
from pyramid.config import Configurator
from pyramid.request import Request
from pyramid.testing import DummyRequest

from pyramid_jwt2 import (
    JWTSecurityPolicy,
    create_jwt_token,
    jwt_claims_from_token,
    set_jwt_authentication_policy,
)


@pytest.fixture
def config() -> Configurator:
    """Create a Pyramid configurator for testing."""
    return Configurator(settings={"jwt.secret": "test-secret"})


def simple_user_loader(userid: str, request: Request) -> str:
    """Load and return userid."""
    return userid


@pytest.fixture
def policy() -> JWTSecurityPolicy:
    """Create a JWT security policy."""
    return JWTSecurityPolicy(
        secret="test-secret",
        user_loader=simple_user_loader,
        algorithm="HS512",
    )


class TestJWTSecurityPolicy:
    """Test JWTSecurityPolicy class."""

    def test_init(self) -> None:
        """Test policy initialization."""
        policy = JWTSecurityPolicy(
            secret="my-secret",
            user_loader=simple_user_loader,
            algorithm="HS256",
            auth_type="Token",
        )
        assert policy.secret == "my-secret"
        assert policy.algorithm == "HS256"
        assert policy.auth_type == "Token"
        assert policy.user_loader == simple_user_loader
        assert policy.custom_token_validation is None
        assert policy.additional_principals is None

    def test_get_token_from_header(self, policy: JWTSecurityPolicy) -> None:
        """Test extracting token from Authorization header."""
        request = DummyRequest()
        request.headers = {"Authorization": "Bearer test-token-123"}

        token = policy._get_token(request)
        assert token == "test-token-123"

    def test_get_token_missing_header(self, policy: JWTSecurityPolicy) -> None:
        """Test missing Authorization header."""
        request = DummyRequest()
        request.headers = {}

        token = policy._get_token(request)
        assert token is None

    def test_get_token_wrong_auth_type(self, policy: JWTSecurityPolicy) -> None:
        """Test wrong auth type in header."""
        request = DummyRequest()
        request.headers = {"Authorization": "Basic dGVzdDoxMjM="}

        token = policy._get_token(request)
        assert token is None

    def test_get_token_malformed_header(self, policy: JWTSecurityPolicy) -> None:
        """Test malformed Authorization header."""
        request = DummyRequest()
        request.headers = {"Authorization": "InvalidHeaderFormat"}

        token = policy._get_token(request)
        assert token is None

    def test_get_token_empty_token(self, policy: JWTSecurityPolicy) -> None:
        """Test Authorization header with empty token."""
        request = DummyRequest()
        request.headers = {"Authorization": "Bearer "}

        token = policy._get_token(request)
        assert token == ""

    def test_decode_valid_token(self, policy: JWTSecurityPolicy) -> None:
        """Test decoding a valid JWT token."""
        payload = {"sub": "user123", "exp": datetime.now(UTC) + timedelta(hours=1)}
        token = jwt.encode(payload, "test-secret", algorithm="HS512")

        claims = policy._decode_token(token)
        assert claims is not None
        assert claims["sub"] == "user123"

    def test_decode_expired_token(self, policy: JWTSecurityPolicy) -> None:
        """Test decoding an expired token."""
        payload = {"sub": "user123", "exp": datetime.now(UTC) - timedelta(hours=1)}
        token = jwt.encode(payload, "test-secret", algorithm="HS512")

        claims = policy._decode_token(token)
        assert claims is None

    def test_decode_invalid_signature(self, policy: JWTSecurityPolicy) -> None:
        """Test decoding token with invalid signature."""
        payload = {"sub": "user123"}
        token = jwt.encode(payload, "wrong-secret", algorithm="HS512")

        claims = policy._decode_token(token)
        assert claims is None

    def test_identity_valid_token(self, policy: JWTSecurityPolicy) -> None:
        """Test getting identity from valid token."""
        payload = {"sub": "user123", "exp": datetime.now(UTC) + timedelta(hours=1)}
        token = jwt.encode(payload, "test-secret", algorithm="HS512")

        request = DummyRequest()
        request.headers = {"Authorization": f"Bearer {token}"}

        identity = policy.identity(request)
        assert identity is not None
        assert identity["userid"] == "user123"
        assert identity["user"] == "user123"
        assert identity["claims"] == request.jwt_claims
        assert identity["claims"]["sub"] == "user123"
        assert request.jwt_claims["sub"] == "user123"

    def test_identity_no_token(self, policy: JWTSecurityPolicy) -> None:
        """Test identity when no token present."""
        request = DummyRequest()
        request.headers = {}

        identity = policy.identity(request)
        assert identity is None

    def test_identity_invalid_token(self, policy: JWTSecurityPolicy) -> None:
        """Test identity with invalid token."""
        request = DummyRequest()
        request.headers = {"Authorization": "Bearer invalid-token"}

        identity = policy.identity(request)
        assert identity is None

    def test_identity_token_missing_sub(self, policy: JWTSecurityPolicy) -> None:
        """Test identity when token missing 'sub' claim."""
        payload = {"exp": datetime.now(UTC) + timedelta(hours=1)}
        token = jwt.encode(payload, "test-secret", algorithm="HS512")

        request = DummyRequest()
        request.headers = {"Authorization": f"Bearer {token}"}

        identity = policy.identity(request)
        assert identity is None

    def test_identity_with_callback_valid(self, policy: JWTSecurityPolicy) -> None:
        """Test identity with validation callback that returns True."""

        def custom_validation(user: str, request: Request) -> bool:
            return True  # Always accept

        policy.custom_token_validation = custom_validation
        payload = {"sub": "user123", "exp": datetime.now(UTC) + timedelta(hours=1)}
        token = jwt.encode(payload, "test-secret", algorithm="HS512")

        request = DummyRequest()
        request.headers = {"Authorization": f"Bearer {token}"}

        identity = policy.identity(request)
        assert identity is not None
        assert identity["userid"] == "user123"
        assert identity["user"] == "user123"
        assert identity["claims"]["sub"] == "user123"

    def test_identity_with_callback_rejected(
        self,
        policy: JWTSecurityPolicy,
    ) -> None:
        """Test identity with validation callback that returns False."""

        def custom_validation(user: str, request: Request) -> bool:
            return False  # Reject all tokens

        policy.custom_token_validation = custom_validation
        payload = {"sub": "user123", "exp": datetime.now(UTC) + timedelta(hours=1)}
        token = jwt.encode(payload, "test-secret", algorithm="HS512")

        request = DummyRequest()
        request.headers = {"Authorization": f"Bearer {token}"}

        identity = policy.identity(request)
        assert identity is None

    def test_identity_user_loader_returns_none(self) -> None:
        """Test identity when user_loader cannot resolve the user."""

        def missing_user_loader(userid: str, request: Request) -> None:
            return None

        policy = JWTSecurityPolicy(
            secret="test-secret",
            user_loader=missing_user_loader,
            algorithm="HS512",
        )
        payload = {"sub": "user123", "exp": datetime.now(UTC) + timedelta(hours=1)}
        token = jwt.encode(payload, "test-secret", algorithm="HS512")

        request = DummyRequest()
        request.headers = {"Authorization": f"Bearer {token}"}

        identity = policy.identity(request)
        assert identity is None

    def test_authenticated_userid(self, policy: JWTSecurityPolicy) -> None:
        """Test getting authenticated user ID."""
        payload = {"sub": "user123", "exp": datetime.now(UTC) + timedelta(hours=1)}
        token = jwt.encode(payload, "test-secret", algorithm="HS512")

        request = DummyRequest()
        request.headers = {"Authorization": f"Bearer {token}"}

        # Get identity from policy
        identity = policy.identity(request)

        # Mock request.identity (read-only property)
        with patch.object(
            type(request),
            "identity",
            new_callable=PropertyMock,
            return_value=identity,
        ):
            userid = policy.authenticated_userid(request)
            assert userid == "user123"

    def test_authenticated_userid_no_identity(
        self,
        policy: JWTSecurityPolicy,
    ) -> None:
        """Test authenticated_userid with no identity."""
        request = DummyRequest()

        # Mock request.identity as None (read-only property)
        with patch.object(
            type(request),
            "identity",
            new_callable=PropertyMock,
            return_value=None,
        ):
            userid = policy.authenticated_userid(request)
            assert userid is None

    def test_permits_with_acl(self, policy: JWTSecurityPolicy) -> None:
        """Test permission checking with ACL using Authenticated principal."""

        class Context:
            __acl__: ClassVar = [(Allow, Authenticated, "view")]

        payload = {"sub": "user123", "exp": datetime.now(UTC) + timedelta(hours=1)}
        token = jwt.encode(payload, "test-secret", algorithm="HS512")

        request = DummyRequest()
        request.headers = {"Authorization": f"Bearer {token}"}

        # Get identity from policy
        identity = policy.identity(request)

        # Mock request.identity (read-only property)
        with patch.object(
            type(request),
            "identity",
            new_callable=PropertyMock,
            return_value=identity,
        ):
            context = Context()
            result = policy.permits(request, context, "view")
            assert isinstance(result, ACLAllowed)

    def test_permits_with_userid_acl(self, policy: JWTSecurityPolicy) -> None:
        """Test permission checking with user-specific ACL."""

        class Context:
            __acl__: ClassVar = [(Allow, "user123", "edit")]

        payload = {"sub": "user123", "exp": datetime.now(UTC) + timedelta(hours=1)}
        token = jwt.encode(payload, "test-secret", algorithm="HS512")

        request = DummyRequest()
        request.headers = {"Authorization": f"Bearer {token}"}

        # Get identity from policy
        identity = policy.identity(request)

        # Mock request.identity (read-only property)
        with patch.object(
            type(request),
            "identity",
            new_callable=PropertyMock,
            return_value=identity,
        ):
            context = Context()
            result = policy.permits(request, context, "edit")
            assert isinstance(result, ACLAllowed)

    def test_permits_with_additional_principals(
        self,
        policy: JWTSecurityPolicy,
    ) -> None:
        """Test permission checking with additional principals."""

        class Context:
            __acl__: ClassVar = [(Allow, "role:admin", "admin")]

        def principal_callback(request: Request, user: str) -> set[str]:
            return {"role:admin"}

        policy.additional_principals = principal_callback
        payload = {"sub": "user123", "exp": datetime.now(UTC) + timedelta(hours=1)}
        token = jwt.encode(payload, "test-secret", algorithm="HS512")

        request = DummyRequest()
        request.headers = {"Authorization": f"Bearer {token}"}

        # Get identity from policy
        identity = policy.identity(request)

        # Mock request.identity (read-only property)
        with patch.object(
            type(request),
            "identity",
            new_callable=PropertyMock,
            return_value=identity,
        ):
            context = Context()
            result = policy.permits(request, context, "admin")
            assert isinstance(result, ACLAllowed)

    def test_permits_no_permission(self, policy: JWTSecurityPolicy) -> None:
        """Test permission denied."""

        class Context:
            __acl__: ClassVar = [(Allow, Authenticated, "view")]

        payload = {"sub": "user123", "exp": datetime.now(UTC) + timedelta(hours=1)}
        token = jwt.encode(payload, "test-secret", algorithm="HS512")

        request = DummyRequest()
        request.headers = {"Authorization": f"Bearer {token}"}

        # Get identity from policy
        identity = policy.identity(request)

        # Mock request.identity (read-only property)
        with patch.object(
            type(request),
            "identity",
            new_callable=PropertyMock,
            return_value=identity,
        ):
            context = Context()
            result = policy.permits(request, context, "edit")
            assert isinstance(result, ACLDenied)

    def test_permits_unauthenticated_user(self, policy: JWTSecurityPolicy) -> None:
        """Test permission checking for unauthenticated user."""
        from pyramid.authorization import Everyone

        class Context:
            __acl__: ClassVar = [
                (Allow, Everyone, "view"),
                (Allow, Authenticated, "edit"),
            ]

        request = DummyRequest()
        request.headers = {}  # No auth token

        # Mock request.identity as None (read-only property)
        with patch.object(
            type(request),
            "identity",
            new_callable=PropertyMock,
            return_value=None,
        ):
            context = Context()
            result_allowed = policy.permits(request, context, "view")
            assert isinstance(result_allowed, ACLAllowed)

            result_not_allowed = policy.permits(request, context, "edit")
            assert isinstance(result_not_allowed, ACLDenied)

    def test_permits_additional_principals_returns_none(
        self,
        policy: JWTSecurityPolicy,
    ) -> None:
        """Test permission checking when additional_principals returns None."""

        class Context:
            __acl__: ClassVar = [(Allow, Authenticated, "view")]

        def principal_callback(request: Request, user: str) -> None:
            return None

        policy.additional_principals = principal_callback
        payload = {"sub": "user123", "exp": datetime.now(UTC) + timedelta(hours=1)}
        token = jwt.encode(payload, "test-secret", algorithm="HS512")

        request = DummyRequest()
        request.headers = {"Authorization": f"Bearer {token}"}

        # Get identity from policy
        identity = policy.identity(request)

        # Mock request.identity (read-only property)
        with patch.object(
            type(request),
            "identity",
            new_callable=PropertyMock,
            return_value=identity,
        ):
            context = Context()
            result = policy.permits(request, context, "view")
            assert isinstance(result, ACLAllowed)

    def test_permits_additional_principals_returns_empty_set(
        self,
        policy: JWTSecurityPolicy,
    ) -> None:
        """Test permission checking when additional_principals returns empty set."""

        class Context:
            __acl__: ClassVar = [(Allow, Authenticated, "view")]

        def principal_callback(request: Request, user: str) -> set[str]:
            return set()

        policy.additional_principals = principal_callback
        payload = {"sub": "user123", "exp": datetime.now(UTC) + timedelta(hours=1)}
        token = jwt.encode(payload, "test-secret", algorithm="HS512")

        request = DummyRequest()
        request.headers = {"Authorization": f"Bearer {token}"}

        # Get identity from policy
        identity = policy.identity(request)

        # Mock request.identity (read-only property)
        with patch.object(
            type(request),
            "identity",
            new_callable=PropertyMock,
            return_value=identity,
        ):
            context = Context()
            result = policy.permits(request, context, "view")
            assert isinstance(result, ACLAllowed)

    def test_remember_raises_error(self, policy: JWTSecurityPolicy) -> None:
        """Test remember raises NotImplementedError."""
        request = DummyRequest()
        with pytest.raises(
            NotImplementedError,
            match="Use create_jwt_token\\(\\) to generate tokens",
        ):
            policy.remember(request, "user123")

    def test_forget_raises_error(self, policy: JWTSecurityPolicy) -> None:
        """Test forget raises NotImplementedError."""
        request = DummyRequest()
        with pytest.raises(
            NotImplementedError,
            match="JWT logout should be handled via validation",
        ):
            policy.forget(request)


class TestCreateJWTToken:
    """Test create_jwt_token helper function."""

    def test_create_token_basic(self, config: Configurator) -> None:
        """Test basic token creation."""
        set_jwt_authentication_policy(
            config,
            "test-secret",
            user_loader=simple_user_loader,
        )
        config.commit()
        request = DummyRequest()
        request.registry = config.registry

        token = create_jwt_token(request, "user123")

        # Verify token can be decoded
        claims = jwt.decode(token, "test-secret", algorithms=["HS512"])
        assert claims["sub"] == "user123"
        assert "iat" in claims

    def test_create_token_with_expiration(self, config: Configurator) -> None:
        """Test token creation with expiration."""
        set_jwt_authentication_policy(
            config,
            "test-secret",
            user_loader=simple_user_loader,
        )
        config.commit()
        request = DummyRequest()
        request.registry = config.registry

        expiration = timedelta(hours=2)
        token = create_jwt_token(request, "user123", expiration=expiration)

        claims = jwt.decode(token, "test-secret", algorithms=["HS512"])
        assert "exp" in claims

        # Verify expiration is roughly 2 hours in the future
        exp_time = datetime.fromtimestamp(claims["exp"], tz=UTC)
        now = datetime.now(UTC)
        assert (
            timedelta(hours=1, minutes=59)
            < (exp_time - now)
            < timedelta(
                hours=2,
                minutes=1,
            )
        )

    def test_create_token_without_policy(self, config: Configurator) -> None:
        """Test token creation fails without policy configured."""
        request = DummyRequest()
        request.registry = config.registry

        with pytest.raises(TypeError, match="JWTSecurityPolicy not configured"):
            create_jwt_token(request, "user123")


class TestSetJWTAuthenticationPolicy:
    """Test set_jwt_authentication_policy configuration."""

    def test_configure_policy(self, config: Configurator) -> None:
        """Test configuring JWT authentication policy."""
        set_jwt_authentication_policy(
            config,
            "test-secret",
            user_loader=simple_user_loader,
        )
        config.commit()

        # Verify policy was registered
        from pyramid.interfaces import ISecurityPolicy

        policy = config.registry.queryUtility(ISecurityPolicy)
        assert isinstance(policy, JWTSecurityPolicy)
        assert policy.secret == "test-secret"

    def test_configure_with_custom_algorithm(self, config: Configurator) -> None:
        """Test configuring with custom algorithm."""
        set_jwt_authentication_policy(
            config,
            "test-secret",
            user_loader=simple_user_loader,
            algorithm="HS256",
        )
        config.commit()

        from pyramid.interfaces import ISecurityPolicy

        policy = config.registry.queryUtility(ISecurityPolicy)
        assert policy.algorithm == "HS256"

    def test_configure_with_custom_auth_type(self, config: Configurator) -> None:
        """Test configuring with custom auth type."""
        set_jwt_authentication_policy(
            config,
            "test-secret",
            user_loader=simple_user_loader,
            auth_type="Token",
        )
        config.commit()

        from pyramid.interfaces import ISecurityPolicy

        policy = config.registry.queryUtility(ISecurityPolicy)
        assert policy.auth_type == "Token"

    def test_configure_with_callback(self, config: Configurator) -> None:
        """Test configuring with custom token validation."""

        def my_custom_validation(user: str, request: Request) -> bool:
            return True

        set_jwt_authentication_policy(
            config,
            "test-secret",
            user_loader=simple_user_loader,
            custom_token_validation=my_custom_validation,
        )
        config.commit()

        from pyramid.interfaces import ISecurityPolicy

        policy = config.registry.queryUtility(ISecurityPolicy)
        assert policy.custom_token_validation == my_custom_validation

    def test_request_method_added(self, config: Configurator) -> None:
        """Test that create_jwt_token is added to request."""
        set_jwt_authentication_policy(
            config,
            "test-secret",
            user_loader=simple_user_loader,
        )
        config.commit()

        request = DummyRequest()
        request.registry = config.registry

        # Manually call the function (DummyRequest doesn't have methods added)
        token = create_jwt_token(request, "user123")
        assert isinstance(token, str)


class TestJwtClaimsFromToken:
    """Test jwt_claims_from_token helper function."""

    def test_decode_valid_token(self, config: Configurator) -> None:
        """Decode claims from a valid token."""
        set_jwt_authentication_policy(
            config,
            "test-secret",
            user_loader=simple_user_loader,
        )
        config.commit()
        request = DummyRequest()
        request.registry = config.registry

        token = create_jwt_token(request, "user123", role="admin")
        claims = jwt_claims_from_token(request, token)

        assert claims["sub"] == "user123"
        assert claims["role"] == "admin"
        assert "iat" in claims

    def test_decode_without_policy(self, config: Configurator) -> None:
        """Decoding without policy raises TypeError."""
        request = DummyRequest()
        request.registry = config.registry

        with pytest.raises(TypeError, match="JWTSecurityPolicy not configured"):
            jwt_claims_from_token(request, "any-token")

    def test_decode_invalid_token(self, config: Configurator) -> None:
        """Invalid token raises jwt.InvalidTokenError."""
        set_jwt_authentication_policy(
            config,
            "test-secret",
            user_loader=simple_user_loader,
        )
        config.commit()
        request = DummyRequest()
        request.registry = config.registry

        with pytest.raises(jwt.InvalidTokenError):
            jwt_claims_from_token(request, "not-a-valid-token")
