# pyramid_jwt2

[![PyPI version](https://img.shields.io/pypi/v/pyramid_jwt2.svg)](https://pypi.org/project/pyramid_jwt2/)
[![Python versions](https://img.shields.io/pypi/pyversions/pyramid_jwt2.svg)](https://pypi.org/project/pyramid_jwt2/)
[![CI](https://github.com/teamniteo/pyramid_jwt2/actions/workflows/ci.yml/badge.svg)](https://github.com/teamniteo/pyramid_jwt2/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/pypi/l/pyramid_jwt2.svg)](https://github.com/teamniteo/pyramid_jwt2/blob/main/LICENSE)

JWT authentication security policy for Pyramid 2.0+.

This package provides a modern, type-safe JWT authentication implementation for Pyramid web framework, an alternative to the existing `pyramid_jwt` for users using Pyramid 2.0's unified security policy.


## Features

- ✅ Pyramid 2.0+ unified security policy (no deprecated auth/authz split)
- ✅ JWT token creation and validation using PyJWT
- ✅ ACL-based permissions support
- ✅ Custom validation callbacks
- ✅ Bearer token authentication
- ✅ Fully typed (PEP 561 compatible)

## Installation

```bash
pip install pyramid-jwt2
```

## Usage

### Basic Configuration

```python
from pyramid.config import Configurator
from pyramid_jwt2 import set_jwt_authentication_policy

def load_user(userid, request):
    """Load user from database."""
    return request.db.query(User).filter(User.id == userid).first()

def main(global_config, **settings):
    config = Configurator(settings=settings)

    # Configure JWT authentication
    set_jwt_authentication_policy(
        config,
        secret=settings['jwt.secret'],
        user_loader=load_user,  # Required: load user from DB
        auth_type='Bearer',     # Authorization: Bearer <token>
    )

    return config.make_wsgi_app()
```

### Creating Tokens

```python
from pyramid.view import view_config

@view_config(route_name='login', request_method='POST', renderer='json')
def login(request):
    # Validate credentials...
    user_id = "12345"

    # Create JWT token
    token = request.create_jwt_token(
        user_id,
        expiration=timedelta(hours=48)
    )

    return {'token': token}
```

### Protected Views

```python
from pyramid.view import view_config

@view_config(
    route_name='protected',
    request_method='GET',
    renderer='json',
    permission='authenticated'
)
def protected_view(request):
    user_id = request.authenticated_userid
    return {'user_id': user_id}
```

### Custom Token Validation

Implement custom token validation (e.g., invalidate token if it was issued
before the last user logout, invalidate token if it was issued before password
changed, etc.):

```python
def load_user(userid: str, request: Request) -> User | None:
    """Load user from database."""
    return request.db.query(User).filter(User.id == userid).first()

def validate_token(user: User, request: Request) -> bool:
    """
    Validate token - receives user object from user_loader.
    Return True if token is valid, False if invalid.
    """
    if user is None:
        return False  # User not found

    # Check if token was issued before user logged out
    if user.logged_out:
        issued_at = datetime.fromtimestamp(request.jwt_claims['iat'])
        if issued_at < user.logged_out:
            return False  # Token invalidated by logout

    return True  # Valid token

# Configure with user_loader and validation
set_jwt_authentication_policy(
    config,
    secret=settings['jwt.secret'],
    user_loader=load_user,
    custom_token_validation=validate_token,
)
```

### ACL Permissions

Use with Pyramid's ACL system:

```python
from pyramid.authorization import Allow, Authenticated

class RootFactory:
    def __init__(self, request):
        self.request = request

    @property
    def __acl__(self):
        if self.request.identity:
            # Grant permissions using Authenticated principal
            return [
                (Allow, Authenticated, 'view'),
                (Allow, Authenticated, 'edit'),
            ]
        return []

config.set_root_factory(RootFactory)
```

For user-specific permissions, the userid is also available as a principal:

```python
# Allow document owner to delete
class DocumentContext:
    def __init__(self, document_id, request):
        self.document = get_document(document_id)

    @property
    def __acl__(self):
        return [
            (Allow, Authenticated, 'view'),
            (Allow, self.document.owner_id, 'delete'),  # Only owner can delete
        ]
```

###  Additional Principals (Role-Based Access)

Add custom principals like roles for cleaner ACLs:

```python
def load_user(userid, request):
    return request.db.query(User).filter(User.id == userid).first()

def add_role_principals(request, user: User) -> set[str]:
    """Add role-based principals."""
    principals = set()

    if user and user.role:
        principals.add(f"role:{user.role}")  # e.g., "role:admin"

    return principals

# Configure with principals callback
set_jwt_authentication_policy(
    config,
    secret=settings['jwt.secret'],
    user_loader=load_user,
    additional_principals=add_role_principals,
)

# Now use clean role-based ACLs
class RootFactory:
    @property
    def __acl__(self):
        return [
            (Allow, 'role:admin', ALL_PERMISSIONS),
            (Allow, 'role:editor', 'edit'),
            (Allow, Authenticated, 'view'),
        ]
```

## Configuration Options

### `set_jwt_authentication_policy(config, secret, user_loader, **options)`

- **`secret`** (str, required): Secret key for signing/verifying JWTs
- **`user_loader`** (callable, required): Function `(userid, request) -> user object | None`
  - Loads user from database once and caches it
  - Return `None` if user doesn't exist (auth fails)
- **`algorithm`** (str, optional): JWT algorithm (default: `"HS512"`)
- **`auth_type`** (str, optional): Authorization header type (default: `"Bearer"`)
- **`custom_token_validation`** (callable, optional): Function `(user, request) -> bool`
  - Return `True` if token is valid, `False` if invalid
  - Receives user object from user_loader
  - Use for logout timestamps, banned users, etc.
- **`additional_principals`** (callable, optional): Function `(request, user) -> set[str]`
  - Returns additional principals to add (e.g., `{"role:admin"}`)
  - Enables clean role-based ACLs

## API Reference

### Request Methods

After configuration, these methods are available on the request object:

- **`request.create_jwt_token(userid, expiration=None, **claims)`**: Create a JWT token
- **`request.jwt_claims_from_token(token)`**: Decode and validate an arbitrary token, returning its claims. Raises `jwt.InvalidTokenError` if the token is invalid or expired
- **`request.authenticated_userid`**: Get the authenticated user ID
- **`request.jwt_claims`**: Access decoded JWT claims. Only populated after `request.identity` has been resolved and the token decoded successfully
- **`request.identity`**: Get identity dict with:
  - `userid`: User ID from token
  - `claims`: Decoded JWT claims
  - `user`: User object from user_loader (cached, no redundant DB queries)

### Stateless Authentication

JWT is stateless, meaning authentication doesn't use cookies or sessions. Therefore:

- **`remember()`** raises `NotImplementedError` - use `create_jwt_token()` instead
- **`forget()`** raises `NotImplementedError` - handle logout via `custom_token_validation`

## Requirements

- Python 3.11+
- Pyramid 2.0+
- PyJWT 2.0+

## Development

This project uses [uv](https://docs.astral.sh/uv/) and [ruff](https://docs.astral.sh/ruff/).

```bash
uv sync --dev   # install dependencies into .venv/
make check      # ruff lint + format check
make unit       # run tests with coverage
make tests      # check + unit (run before every commit)
make build      # build sdist + wheel into dist/
```

See [RELEASE.md](RELEASE.md) for the release process.

## License

MIT
