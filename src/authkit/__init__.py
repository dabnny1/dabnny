"""authkit - a small standard-library authentication utility."""

from authkit.login import (
    AuthError,
    UserStore,
    hash_password,
    issue_token,
    verify_password,
    verify_token,
)

__version__ = "0.1.0"

__all__ = [
    "AuthError",
    "UserStore",
    "hash_password",
    "verify_password",
    "issue_token",
    "verify_token",
]
