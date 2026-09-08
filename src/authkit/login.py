"""Login / authentication utility.

Standard library only. Provides:
  - hash_password / verify_password  (PBKDF2-HMAC-SHA256, per-password salt)
  - UserStore                        (JSON-backed user registry)
  - issue_token / verify_token       (signed, expiring session tokens)
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# --- password hashing -------------------------------------------------------

_ALGO = "sha256"
_ITERATIONS = 240_000
_SALT_BYTES = 16


def hash_password(password: str, *, iterations: int = _ITERATIONS) -> str:
    """Return an encoded hash string: 'pbkdf2_sha256$iterations$salt$hash'."""
    if not password:
        raise ValueError("password must not be empty")
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(_ALGO, password.encode("utf-8"), salt, iterations)
    return "pbkdf2_{}${}${}${}".format(
        _ALGO,
        iterations,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, encoded: str) -> bool:
    """Check a plaintext password against an encoded hash from hash_password."""
    try:
        scheme, iterations, salt_b64, hash_b64 = encoded.split("$")
        if scheme != f"pbkdf2_{_ALGO}":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        actual = hashlib.pbkdf2_hmac(
            _ALGO, password.encode("utf-8"), salt, int(iterations)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


# --- user store ------------------------------------------------------------


class AuthError(Exception):
    """Raised for authentication failures."""


@dataclass
class UserStore:
    """A tiny JSON-backed username -> password-hash registry."""

    path: Path
    _users: dict[str, str] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        if self.path.exists():
            self._users = json.loads(self.path.read_text("utf-8"))

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._users, indent=2), "utf-8")
        os.replace(tmp, self.path)

    def add_user(self, username: str, password: str) -> None:
        username = username.strip().lower()
        if not username:
            raise ValueError("username must not be empty")
        if username in self._users:
            raise ValueError(f"user {username!r} already exists")
        self._users[username] = hash_password(password)
        self._save()

    def set_password(self, username: str, password: str) -> None:
        username = username.strip().lower()
        if username not in self._users:
            raise KeyError(username)
        self._users[username] = hash_password(password)
        self._save()

    def authenticate(self, username: str, password: str) -> bool:
        encoded = self._users.get(username.strip().lower())
        if encoded is None:
            # Still run a hash to reduce user-enumeration timing signal.
            hash_password(password)
            return False
        return verify_password(password, encoded)

    def login(self, username: str, password: str) -> None:
        if not self.authenticate(username, password):
            raise AuthError("invalid username or password")


# --- session tokens -------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def issue_token(username: str, secret: str, *, ttl_seconds: int = 3600) -> str:
    """Create a signed token 'payload.signature' valid for ttl_seconds."""
    payload = {
        "sub": username,
        "exp": int(time.time()) + ttl_seconds,
        "nonce": secrets.token_hex(8),
    }
    raw = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(secret.encode("utf-8"), raw.encode("ascii"), hashlib.sha256).digest()
    return f"{raw}.{_b64url(sig)}"


def verify_token(token: str, secret: str) -> str:
    """Return the username if the token is valid and unexpired, else raise."""
    try:
        raw, sig_b64 = token.split(".")
    except ValueError:
        raise AuthError("malformed token")
    expected = hmac.new(
        secret.encode("utf-8"), raw.encode("ascii"), hashlib.sha256
    ).digest()
    if not hmac.compare_digest(expected, _b64url_decode(sig_b64)):
        raise AuthError("bad signature")
    payload = json.loads(_b64url_decode(raw))
    if payload.get("exp", 0) < time.time():
        raise AuthError("token expired")
    return payload["sub"]


# --- command-line interface ---------------------------------------------

DEFAULT_STORE = Path.home() / ".login_users.json"


def _prompt_password(confirm: bool = False) -> str:
    pw = getpass.getpass("Password: ")
    if confirm and getpass.getpass("Confirm password: ") != pw:
        raise SystemExit("error: passwords do not match")
    return pw


def _token_secret() -> str:
    secret = os.environ.get("LOGIN_TOKEN_SECRET")
    if not secret:
        raise SystemExit(
            "error: set LOGIN_TOKEN_SECRET in the environment to issue/verify tokens"
        )
    return secret


def _cmd_add(args: argparse.Namespace) -> int:
    store = UserStore(args.store)
    password = args.password or _prompt_password(confirm=True)
    try:
        store.add_user(args.username, password)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"user {args.username!r} added to {store.path}")
    return 0


def _cmd_passwd(args: argparse.Namespace) -> int:
    store = UserStore(args.store)
    password = args.password or _prompt_password(confirm=True)
    try:
        store.set_password(args.username, password)
    except KeyError:
        print(f"error: no such user {args.username!r}", file=sys.stderr)
        return 1
    print(f"password updated for {args.username!r}")
    return 0


def _cmd_login(args: argparse.Namespace) -> int:
    store = UserStore(args.store)
    password = args.password or _prompt_password()
    try:
        store.login(args.username, password)
    except AuthError as exc:
        print(f"login failed: {exc}", file=sys.stderr)
        return 1
    print(f"login OK: {args.username}")
    if args.token:
        print(issue_token(args.username, _token_secret(), ttl_seconds=args.ttl))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        user = verify_token(args.token, _token_secret())
    except AuthError as exc:
        print(f"invalid token: {exc}", file=sys.stderr)
        return 1
    print(f"token OK: {user}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authkit", description="User registration and authentication utility."
    )
    parser.add_argument(
        "--store",
        type=Path,
        default=DEFAULT_STORE,
        help=f"path to the user store JSON file (default: {DEFAULT_STORE})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="add a new user")
    p_add.add_argument("username")
    p_add.add_argument(
        "--password", help="password (omit to be prompted; safer than passing on CLI)"
    )
    p_add.set_defaults(func=_cmd_add)

    p_passwd = sub.add_parser("passwd", help="change an existing user's password")
    p_passwd.add_argument("username")
    p_passwd.add_argument("--password")
    p_passwd.set_defaults(func=_cmd_passwd)

    p_login = sub.add_parser("login", help="verify a username/password")
    p_login.add_argument("username")
    p_login.add_argument("--password")
    p_login.add_argument(
        "--token", action="store_true", help="print a session token on success"
    )
    p_login.add_argument(
        "--ttl", type=int, default=3600, help="token lifetime in seconds (default: 3600)"
    )
    p_login.set_defaults(func=_cmd_login)

    p_verify = sub.add_parser("verify-token", help="check a session token")
    p_verify.add_argument("token")
    p_verify.set_defaults(func=_cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
