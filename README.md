# authkit

[![tests](https://github.com/dabnny1/dabnny/actions/workflows/tests.yml/badge.svg)](https://github.com/dabnny1/dabnny/actions/workflows/tests.yml)

A small authentication utility built entirely on the Python standard library:

- **Password hashing** — PBKDF2-HMAC-SHA256 with a per-password random salt.
- **`UserStore`** — a JSON-backed username → password-hash registry with atomic writes.
- **Session tokens** — HMAC-signed, expiring tokens (`payload.signature`, base64url).

## Layout

```
authkit/
├── pyproject.toml
├── src/authkit/
│   ├── __init__.py      # public API re-exports
│   ├── __main__.py      # `python -m authkit`
│   └── login.py         # implementation + argparse CLI
└── tests/
    └── test_login.py
```

## Install (editable, with dev deps)

```
python -m pip install -e ".[dev]"
```

## CLI

```
authkit [--store PATH] <command>          # or: python -m authkit ...

  add <username> [--password PW]                       register a new user
  passwd <username> [--password PW]                    change a password
  login <username> [--password PW] [--token] [--ttl N] verify credentials
  verify-token <token>                                 check a session token
```

Omit `--password` to be prompted securely. `--store` defaults to `~/.login_users.json`.
Token operations require `LOGIN_TOKEN_SECRET` in the environment.

```
export LOGIN_TOKEN_SECRET=some-long-random-string
authkit add alice
authkit login alice --token --ttl 900
authkit verify-token "<token>"
```

## Library

```python
from authkit import UserStore, hash_password, verify_password, issue_token, verify_token

store = UserStore("users.json")
store.add_user("alice", "correct horse battery staple")
store.authenticate("alice", "correct horse battery staple")  # -> True
```

## Tests

```
pytest
```

## Notes

- Load the token secret from config/environment, never a literal.
- For new projects, consider `argon2` or `bcrypt` (needs a dependency) over PBKDF2.

## License

[MIT](LICENSE)
