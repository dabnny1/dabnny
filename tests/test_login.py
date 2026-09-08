"""Tests for the auth functions in authkit.login.

Run:  pytest
"""

import time

import pytest

from authkit import login
from authkit.login import (
    AuthError,
    UserStore,
    hash_password,
    issue_token,
    verify_password,
    verify_token,
)


# --- hash_password / verify_password -------------------------------------


def test_hash_roundtrip():
    encoded = hash_password("s3kr3t-pass")
    assert verify_password("s3kr3t-pass", encoded)


def test_hash_rejects_wrong_password():
    encoded = hash_password("correct")
    assert not verify_password("wrong", encoded)


def test_hash_is_salted_and_nondeterministic():
    a = hash_password("same")
    b = hash_password("same")
    assert a != b
    assert verify_password("same", a)
    assert verify_password("same", b)


def test_encoded_format():
    encoded = hash_password("x", iterations=1000)
    scheme, iterations, salt, digest = encoded.split("$")
    assert scheme == "pbkdf2_sha256"
    assert iterations == "1000"
    assert salt and digest


def test_hash_rejects_empty_password():
    with pytest.raises(ValueError):
        hash_password("")


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not-even-close",
        "a$b$c",  # too few fields
        "pbkdf2_sha512$1000$c2FsdA==$aGFzaA==",  # wrong scheme
        "pbkdf2_sha256$notanint$c2FsdA==$aGFzaA==",  # bad iteration count
        "pbkdf2_sha256$1000$!!!$!!!",  # undecodable base64
    ],
)
def test_verify_password_handles_malformed_encoded(bad):
    assert verify_password("whatever", bad) is False


def test_verify_password_wrong_iterations_fails():
    salt_scheme, _, salt, digest = hash_password("pw", iterations=1000).split("$")
    tampered = f"{salt_scheme}$2000${salt}${digest}"
    assert not verify_password("pw", tampered)


# --- UserStore ----------------------------------------------------------


@pytest.fixture
def store(tmp_path):
    return UserStore(tmp_path / "users.json")


def test_add_and_authenticate(store):
    store.add_user("Alice", "hunter2")
    assert store.authenticate("alice", "hunter2")
    assert not store.authenticate("alice", "nope")


def test_username_is_case_insensitive_and_trimmed(store):
    store.add_user("  Bob  ", "pw")
    assert store.authenticate("BOB", "pw")


def test_add_duplicate_user_rejected(store):
    store.add_user("carol", "pw")
    with pytest.raises(ValueError):
        store.add_user("Carol", "other")


def test_add_empty_username_rejected(store):
    with pytest.raises(ValueError):
        store.add_user("   ", "pw")


def test_authenticate_unknown_user_returns_false(store):
    assert store.authenticate("ghost", "pw") is False


def test_login_raises_on_bad_credentials(store):
    store.add_user("dave", "pw")
    store.login("dave", "pw")  # no exception
    with pytest.raises(AuthError):
        store.login("dave", "bad")
    with pytest.raises(AuthError):
        store.login("nobody", "pw")


def test_set_password(store):
    store.add_user("erin", "old")
    store.set_password("erin", "new")
    assert not store.authenticate("erin", "old")
    assert store.authenticate("erin", "new")


def test_set_password_unknown_user(store):
    with pytest.raises(KeyError):
        store.set_password("missing", "pw")


def test_persistence_across_instances(tmp_path):
    path = tmp_path / "users.json"
    UserStore(path).add_user("frank", "pw")
    assert UserStore(path).authenticate("frank", "pw")


def test_store_file_is_valid_json(tmp_path):
    import json

    path = tmp_path / "users.json"
    store = UserStore(path)
    store.add_user("grace", "pw")
    data = json.loads(path.read_text("utf-8"))
    assert list(data) == ["grace"]
    assert data["grace"].startswith("pbkdf2_sha256$")


def test_no_tmp_file_left_behind(tmp_path):
    path = tmp_path / "users.json"
    store = UserStore(path)
    store.add_user("heidi", "pw")
    assert not path.with_suffix(path.suffix + ".tmp").exists()


# --- issue_token / verify_token ---------------------------------------


SECRET = "test-secret"


def test_token_roundtrip():
    token = issue_token("alice", SECRET)
    assert verify_token(token, SECRET) == "alice"


def test_token_rejects_wrong_secret():
    token = issue_token("alice", SECRET)
    with pytest.raises(AuthError):
        verify_token(token, "other-secret")


def test_token_rejects_tampered_payload():
    token = issue_token("alice", SECRET)
    raw, sig = token.split(".")
    forged = login._b64url(b'{"sub":"admin","exp":9999999999,"nonce":"x"}')
    with pytest.raises(AuthError):
        verify_token(f"{forged}.{sig}", SECRET)


@pytest.mark.parametrize("bad", ["", "no-dot", "a.b.c", "onlyraw."])
def test_token_rejects_malformed(bad):
    with pytest.raises(AuthError):
        verify_token(bad, SECRET)


def test_token_expires():
    token = issue_token("alice", SECRET, ttl_seconds=-1)
    with pytest.raises(AuthError):
        verify_token(token, SECRET)


def test_token_valid_just_before_expiry(monkeypatch):
    token = issue_token("alice", SECRET, ttl_seconds=100)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 99)
    assert verify_token(token, SECRET) == "alice"


def test_tokens_are_unique_per_issue():
    assert issue_token("alice", SECRET) != issue_token("alice", SECRET)
