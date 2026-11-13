import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

from fastapi.testclient import TestClient
import pytest

import app.auth as auth_module
from app.main import create_app

HEADERS = {"X-Sentinel-Import": "1"}
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def anonymous(tmp_path):
    with TestClient(create_app(tmp_path / "private"), base_url="http://127.0.0.1", client=("127.0.0.1", 50200)) as client:
        yield client


@pytest.fixture
def owner(anonymous, sign_in):
    password = sign_in(anonymous)
    return anonymous, password


def login(client, password, username="test-owner"):
    return client.post("/api/auth/login", json={"username": username, "password": password}, headers=HEADERS)


def test_first_run_has_no_default_owner_and_no_public_signup(anonymous):
    assert anonymous.get("/api/auth/status").json() == {"configured": False}
    assert login(anonymous, "Not-a-real-test-password").status_code == 401
    assert anonymous.get("/api/auth/me").status_code == 401
    assert anonymous.get("/", follow_redirects=False).status_code == 303
    page = anonymous.get("/login")
    assert page.status_code == 200 and "There is no default password" in page.text
    assert anonymous.post("/api/auth/setup", json={}, headers=HEADERS).status_code == 401
    assert anonymous.get("/health").json()["authentication_required"] is True


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/uploads"), ("GET", "/api/uploads/" + "a" * 32),
    ("GET", "/api/events?upload_id=" + "a" * 32),
    ("GET", "/api/uploads/" + "a" * 32 + "/rejected"),
    ("GET", "/api/timeline"), ("GET", "/api/reports/" + "a" * 32),
    ("POST", "/api/uploads?format=windows-json&filename=private.json"),
    ("DELETE", "/api/uploads/" + "a" * 32),
])
def test_every_evidence_route_denies_signed_out_requests(anonymous, method, path):
    response = anonymous.request(method, path, headers=HEADERS)
    assert response.status_code == 401
    assert response.json() == {"detail": "Sign in to access local evidence."}
    assert response.headers["cache-control"] == "no-store"


def test_password_and_session_storage_cookie_attributes(owner):
    client, password = owner
    token = client.cookies.get(client.app.state.session_cookie_name)
    with client.app.state.store.connect() as connection:
        account = connection.execute("SELECT * FROM owner_account").fetchone()
        session = connection.execute("SELECT * FROM auth_sessions").fetchone()
    assert account["password_hash"].startswith("scrypt$131072$8$1$")
    assert password not in account["password_hash"] and session["token_hash"] != token
    assert session["token_hash"] == auth_module.token_hash(token)
    response = login(client, password)
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and "Path=/" in cookie
    assert "Max-Age=86400" in cookie and "Domain=" not in cookie
    assert token not in response.text and password not in response.text
    assert client.get("/api/auth/me").json() == {"username": "test-owner", "role": "owner"}


def test_login_rotates_token_and_logout_revokes_it(owner):
    client, password = owner
    name = client.app.state.session_cookie_name
    old = client.cookies.get(name)
    assert login(client, password).status_code == 200
    current = client.cookies.get(name)
    assert current != old
    assert client.app.state.auth.current_user(old) is None
    response = client.post("/api/auth/logout", headers=HEADERS)
    assert response.status_code == 204 and "Max-Age=0" in response.headers["set-cookie"]
    client.cookies.set(name, current)
    assert client.get("/api/uploads").status_code == 401


def test_one_logout_does_not_revoke_an_independent_session(owner):
    client, password = owner
    name = client.app.state.session_cookie_name
    first = client.cookies.get(name)
    client.cookies.clear()
    assert login(client, password).status_code == 200
    second = client.cookies.get(name)
    client.post("/api/auth/logout", headers=HEADERS)
    assert client.app.state.auth.current_user(second) is None
    assert client.app.state.auth.current_user(first)["username"] == "test-owner"


@pytest.mark.parametrize("expiry", ["idle", "absolute"])
def test_server_enforces_idle_and_absolute_expiration(owner, expiry):
    client, _ = owner
    auth = client.app.state.auth
    with client.app.state.store.connect() as connection:
        row = connection.execute("SELECT * FROM auth_sessions").fetchone()
        if expiry == "absolute":
            connection.execute("UPDATE auth_sessions SET last_seen=?", (row["expires_at"] - 1,))
    future = row["created_at"] + auth_module.IDLE_SECONDS + 1 if expiry == "idle" else row["expires_at"] + 1
    auth.clock = lambda: future
    assert client.get("/api/uploads").status_code == 401
    with client.app.state.store.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0] == 0


def test_forged_cookie_is_not_authentication(owner):
    client, _ = owner
    client.cookies.clear()
    client.cookies.set(client.app.state.session_cookie_name, secrets.token_urlsafe(32))
    assert client.get("/api/timeline").status_code == 401
    assert client.get("/static/index.html", follow_redirects=False).status_code == 303


def test_bad_usernames_and_passwords_have_same_response(owner):
    client, password = owner
    wrong_name = login(client, password, username="missing-owner")
    wrong_password = login(client, "Wrong-test-password-only")
    assert wrong_name.status_code == wrong_password.status_code == 401
    assert wrong_name.json() == wrong_password.json() == {"detail": "Incorrect username or password."}
    assert client.get("/api/auth/me").status_code == 200


@pytest.mark.parametrize("body", [
    {"username": "x", "password": ["SECRET-TEST-ONLY"]},
    {"username": "x", "password": "SECRET-TEST-ONLY", "extra": True},
    {"username": "x", "password": "SECRET-TEST-ONLY" * 20},
    {"username": "x", "password": "\ud800"},
    ["SECRET-TEST-ONLY"],
])
def test_bad_login_payload_never_echoes_submitted_credentials(anonymous, body):
    response = anonymous.post("/api/auth/login", content=json.dumps(body),
                              headers=HEADERS | {"Content-Type": "application/json"})
    assert response.status_code == 400
    assert "SECRET-TEST-ONLY" not in response.text


def test_login_body_limits_json_framing_and_mutation_guards(anonymous):
    assert anonymous.post("/api/auth/login", content=b'x' * 8193,
                          headers=HEADERS | {"Content-Type": "application/json"}).status_code == 413
    assert anonymous.post("/api/auth/login", content=b'{broken',
                          headers=HEADERS | {"Content-Type": "application/json"}).status_code == 400
    assert anonymous.post("/api/auth/login", json={}).status_code == 403
    assert anonymous.post("/api/auth/login", json={}, headers=HEADERS | {"Origin": "https://other.example"}).status_code == 403
    assert anonymous.post("/api/auth/logout", headers=HEADERS).status_code == 204


def test_failed_login_limit_survives_restart_and_expires(owner, monkeypatch):
    client, password = owner
    monkeypatch.setattr(auth_module, "MAX_FAILURES", 2)
    for _ in range(2):
        assert login(client, "Wrong-test-password-only").status_code == 401
    limited = login(client, password)
    assert limited.status_code == 429 and int(limited.headers["retry-after"]) > 0
    application = create_app(client.app.state.store.root)
    with TestClient(application, base_url="http://127.0.0.1", client=("127.0.0.1", 50201)) as restarted:
        assert login(restarted, password).status_code == 429
        now = application.state.auth.clock()
        application.state.auth.clock = lambda: now + auth_module.FAILURE_WINDOW + 1
        assert login(restarted, password).status_code == 200


def test_console_recovery_revokes_sessions_and_preserves_evidence(owner):
    client, old_password = owner
    source = b'{"Id":4625,"Message":"Synthetic recovery evidence"}'
    item = client.post("/api/uploads?format=windows-json&filename=recovery.json", content=source,
                       headers=HEADERS | {"Content-Type": "application/json"}).json()
    replacement = "Recovery-test-only-" + secrets.token_urlsafe(24)
    client.app.state.auth.reset_password(replacement)
    assert client.get("/api/uploads").status_code == 401
    assert login(client, old_password).status_code == 401
    assert login(client, replacement).status_code == 200
    assert client.get(f"/api/uploads/{item['id']}").status_code == 200
    assert client.app.state.store.blob_path(item["id"]).read_bytes() == source


def test_session_count_is_bounded(owner):
    client, password = owner
    auth = client.app.state.auth
    first = client.cookies.get(client.app.state.session_cookie_name)
    newest = None
    for _ in range(auth_module.MAX_SESSIONS):
        newest, _ = auth.login("test-owner", password)
    assert auth.current_user(first) is None
    assert auth.current_user(newest) is not None
    with client.app.state.store.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0] == auth_module.MAX_SESSIONS


def test_hash_work_is_not_queued_for_parallel_logins(owner):
    client, password = owner
    with client.app.state.auth.login_lock:
        response = login(client, password)
    assert response.status_code == 429 and response.headers["retry-after"] == "1"


def test_account_setup_cli_requires_hidden_interactive_input(tmp_path):
    root = tmp_path / "no-account"
    environment = dict(os.environ, SENTINEL_STORAGE_DIR=str(root))
    process = subprocess.run([sys.executable, "-m", "app.auth", "setup"], cwd=ROOT,
                             input="", capture_output=True, text=True, env=environment, timeout=15)
    assert process.returncode == 1
    assert "interactive local console" in process.stderr
    assert not root.exists()
