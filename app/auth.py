"""Local accounts, opaque sessions, and console-only account setup."""

import argparse
import getpass
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import sqlite3
import sys
import threading
import time

from .db import EvidenceStore

SCRYPT_N, SCRYPT_R, SCRYPT_P = 131072, 8, 1
SESSION_SECONDS = 24 * 60 * 60
IDLE_SECONDS = 30 * 60
MAX_SESSIONS = 5
MAX_FAILURES = 10
FAILURE_WINDOW = 10 * 60
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")


class LoginLimited(ValueError):
    def __init__(self, retry_after: int):
        self.retry_after = retry_after


class LoginBusy(ValueError):
    pass


def validate_password(password: str) -> bytes:
    if not isinstance(password, str) or not 15 <= len(password) <= 128 or password.isspace() or "\x00" in password:
        raise ValueError("Use a nonblank password of 15-128 characters.")
    try:
        return password.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Password must be valid Unicode text.") from exc


def password_key(password: bytes, salt: bytes) -> bytes:
    return hashlib.scrypt(password, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                          dklen=32, maxmem=256 * 1024 * 1024)


def hash_password(password: str) -> str:
    encoded = validate_password(password)
    salt = secrets.token_bytes(16)
    key = password_key(encoded, salt)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${key.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        encoded = validate_password(password)
        algorithm, n, r, p, salt, key = stored.split("$")
        if (algorithm, n, r, p) != ("scrypt", str(SCRYPT_N), str(SCRYPT_R), str(SCRYPT_P)):
            return False
        salt_bytes, expected = bytes.fromhex(salt), bytes.fromhex(key)
        if len(salt_bytes) != 16 or len(expected) != 32:
            return False
        return hmac.compare_digest(password_key(encoded, salt_bytes), expected)
    except (ValueError, TypeError, UnicodeError):
        return False


def token_hash(token: str | None) -> str | None:
    if not isinstance(token, str) or TOKEN_PATTERN.fullmatch(token) is None:
        return None
    return hashlib.sha256(token.encode("ascii")).hexdigest()


class AuthService:
    def __init__(self, store: EvidenceStore, *, clock=None):
        self.store = store
        self.clock = clock or time.time
        self.login_lock = threading.Lock()

    def initialize(self):
        with self.store.connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS owner_account (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auth_sessions (
                    token_hash TEXT PRIMARY KEY,
                    owner_id INTEGER NOT NULL REFERENCES owner_account(id) ON DELETE CASCADE,
                    created_at REAL NOT NULL, last_seen REAL NOT NULL, expires_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS login_failures (occurred_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS teammate_accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL
                );
            """)
            connection.execute("BEGIN IMMEDIATE")
            if not any(row[1] == "teammate_id" for row in connection.execute("PRAGMA table_info(auth_sessions)")):
                connection.execute("ALTER TABLE auth_sessions ADD COLUMN teammate_id INTEGER REFERENCES teammate_accounts(id) ON DELETE CASCADE")
            if not any(row[1] == "client" for row in connection.execute("PRAGMA table_info(login_failures)")):
                connection.execute("ALTER TABLE login_failures ADD COLUMN client TEXT NOT NULL DEFAULT ''")
            self._prune(connection, self.clock())

    def configured(self) -> bool:
        if not self.store.db_path.exists():
            return False
        with self.store.connect() as connection:
            if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='owner_account'").fetchone() is None:
                return False
            return connection.execute("SELECT 1 FROM owner_account WHERE id=1").fetchone() is not None

    def create_owner(self, username: str, password: str, *, teammate=False):
        if not isinstance(username, str) or re.fullmatch(r"[a-z][a-z0-9_.-]{2,31}", username) is None:
            raise ValueError("Use a lowercase username of 3-32 letters, digits, dots, underscores, or hyphens, starting with a letter.")
        stored = hash_password(password)
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            owner = connection.execute("SELECT username FROM owner_account").fetchone()
            if teammate:
                if owner is None:
                    raise ValueError("Create the owner first.")
                if owner[0] == username or connection.execute("SELECT 1 FROM teammate_accounts WHERE username=?", (username,)).fetchone():
                    raise ValueError("An account already uses this username.")
                connection.execute("INSERT INTO teammate_accounts(username,password_hash) VALUES (?,?)", (username, stored))
                return
            if owner is not None:
                raise ValueError("A local owner already exists.")
            connection.execute("INSERT INTO owner_account VALUES (1,?,?)", (username, stored))

    def remove_teammate(self, username):
        with self.store.connect() as connection:
            if not connection.execute("DELETE FROM teammate_accounts WHERE username=?", (username,)).rowcount:
                raise ValueError("No teammate account uses this username.")

    def reset_password(self, password: str):
        stored = hash_password(password)
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM owner_account").fetchone() is None:
                raise ValueError("Create the local owner first.")
            connection.execute("UPDATE owner_account SET password_hash=? WHERE id=1", (stored,))
            connection.execute("DELETE FROM auth_sessions")
            connection.execute("DELETE FROM login_failures")

    @staticmethod
    def _prune(connection, now):
        connection.execute("DELETE FROM auth_sessions WHERE expires_at <= ? OR last_seen <= ? OR created_at > ?",
                           (now, now - IDLE_SECONDS, now))
        connection.execute("DELETE FROM login_failures WHERE occurred_at <= ?", (now - FAILURE_WINDOW,))

    def login(self, username: str, password: str, previous: str | None = None, *, client="", teammates=False):
        if not self.login_lock.acquire(blocking=False):
            raise LoginBusy()
        try:
            now = self.clock()
            with self.store.connect() as connection:
                self._prune(connection, now)
                failures = connection.execute("SELECT COUNT(*), MIN(occurred_at) FROM login_failures WHERE client=?", (client,)).fetchone()
                if failures[0] >= MAX_FAILURES:
                    raise LoginLimited(max(1, int(failures[1] + FAILURE_WINDOW - now) + 1))
                account = connection.execute("SELECT username, password_hash FROM owner_account WHERE id=1").fetchone()
                teammate = (connection.execute("SELECT * FROM teammate_accounts WHERE username=?", (username.casefold(),)).fetchone()
                            if teammates else None)
                if teammate is not None:
                    account = teammate
            if account is None:
                return None
            # A wrong username still takes the owner's real password-verification path.
            valid_password = verify_password(password, account["password_hash"])
            valid_username = hmac.compare_digest(username.casefold().encode("utf-8"), account["username"].encode("utf-8"))
            with self.store.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                if not (valid_password and valid_username):
                    connection.execute("INSERT INTO login_failures(occurred_at,client) VALUES (?,?)", (now, client))
                    return None
                # A password reset between verification and insertion invalidates the login.
                teammate_id = teammate["id"] if teammate is not None else None
                current = (connection.execute("SELECT password_hash FROM teammate_accounts WHERE id=?", (teammate_id,)).fetchone()
                           if teammate_id is not None else connection.execute("SELECT password_hash FROM owner_account WHERE id=1").fetchone())
                if current is None or current["password_hash"] != account["password_hash"]:
                    return None
                self._prune(connection, now)
                connection.execute("DELETE FROM login_failures WHERE client=?", (client,))
                old_hash = token_hash(previous)
                if old_hash:
                    connection.execute("DELETE FROM auth_sessions WHERE token_hash=?", (old_hash,))
                old = connection.execute("SELECT token_hash FROM auth_sessions WHERE teammate_id IS ? ORDER BY created_at DESC, rowid DESC",
                                         (teammate_id,)).fetchall()
                for row in old[MAX_SESSIONS - 1:]:
                    connection.execute("DELETE FROM auth_sessions WHERE token_hash=?", (row["token_hash"],))
                token = secrets.token_urlsafe(32)
                connection.execute("INSERT INTO auth_sessions(token_hash,owner_id,created_at,last_seen,expires_at,teammate_id) VALUES (?,1,?,?,?,?)",
                                   (token_hash(token), now, now, now + SESSION_SECONDS, teammate_id))
            return token, account["username"]
        finally:
            self.login_lock.release()

    def current_user(self, token: str | None, *, touch: bool = True) -> dict | None:
        hashed = token_hash(token)
        if hashed is None:
            return None
        now = self.clock()
        with self.store.connect() as connection:
            row = connection.execute(
                "SELECT s.*, COALESCE(t.username,a.username) AS username FROM auth_sessions s "
                "JOIN owner_account a ON a.id=s.owner_id LEFT JOIN teammate_accounts t ON t.id=s.teammate_id WHERE token_hash=?", (hashed,)
            ).fetchone()
            if row is None:
                return None
            if now >= row["expires_at"] or now - row["last_seen"] >= IDLE_SECONDS or now < row["created_at"]:
                connection.execute("DELETE FROM auth_sessions WHERE token_hash=?", (hashed,))
                return None
            if touch:
                changed = connection.execute("UPDATE auth_sessions SET last_seen=? WHERE token_hash=?", (now, hashed))
                if changed.rowcount != 1:
                    return None
            return {"username": row["username"], "role": "teammate" if row["teammate_id"] is not None else "owner"}

    def logout(self, token: str | None):
        hashed = token_hash(token)
        if hashed:
            with self.store.connect() as connection:
                connection.execute("DELETE FROM auth_sessions WHERE token_hash=?", (hashed,))


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Sentinel accounts from the host console.")
    parser.add_argument("command", choices=("status", "setup", "reset", "add-teammate", "remove-teammate"))
    parser.add_argument("username", nargs="?", help="Teammate username")
    args = parser.parse_args()
    root = Path(os.environ.get("SENTINEL_STORAGE_DIR", str(Path(__file__).resolve().parents[1] / "storage")))
    store = EvidenceStore(root)
    auth = AuthService(store)
    try:
        configured = auth.configured()
        if args.command == "status":
            print("Local owner configured." if configured else "Local owner setup required.")
            return 0 if configured else 3
        if args.command == "setup" and configured:
            print("Local owner is already configured.")
            return 0
        if args.command == "reset" and not configured:
            print("Create a local owner first using the launcher.", file=sys.stderr)
            return 1
        if not sys.stdin.isatty():
            print("Account setup requires an interactive local console. Run Start Sentinel or this command in a terminal.", file=sys.stderr)
            return 1
        store.initialize()
        auth.initialize()
        if args.command == "remove-teammate":
            auth.remove_teammate(args.username)
            print("Teammate removed and sessions revoked.")
            return 0
        print("Account setup. The password prompt is hidden.")
        username = args.username if args.command == "add-teammate" else None
        if args.command in {"setup", "add-teammate"} and not username:
            username = input("Username (lowercase, 3-32 characters): ").strip()
        password = getpass.getpass("New password (15-128 characters): ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            print("Passwords did not match; no account change was made.", file=sys.stderr)
            return 1
        if args.command in {"setup", "add-teammate"}:
            auth.create_owner(username, password, teammate=args.command == "add-teammate")
            print("Teammate account created." if args.command == "add-teammate" else "Local owner configured.")
        else:
            auth.reset_password(password)
            print("Password reset. Existing sessions revoked; evidence retained.")
        return 0
    except (ValueError, OSError, sqlite3.Error):
        print("Account change failed. Check the username/password requirements and local storage permissions.", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nAccount change cancelled.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
