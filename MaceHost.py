"""MaceHost — accounts and friends API for Mace Launcher.

Run:
    python -m pip install fastapi uvicorn
    python MaceHost.py

The service listens on 0.0.0.0:$PORT (8000 by default). Clients read the
public address from mace_server.txt; that file is not used as the bind address.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import warnings
import time
import uuid
import mimetypes
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # Optional locally; required when DATABASE_URL is PostgreSQL.
    psycopg = None
    dict_row = None

from fastapi import Depends, FastAPI, Header, HTTPException, Query, UploadFile, File, Form
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
_USE_POSTGRES = DATABASE_URL.lower().startswith(("postgres://", "postgresql://"))
if DATABASE_URL and not _USE_POSTGRES:
    raise RuntimeError("DATABASE_URL must be a PostgreSQL connection URL (postgresql://...).")
if _USE_POSTGRES and psycopg is None:
    raise RuntimeError("DATABASE_URL is set to PostgreSQL, but psycopg is missing. Install requirements.txt.")

# Local development defaults to a database beside the source. On hosted runtimes
# without DATABASE_URL, use /tmp so a read-only /app directory does not crash boot.
# /tmp is ephemeral: use Hostless managed PostgreSQL + DATABASE_URL for real accounts.
_configured_db_path = os.environ.get("MACE_ACCOUNTS_DB", "").strip()
if _configured_db_path:
    DATABASE_PATH = Path(_configured_db_path).expanduser()
elif os.environ.get("PORT") and not _USE_POSTGRES:
    DATABASE_PATH = Path(os.environ.get("MACE_TEMP_DB_PATH", "/tmp/mace_accounts.db"))
    warnings.warn(
        "DATABASE_URL is not configured. MaceHost is using temporary SQLite at "
        f"{DATABASE_PATH}; accounts may be lost after a restart or redeploy. "
        "Connect a managed PostgreSQL database for persistent accounts.",
        RuntimeWarning,
    )
else:
    DATABASE_PATH = BASE_DIR / "mace_accounts.db"

PBKDF2_ROUNDS = 310_000
SESSION_SECONDS = 60 * 60 * 24 * 30

app = FastAPI(
    title="MaceHost — Mace Accounts API",
    description="Unified accounts, profiles, and friends for Mace Launcher.",
    version="1.2.0",
)

# Access tokens are sent explicitly as Bearer tokens; cookies are not used.
# For production, set MACE_ALLOWED_ORIGINS to a comma-separated allow-list.
_origins_env = os.environ.get("MACE_ALLOWED_ORIGINS", "").strip()
_allowed_origins = [item.strip() for item in _origins_env.split(",") if item.strip()] if _origins_env else ["*"]
# Always permit the public Mace Launcher website even when a custom allow-list is set.
_site_origin = "https://mace-launcher.onrender.com"
if "*" not in _allowed_origins and _site_origin not in _allowed_origins:
    _allowed_origins.append(_site_origin)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
    max_age=600,
)


class RegisterBody(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=8, max_length=256)


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=254)  # username or email
    password: str = Field(min_length=1, max_length=256)


class FriendTargetBody(BaseModel):
    mace_id: str = Field(min_length=3, max_length=40)


class PresenceBody(BaseModel):
    status: str = Field(default="launcher", pattern="^(offline|launcher|minecraft)$")
    game_version: str = Field(default="", max_length=32)
    playtime_delta: int = Field(default=0, ge=0, le=60)


class ProfileUpdateBody(BaseModel):
    display_name: str = Field(default="", max_length=32)
    bio: str = Field(default="", max_length=240)


class ChatMessageBody(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class _PostgresCursor:
    """Small adapter preserving the sqlite-style API used by this service."""
    def __init__(self, cursor, lastrowid=None, prefetched=None):
        self._cursor = cursor
        self.lastrowid = lastrowid
        self._prefetched = prefetched

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def fetchone(self):
        if self._prefetched is not None:
            row, self._prefetched = self._prefetched, None
            return row
        return self._cursor.fetchone()

    def fetchall(self):
        rows = self._cursor.fetchall()
        if self._prefetched is not None:
            rows.insert(0, self._prefetched)
            self._prefetched = None
        return rows


class _PostgresConnection:
    def __init__(self, connection):
        self._connection = connection

    def execute(self, sql: str, params=()):
        statement = sql.strip()
        # Translate the small subset of SQLite SQL used by this API to PostgreSQL.
        statement = re.sub(r"^INSERT\s+OR\s+IGNORE\s+INTO\s+", "INSERT INTO ", statement, flags=re.I)
        has_ignore = bool(re.match(r"^INSERT\s+OR\s+IGNORE\s+INTO\s+", sql.strip(), flags=re.I))
        statement = statement.replace("?", "%s")
        table_match = re.match(r"^INSERT\s+INTO\s+(users|friend_requests)\b", statement, flags=re.I)
        wants_id = bool(table_match) and " RETURNING " not in statement.upper()
        if wants_id:
            statement = statement.rstrip().rstrip(";") + " RETURNING id"
        if has_ignore:
            statement = statement.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
        cur = self._connection.cursor()
        cur.execute(statement, tuple(params or ()))
        if wants_id:
            row = cur.fetchone()
            return _PostgresCursor(cur, lastrowid=(row["id"] if row else None))
        return _PostgresCursor(cur)

    def executescript(self, script: str):
        # Schema contains independent CREATE TABLE/INDEX statements only.
        for statement in script.split(";"):
            if statement.strip():
                self.execute(statement)


@contextmanager
def database():
    if _USE_POSTGRES:
        # psycopg dict_row lets existing API code keep accessing row["column"].
        conn = psycopg.connect(DATABASE_URL.replace("postgres://", "postgresql://", 1), row_factory=dict_row, connect_timeout=10)
        try:
            yield _PostgresConnection(conn)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        return

    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DATABASE_PATH), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    schema = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mace_id TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL,
            username_key TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            email_key TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
        CREATE TABLE IF NOT EXISTS friend_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            responded_at TEXT,
            CHECK(requester_id <> recipient_id)
        );
        CREATE INDEX IF NOT EXISTS idx_friend_requests_recipient_status
            ON friend_requests(recipient_id, status);
        CREATE INDEX IF NOT EXISTS idx_friend_requests_requester_status
            ON friend_requests(requester_id, status);
        CREATE TABLE IF NOT EXISTS friendships (
            user_a_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            user_b_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            PRIMARY KEY(user_a_id, user_b_id),
            CHECK(user_a_id < user_b_id)
        );
        CREATE TABLE IF NOT EXISTS blocks (
            blocker_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            blocked_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            PRIMARY KEY(blocker_id, blocked_id),
            CHECK(blocker_id <> blocked_id)
        );
        """
    if _USE_POSTGRES:
        # SERIAL primary keys + BIGINT foreign keys are native PostgreSQL types.
        schema = schema.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
        schema = re.sub(r"\bINTEGER NOT NULL REFERENCES", "BIGINT NOT NULL REFERENCES", schema)
    with database() as db:
        db.executescript(schema)


init_db()

# Social extensions are separate tables so existing accounts migrate without data loss.
_SOCIAL_SCHEMA = """
CREATE TABLE IF NOT EXISTS user_profiles (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL DEFAULT '',
    bio TEXT NOT NULL DEFAULT '',
    minecraft_seconds BIGINT NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS presence (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'offline',
    last_seen BIGINT NOT NULL DEFAULT 0,
    game_version TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS attachments (
    file_id TEXT PRIMARY KEY,
    owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    original_name TEXT NOT NULL,
    content_type TEXT NOT NULL,
    file_size BIGINT NOT NULL DEFAULT 0,
    stored_path TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    expires_at BIGINT,
    deleted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_attachments_expiry ON attachments(expires_at, deleted);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    text TEXT NOT NULL DEFAULT '',
    attachment_id TEXT REFERENCES attachments(file_id) ON DELETE SET NULL,
    message_type TEXT NOT NULL DEFAULT 'text',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, recipient_id, id);
CREATE TABLE IF NOT EXISTS profile_screenshots (
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    attachment_id TEXT NOT NULL UNIQUE REFERENCES attachments(file_id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    PRIMARY KEY(user_id, attachment_id)
);
"""
if _USE_POSTGRES:
    _SOCIAL_SCHEMA = _SOCIAL_SCHEMA.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
with database() as _db:
    _db.executescript(_SOCIAL_SCHEMA)

if os.environ.get("MACE_UPLOAD_DIR"):
    UPLOAD_DIR = Path(os.environ["MACE_UPLOAD_DIR"]).expanduser()
elif os.environ.get("PORT"):
    UPLOAD_DIR = Path(os.environ.get("MACE_TEMP_DB_PATH", "/tmp/mace_accounts.db")).parent / "mace_uploads"
else:
    UPLOAD_DIR = BASE_DIR / "mace_uploads"
MAX_UPLOAD_BYTES = max(1, int(os.environ.get("MACE_MAX_UPLOAD_MB", "100"))) * 1024 * 1024
CHAT_FILE_LIFETIME_SECONDS = 60 * 60
PRESENCE_STALE_SECONDS = 90


def _hash_password(password: str, salt_hex: Optional[str] = None) -> str:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return salt.hex() + "$" + digest.hex()


def _verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, expected = stored.split("$", 1)
        actual = _hash_password(password, salt_hex).split("$", 1)[1]
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _new_session(db: sqlite3.Connection, user_id: int) -> str:
    token = secrets.token_urlsafe(40)
    db.execute(
        "INSERT INTO sessions(token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (hashlib.sha256(token.encode("utf-8")).hexdigest(), user_id, int(time.time()) + SESSION_SECONDS, utc_now()),
    )
    return token


def _public_user(row: sqlite3.Row) -> dict:
    keys = set(row.keys()) if hasattr(row, "keys") else set(row) if isinstance(row, dict) else set()
    status = str(row["presence_status"] or "offline") if "presence_status" in keys else "offline"
    seen = int(row["presence_last_seen"] or 0) if "presence_last_seen" in keys else 0
    if not seen or time.time() - seen > PRESENCE_STALE_SECONDS:
        status = "offline"
    return {
        "mace_id": row["mace_id"],
        "username": row["username"],
        "created_at": row["created_at"],
        "avatar_url": None,
        "status": status if status in ("offline", "launcher", "minecraft") else "offline",
        "game_version": str(row["presence_game_version"] or "") if "presence_game_version" in keys else "",
    }


def current_user(authorization: Optional[str] = Header(default=None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Войдите в аккаунт Mace Launcher.")
    token = authorization.split(None, 1)[1].strip()
    if not token or len(token) > 512:
        raise HTTPException(status_code=401, detail="Недействительная сессия.")
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with database() as db:
        db.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))
        row = db.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?",
            (token_hash, int(time.time())),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Сессия истекла. Войдите снова.")
        return dict(row)


def _blocked_either_way(db: sqlite3.Connection, first_id: int, second_id: int) -> bool:
    return db.execute(
        "SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?) LIMIT 1",
        (first_id, second_id, second_id, first_id),
    ).fetchone() is not None


def _are_friends(db: sqlite3.Connection, first_id: int, second_id: int) -> bool:
    a, b = sorted((int(first_id), int(second_id)))
    return db.execute("SELECT 1 FROM friendships WHERE user_a_id=? AND user_b_id=?", (a, b)).fetchone() is not None


def _user_by_mace_id(db: sqlite3.Connection, mace_id: str):
    return db.execute("SELECT * FROM users WHERE upper(mace_id)=upper(?)", (mace_id.strip(),)).fetchone()


@app.get("/")
def root():
    return {"service": "MaceHost", "api": "/docs", "health": "/health"}


@app.get("/health")
def health():
    return {
        "ok": True,
        "service": "MaceHost",
        "api_version": "1.2.0",
        "database": "postgresql" if _USE_POSTGRES else "sqlite",
        "persistent_database": bool(_USE_POSTGRES or os.environ.get("MACE_ACCOUNTS_DB")),
    }


@app.post("/register")
def register(body: RegisterBody):
    username = body.username.strip()
    email = body.email.strip()
    if len(username) < 3 or len(username) > 32:
        raise HTTPException(status_code=422, detail="Имя должно содержать от 3 до 32 символов.")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(status_code=422, detail="Введите корректный адрес электронной почты.")
    if len(body.password) < 8:
        raise HTTPException(status_code=422, detail="Пароль должен содержать минимум 8 символов.")
    username_key = username.casefold()
    email_key = email.casefold()
    mace_id = "MACE-" + secrets.token_hex(4).upper()
    try:
        with database() as db:
            cur = db.execute(
                "INSERT INTO users(mace_id,username,username_key,email,email_key,password_hash,created_at) VALUES (?,?,?,?,?,?,?)",
                (mace_id, username, username_key, email, email_key, _hash_password(body.password), utc_now()),
            )
            user_id = int(cur.lastrowid)
            token = _new_session(db, user_id)
    except ((sqlite3.IntegrityError,) + ((psycopg.IntegrityError,) if _USE_POSTGRES else ())):
        with database() as db:
            if db.execute("SELECT 1 FROM users WHERE username_key=?", (username_key,)).fetchone():
                raise HTTPException(status_code=409, detail="Это имя уже занято.")
            if db.execute("SELECT 1 FROM users WHERE email_key=?", (email_key,)).fetchone():
                raise HTTPException(status_code=409, detail="Аккаунт с такой почтой уже существует.")
        raise HTTPException(status_code=409, detail="Не удалось создать аккаунт. Попробуйте другое имя или почту.")
    return {"username": username, "mace_id": mace_id, "token": token}


@app.post("/login")
def login(body: LoginBody):
    identity = body.username.strip()
    identity_key = identity.casefold()
    with database() as db:
        row = db.execute(
            "SELECT * FROM users WHERE username_key=? OR email_key=? LIMIT 1",
            (identity_key, identity_key),
        ).fetchone()
        if not row or not _verify_password(body.password, row["password_hash"]):
            # Deliberately avoid disclosing whether username or email exists.
            raise HTTPException(status_code=401, detail="Неверное имя, почта или пароль.")
        token = _new_session(db, int(row["id"]))
        return {"username": row["username"], "mace_id": row["mace_id"], "token": token}


@app.get("/me")
def me(user: dict = Depends(current_user)):
    return _profile_payload(user, include_email=True)


@app.post("/logout")
def logout(user: dict = Depends(current_user), authorization: Optional[str] = Header(default=None)):
    token = authorization.split(None, 1)[1].strip() if authorization else ""
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with database() as db:
        db.execute("DELETE FROM sessions WHERE token_hash=? AND user_id=?", (token_hash, user["id"]))
    return {"ok": True}


@app.get("/users/search")
def search_users(q: str = Query(default="", max_length=80), user: dict = Depends(current_user)):
    query = q.strip()
    if len(query) < 2:
        return {"users": []}
    with database() as db:
        rows = db.execute(
            """SELECT u.*, p.status AS presence_status, p.last_seen AS presence_last_seen, p.game_version AS presence_game_version
               FROM users u LEFT JOIN presence p ON p.user_id=u.id
               WHERE u.id<>? AND (u.username_key LIKE ? OR upper(u.mace_id) LIKE upper(?))
                 AND NOT EXISTS (
                    SELECT 1 FROM blocks b WHERE
                    (b.blocker_id=? AND b.blocked_id=u.id) OR
                    (b.blocker_id=u.id AND b.blocked_id=?)
                 )
               ORDER BY u.username_key LIMIT 20""",
            (user["id"], "%" + query.casefold() + "%", "%" + query + "%", user["id"], user["id"]),
        ).fetchall()
        return {"users": [_public_user(row) for row in rows]}


@app.post("/friends/request")
def send_friend_request(body: FriendTargetBody, user: dict = Depends(current_user)):
    with database() as db:
        target = _user_by_mace_id(db, body.mace_id)
        if not target:
            raise HTTPException(status_code=404, detail="Аккаунт с таким MaceId не найден.")
        if int(target["id"]) == int(user["id"]):
            raise HTTPException(status_code=400, detail="Нельзя добавить самого себя в друзья.")
        target_id = int(target["id"])
        me_id = int(user["id"])
        if _blocked_either_way(db, me_id, target_id):
            raise HTTPException(status_code=403, detail="Взаимодействие с этим пользователем ограничено.")
        if _are_friends(db, me_id, target_id):
            raise HTTPException(status_code=409, detail="Вы уже друзья.")
        incoming = db.execute(
            "SELECT id FROM friend_requests WHERE requester_id=? AND recipient_id=? AND status='pending' LIMIT 1",
            (target_id, me_id),
        ).fetchone()
        if incoming:
            raise HTTPException(status_code=409, detail="Этот пользователь уже отправил вам заявку. Примите её в разделе заявок.")
        existing = db.execute(
            "SELECT id FROM friend_requests WHERE requester_id=? AND recipient_id=? AND status='pending' LIMIT 1",
            (me_id, target_id),
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="Заявка уже отправлена.")
        cur = db.execute(
            "INSERT INTO friend_requests(requester_id,recipient_id,status,created_at) VALUES (?,?, 'pending', ?)",
            (me_id, target_id, utc_now()),
        )
        return {"ok": True, "request_id": int(cur.lastrowid), "message": "Заявка в друзья отправлена."}


@app.get("/friends")
def get_friends(user: dict = Depends(current_user)):
    me_id = int(user["id"])
    with database() as db:
        friends_rows = db.execute(
            """SELECT u.*, p.status AS presence_status, p.last_seen AS presence_last_seen, p.game_version AS presence_game_version
               FROM friendships f JOIN users u ON u.id =
               CASE WHEN f.user_a_id=? THEN f.user_b_id ELSE f.user_a_id END
               LEFT JOIN presence p ON p.user_id=u.id
               WHERE f.user_a_id=? OR f.user_b_id=? ORDER BY u.username_key""",
            (me_id, me_id, me_id),
        ).fetchall()
        incoming_rows = db.execute(
            """SELECT fr.id AS request_id, fr.created_at, u.*, p.status AS presence_status, p.last_seen AS presence_last_seen, p.game_version AS presence_game_version
               FROM friend_requests fr JOIN users u ON u.id=fr.requester_id
               LEFT JOIN presence p ON p.user_id=u.id
               WHERE fr.recipient_id=? AND fr.status='pending' ORDER BY fr.created_at DESC""",
            (me_id,),
        ).fetchall()
        outgoing_rows = db.execute(
            """SELECT fr.id AS request_id, fr.created_at, u.*, p.status AS presence_status, p.last_seen AS presence_last_seen, p.game_version AS presence_game_version
               FROM friend_requests fr JOIN users u ON u.id=fr.recipient_id
               LEFT JOIN presence p ON p.user_id=u.id
               WHERE fr.requester_id=? AND fr.status='pending' ORDER BY fr.created_at DESC""",
            (me_id,),
        ).fetchall()
        friends = [_public_user(row) for row in friends_rows if not _blocked_either_way(db, me_id, int(row["id"]))]
        incoming = [{"request_id": row["request_id"], **_public_user(row), "created_at": row["created_at"]} for row in incoming_rows]
        outgoing = [{"request_id": row["request_id"], **_public_user(row), "created_at": row["created_at"]} for row in outgoing_rows]
        return {"friends": friends, "incoming": incoming, "outgoing": outgoing}


def _respond_request(request_id: int, user: dict, accept: bool):
    me_id = int(user["id"])
    with database() as db:
        row = db.execute(
            "SELECT * FROM friend_requests WHERE id=? AND recipient_id=? AND status='pending'",
            (request_id, me_id),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Заявка не найдена или уже обработана.")
        sender_id = int(row["requester_id"])
        if _blocked_either_way(db, me_id, sender_id):
            db.execute("UPDATE friend_requests SET status='rejected', responded_at=? WHERE id=?", (utc_now(), request_id))
            raise HTTPException(status_code=403, detail="Взаимодействие с этим пользователем ограничено.")
        if accept:
            a, b = sorted((me_id, sender_id))
            db.execute("INSERT OR IGNORE INTO friendships(user_a_id,user_b_id,created_at) VALUES (?,?,?)", (a, b, utc_now()))
            status = "accepted"
        else:
            status = "rejected"
        db.execute("UPDATE friend_requests SET status=?, responded_at=? WHERE id=?", (status, utc_now(), request_id))
    return {"ok": True, "status": status}


@app.post("/friends/requests/{request_id}/accept")
def accept_friend_request(request_id: int, user: dict = Depends(current_user)):
    return _respond_request(request_id, user, True)


@app.post("/friends/requests/{request_id}/reject")
def reject_friend_request(request_id: int, user: dict = Depends(current_user)):
    return _respond_request(request_id, user, False)


@app.delete("/friends/{mace_id}")
def remove_friend(mace_id: str, user: dict = Depends(current_user)):
    with database() as db:
        target = _user_by_mace_id(db, mace_id)
        if not target:
            raise HTTPException(status_code=404, detail="Пользователь не найден.")
        a, b = sorted((int(user["id"]), int(target["id"])))
        db.execute("DELETE FROM friendships WHERE user_a_id=? AND user_b_id=?", (a, b))
        db.execute(
            "UPDATE friend_requests SET status='cancelled', responded_at=? WHERE status='pending' AND ((requester_id=? AND recipient_id=?) OR (requester_id=? AND recipient_id=?))",
            (utc_now(), int(user["id"]), int(target["id"]), int(target["id"]), int(user["id"])),
        )
    return {"ok": True}


@app.post("/users/block")
def block_user(body: FriendTargetBody, user: dict = Depends(current_user)):
    with database() as db:
        target = _user_by_mace_id(db, body.mace_id)
        if not target:
            raise HTTPException(status_code=404, detail="Пользователь не найден.")
        me_id, target_id = int(user["id"]), int(target["id"])
        if me_id == target_id:
            raise HTTPException(status_code=400, detail="Нельзя заблокировать самого себя.")
        db.execute("INSERT OR IGNORE INTO blocks(blocker_id,blocked_id,created_at) VALUES (?,?,?)", (me_id, target_id, utc_now()))
        a, b = sorted((me_id, target_id))
        db.execute("DELETE FROM friendships WHERE user_a_id=? AND user_b_id=?", (a, b))
        db.execute(
            "UPDATE friend_requests SET status='cancelled', responded_at=? WHERE status='pending' AND ((requester_id=? AND recipient_id=?) OR (requester_id=? AND recipient_id=?))",
            (utc_now(), me_id, target_id, target_id, me_id),
        )
    return {"ok": True}


@app.delete("/users/block/{mace_id}")
def unblock_user(mace_id: str, user: dict = Depends(current_user)):
    with database() as db:
        target = _user_by_mace_id(db, mace_id)
        if not target:
            raise HTTPException(status_code=404, detail="Пользователь не найден.")
        db.execute("DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?", (int(user["id"]), int(target["id"])))
    return {"ok": True}


# ---------------------------------------------------------------------------
# Mace Social: profiles, presence, chats and time-limited file transfer
# ---------------------------------------------------------------------------
def _ensure_user_profile(db, user_id: int) -> None:
    db.execute(
        "INSERT OR IGNORE INTO user_profiles(user_id,display_name,bio,minecraft_seconds,updated_at) VALUES (?,?,?,?,?)",
        (int(user_id), "", "", 0, utc_now()),
    )

def _effective_presence(status: str, last_seen: int) -> str:
    if not last_seen or int(time.time()) - int(last_seen) > PRESENCE_STALE_SECONDS:
        return "offline"
    return status if status in ("launcher", "minecraft") else "offline"

def _attachment_public(row, *, include_expired=True) -> dict:
    file_id = row["file_id"]
    expired = bool(row["deleted"]) or (row["expires_at"] is not None and int(row["expires_at"]) <= int(time.time()))
    if expired and not include_expired:
        return {}
    return {
        "file_id": file_id, "filename": row["original_name"], "content_type": row["content_type"],
        "file_size": int(row["file_size"] or 0), "purpose": row["purpose"],
        "created_at": row["created_at"], "expires_at": row["expires_at"], "expired": expired,
        "download_url": f"/files/{file_id}" if not expired else None,
    }

def _profile_payload(user: dict, include_email: bool = False) -> dict:
    user_id = int(user["id"])
    with database() as db:
        _ensure_user_profile(db, user_id)
        prof = db.execute("SELECT * FROM user_profiles WHERE user_id=?", (user_id,)).fetchone()
        presence = db.execute("SELECT status,last_seen,game_version FROM presence WHERE user_id=?", (user_id,)).fetchone()
        shot_rows = db.execute(
            "SELECT a.* FROM profile_screenshots s JOIN attachments a ON a.file_id=s.attachment_id WHERE s.user_id=? ORDER BY s.created_at DESC LIMIT 30",
            (user_id,),
        ).fetchall()
    status = _effective_presence(presence["status"], presence["last_seen"]) if presence else "offline"
    result = {
        "username": user["username"], "mace_id": user["mace_id"], "created_at": user["created_at"],
        "avatar_url": None, "display_name": str(prof["display_name"] or ""), "bio": str(prof["bio"] or ""),
        "minecraft_seconds": int(prof["minecraft_seconds"] or 0),
        "minecraft_hours": round(int(prof["minecraft_seconds"] or 0) / 3600, 2),
        "status": status, "game_version": str(presence["game_version"] or "") if presence else "",
        "last_seen": int(presence["last_seen"] or 0) if presence else 0,
        "screenshots": [_attachment_public(row) for row in shot_rows],
    }
    if include_email:
        result["email"] = user["email"]
    return result

def _resolve_friend(db, user: dict, mace_id: str) -> dict:
    target = _user_by_mace_id(db, mace_id)
    if not target:
        raise HTTPException(status_code=404, detail="Аккаунт с таким MaceId не найден.")
    if int(target["id"]) == int(user["id"]):
        raise HTTPException(status_code=400, detail="Нельзя отправлять сообщения самому себе.")
    if _blocked_either_way(db, int(user["id"]), int(target["id"])):
        raise HTTPException(status_code=403, detail="Взаимодействие с этим пользователем ограничено.")
    if not _are_friends(db, int(user["id"]), int(target["id"])):
        raise HTTPException(status_code=403, detail="Общаться и обмениваться файлами можно только с друзьями.")
    return dict(target)

def _safe_filename(name: str) -> str:
    clean = Path(str(name or "file")).name.replace("\\", "_").replace("/", "_")
    clean = re.sub(r"[^\w.() \-+\[\]]", "_", clean, flags=re.UNICODE).strip(" .")
    return (clean or "file")[:180]

async def _save_upload(upload: UploadFile, user_id: int, *, purpose: str, recipient_id: int | None, expires_at: int | None, max_bytes: int) -> dict:
    if not upload or not upload.filename:
        raise HTTPException(status_code=400, detail="Файл не выбран.")
    original_name = _safe_filename(upload.filename)
    content_type = (upload.content_type or mimetypes.guess_type(original_name)[0] or "application/octet-stream")[:160]
    # Profile screenshots must really be images; chat accepts arbitrary files.
    if purpose == "profile_screenshot" and not content_type.startswith("image/"):
        raise HTTPException(status_code=415, detail="Для скриншота нужен файл изображения.")
    file_id = uuid.uuid4().hex
    try:
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        target = UPLOAD_DIR / f"{file_id}.bin"
        total = 0
        with target.open("wb") as out:
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    out.close()
                    target.unlink(missing_ok=True)
                    raise HTTPException(status_code=413, detail=f"Файл слишком большой (лимит {max_bytes // (1024*1024)} МБ).")
                out.write(chunk)
        if total == 0:
            target.unlink(missing_ok=True)
            raise HTTPException(status_code=400, detail="Файл пустой.")
        with database() as db:
            db.execute(
                "INSERT INTO attachments(file_id,owner_id,recipient_id,purpose,original_name,content_type,file_size,stored_path,created_at,expires_at,deleted) VALUES (?,?,?,?,?,?,?,?,?,?,0)",
                (file_id, int(user_id), recipient_id, purpose, original_name, content_type, total, str(target), utc_now(), expires_at),
            )
            row = db.execute("SELECT * FROM attachments WHERE file_id=?", (file_id,)).fetchone()
        return _attachment_public(row)
    except HTTPException:
        raise
    except Exception as exc:
        try:
            (UPLOAD_DIR / f"{file_id}.bin").unlink(missing_ok=True)
        except OSError:
            pass
        raise HTTPException(status_code=500, detail=f"Не удалось сохранить файл: {type(exc).__name__}") from exc
    finally:
        try:
            await upload.close()
        except Exception:
            pass

def _insert_message(sender_id: int, recipient_id: int, text: str = "", attachment_id: str | None = None, message_type: str = "text") -> dict:
    with database() as db:
        cur = db.execute(
            "INSERT INTO messages(sender_id,recipient_id,text,attachment_id,message_type,created_at) VALUES (?,?,?,?,?,?) RETURNING id",
            (sender_id, recipient_id, text, attachment_id, message_type, utc_now()),
        )
        inserted = cur.fetchone()
        message_id = int(inserted["id"] if isinstance(inserted, dict) or hasattr(inserted, "keys") else inserted[0])
        return _message_by_id(db, message_id, sender_id)

def _message_by_id(db, message_id: int, viewer_id: int) -> dict:
    row = db.execute(
        "SELECT m.*, su.username AS sender_username, su.mace_id AS sender_mace_id, ru.username AS recipient_username, a.file_id AS a_file_id, a.original_name AS a_original_name, a.content_type AS a_content_type, a.file_size AS a_file_size, a.purpose AS a_purpose, a.created_at AS a_created_at, a.expires_at AS a_expires_at, a.deleted AS a_deleted "
        "FROM messages m JOIN users su ON su.id=m.sender_id JOIN users ru ON ru.id=m.recipient_id LEFT JOIN attachments a ON a.file_id=m.attachment_id WHERE m.id=?",
        (int(message_id),),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Сообщение не найдено.")
    keys = set(row.keys())
    attachment = None
    if row["a_file_id"]:
        attachment = {"file_id": row["a_file_id"], "filename": row["a_original_name"], "content_type": row["a_content_type"],
                      "file_size": int(row["a_file_size"] or 0), "purpose": row["a_purpose"], "created_at": row["a_created_at"],
                      "expires_at": row["a_expires_at"], "expired": bool(row["a_deleted"]) or (row["a_expires_at"] is not None and int(row["a_expires_at"]) <= int(time.time())),
                      "download_url": f"/files/{row['a_file_id']}" if not row["a_deleted"] and (row["a_expires_at"] is None or int(row["a_expires_at"]) > int(time.time())) else None}
    elif row["attachment_id"]:
        attachment = {"file_id": row["attachment_id"], "filename": "Файл удалён через час", "expired": True, "download_url": None}
    return {"id": int(row["id"]), "text": str(row["text"] or ""), "sender_username": row["sender_username"],
            "sender_mace_id": row["sender_mace_id"], "sender_id": int(row["sender_id"]), "recipient_id": int(row["recipient_id"]),
            "is_mine": int(row["sender_id"]) == int(viewer_id), "message_type": row["message_type"],
            "created_at": row["created_at"], "attachment": attachment, "attachment_id": row["attachment_id"]}

def _cleanup_expired_uploads() -> int:
    now = int(time.time())
    with database() as db:
        rows = db.execute("SELECT file_id,stored_path FROM attachments WHERE expires_at IS NOT NULL AND expires_at<=? AND deleted=0", (now,)).fetchall()
        count = 0
        for row in rows:
            try:
                if row["stored_path"]:
                    Path(row["stored_path"]).unlink(missing_ok=True)
            except OSError:
                pass
            db.execute("UPDATE attachments SET deleted=1,stored_path='' WHERE file_id=?", (row["file_id"],))
            count += 1
    return count

def _cleanup_worker():
    while True:
        try:
            _cleanup_expired_uploads()
        except Exception as exc:
            print(f"[MaceHost] Cleanup warning: {exc}")
        time.sleep(60)

@app.on_event("startup")
def _start_upload_cleanup():
    threading.Thread(target=_cleanup_worker, daemon=True, name="MaceUploadCleanup").start()

@app.put("/profile")
def update_profile(body: ProfileUpdateBody, user: dict = Depends(current_user)):
    display_name = body.display_name.strip()[:32]
    bio = body.bio.strip()[:240]
    with database() as db:
        _ensure_user_profile(db, int(user["id"]))
        db.execute("UPDATE user_profiles SET display_name=?,bio=?,updated_at=? WHERE user_id=?", (display_name, bio, utc_now(), int(user["id"])))
    return _profile_payload(user, include_email=True)

@app.post("/presence")
def update_presence(body: PresenceBody, user: dict = Depends(current_user)):
    user_id = int(user["id"]); now = int(time.time())
    status = body.status
    if status == "minecraft" and not body.game_version.strip():
        game_version = "Minecraft"
    else:
        game_version = body.game_version.strip()[:32]
    with database() as db:
        db.execute(
            "INSERT INTO presence(user_id,status,last_seen,game_version) VALUES (?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET status=excluded.status,last_seen=excluded.last_seen,game_version=excluded.game_version",
            (user_id, status, now, game_version),
        )
        _ensure_user_profile(db, user_id)
        if body.playtime_delta and status == "minecraft":
            db.execute("UPDATE user_profiles SET minecraft_seconds=minecraft_seconds+?,updated_at=? WHERE user_id=?", (min(60, int(body.playtime_delta)), utc_now(), user_id))
    return {"ok": True, "status": status, "last_seen": now}

@app.get("/profiles/{mace_id}")
def get_public_profile(mace_id: str, user: dict = Depends(current_user)):
    with database() as db:
        target = _user_by_mace_id(db, mace_id)
        if not target:
            raise HTTPException(status_code=404, detail="Профиль не найден.")
        if _blocked_either_way(db, int(user["id"]), int(target["id"])):
            raise HTTPException(status_code=403, detail="Этот профиль недоступен.")
    return _profile_payload(dict(target), include_email=False)

@app.post("/profile/screenshots")
async def upload_profile_screenshot(file: UploadFile = File(...), user: dict = Depends(current_user)):
    attachment = await _save_upload(file, int(user["id"]), purpose="profile_screenshot", recipient_id=None, expires_at=None, max_bytes=15*1024*1024)
    with database() as db:
        db.execute("INSERT INTO profile_screenshots(user_id,attachment_id,created_at) VALUES (?,?,?)", (int(user["id"]), attachment["file_id"], utc_now()))
    return {"ok": True, "screenshot": attachment}

@app.delete("/profile/screenshots/{file_id}")
def delete_profile_screenshot(file_id: str, user: dict = Depends(current_user)):
    with database() as db:
        row = db.execute("SELECT a.* FROM attachments a JOIN profile_screenshots s ON s.attachment_id=a.file_id WHERE a.file_id=? AND s.user_id=?", (file_id, int(user["id"]))).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Скриншот не найден.")
        try:
            if row["stored_path"]:
                Path(row["stored_path"]).unlink(missing_ok=True)
        except OSError:
            pass
        db.execute("DELETE FROM profile_screenshots WHERE attachment_id=? AND user_id=?", (file_id, int(user["id"])))
        db.execute("DELETE FROM attachments WHERE file_id=?", (file_id,))
    return {"ok": True}

@app.post("/chats/{mace_id}/messages")
def send_chat_message(mace_id: str, body: ChatMessageBody, user: dict = Depends(current_user)):
    with database() as db:
        target = _resolve_friend(db, user, mace_id)
    message = _insert_message(int(user["id"]), int(target["id"]), body.text.strip(), None, "text")
    return {"ok": True, "message": message}

@app.get("/chats/{mace_id}/messages")
def get_chat_messages(mace_id: str, limit: int = Query(default=50, ge=1, le=100), after_id: int = Query(default=0, ge=0), user: dict = Depends(current_user)):
    with database() as db:
        target = _resolve_friend(db, user, mace_id)
        rows = db.execute(
            "SELECT id FROM messages WHERE ((sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?)) AND id>? ORDER BY id DESC LIMIT ?",
            (int(user["id"]), int(target["id"]), int(target["id"]), int(user["id"]), int(after_id), int(limit)),
        ).fetchall()
        ids = [int(r["id"] if hasattr(r, "keys") else r[0]) for r in rows]
        ids.reverse()
        messages = [_message_by_id(db, message_id, int(user["id"])) for message_id in ids]
    return {"messages": messages, "next_after_id": max(ids, default=after_id)}

@app.post("/chats/{mace_id}/files")
async def send_chat_file(mace_id: str, file: UploadFile = File(...), user: dict = Depends(current_user)):
    with database() as db:
        target = _resolve_friend(db, user, mace_id)
    expires = int(time.time()) + CHAT_FILE_LIFETIME_SECONDS
    attachment = await _save_upload(file, int(user["id"]), purpose="chat", recipient_id=int(target["id"]), expires_at=expires, max_bytes=MAX_UPLOAD_BYTES)
    ct = str(attachment.get("content_type") or "")
    if ct.startswith("image/"):
        kind = "image"
    elif ct.startswith("audio/") or Path(str(attachment.get("filename") or "")).suffix.lower() in {".mp3", ".wav", ".ogg", ".m4a", ".flac", ".aac", ".opus"}:
        kind = "audio"
    else:
        kind = "file"
    message = _insert_message(int(user["id"]), int(target["id"]), "", attachment["file_id"], kind)
    return {"ok": True, "message": message, "attachment": attachment, "delete_after_seconds": CHAT_FILE_LIFETIME_SECONDS}

@app.get("/files/{file_id}")
def download_social_file(file_id: str, user: dict = Depends(current_user)):
    _cleanup_expired_uploads()
    with database() as db:
        row = db.execute("SELECT * FROM attachments WHERE file_id=?", (file_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Файл не найден.")
        owner_id = int(row["owner_id"]); recipient_id = int(row["recipient_id"]) if row["recipient_id"] is not None else None
        viewer_id = int(user["id"])
        if row["purpose"] == "chat":
            if viewer_id not in (owner_id, recipient_id):
                raise HTTPException(status_code=403, detail="Нет доступа к этому файлу.")
        elif row["purpose"] == "profile_screenshot":
            pass
        else:
            raise HTTPException(status_code=404, detail="Файл не найден.")
        if row["deleted"] or (row["expires_at"] is not None and int(row["expires_at"]) <= int(time.time())):
            raise HTTPException(status_code=410, detail="Файл удалён с сервера спустя час после отправки.")
        path = Path(row["stored_path"])
        if not path.is_file():
            raise HTTPException(status_code=410, detail="Файл больше недоступен на сервере.")
        return FileResponse(path, media_type=row["content_type"], filename=row["original_name"], content_disposition_type="attachment")

@app.delete("/friends/requests/{request_id}")
def cancel_friend_request(request_id: int, user: dict = Depends(current_user)):
    with database() as db:
        row = db.execute("SELECT id FROM friend_requests WHERE id=? AND requester_id=? AND status='pending'", (int(request_id), int(user["id"]))).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Исходящая заявка не найдена.")
        db.execute("UPDATE friend_requests SET status='cancelled',responded_at=? WHERE id=?", (utc_now(), int(request_id)))
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    bind_host = os.environ.get("MACE_BIND_HOST", "0.0.0.0")
    bind_port = int(os.environ.get("PORT", os.environ.get("MACE_PORT", "8000")))
    uvicorn.run(app, host=bind_host, port=bind_port, log_level=os.environ.get("MACE_LOG_LEVEL", "info"))
