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
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.environ.get("MACE_ACCOUNTS_DB", str(BASE_DIR / "mace_accounts.db")))
PBKDF2_ROUNDS = 310_000
SESSION_SECONDS = 60 * 60 * 24 * 30

app = FastAPI(
    title="MaceHost — Mace Accounts API",
    description="Unified accounts, profiles, and friends for Mace Launcher.",
    version="1.0.0",
)

# Access tokens are sent explicitly as Bearer tokens; cookies are not used.
# For production, set MACE_ALLOWED_ORIGINS to a comma-separated allow-list.
_origins_env = os.environ.get("MACE_ALLOWED_ORIGINS", "").strip()
_allowed_origins = [item.strip() for item in _origins_env.split(",") if item.strip()] if _origins_env else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
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


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def database():
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
    with database() as db:
        db.executescript(
            """
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
        )


init_db()


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
    return {
        "mace_id": row["mace_id"],
        "username": row["username"],
        "created_at": row["created_at"],
        "avatar_url": None,
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
    return {"ok": True, "service": "MaceHost", "api_version": "1.0.0"}


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
    except sqlite3.IntegrityError:
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
    return {
        "username": user["username"],
        "mace_id": user["mace_id"],
        "email": user["email"],
        "created_at": user["created_at"],
        "avatar_url": None,
    }


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
            """SELECT u.* FROM users u
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
            """SELECT u.* FROM friendships f JOIN users u ON u.id =
               CASE WHEN f.user_a_id=? THEN f.user_b_id ELSE f.user_a_id END
               WHERE f.user_a_id=? OR f.user_b_id=? ORDER BY u.username_key""",
            (me_id, me_id, me_id),
        ).fetchall()
        incoming_rows = db.execute(
            """SELECT fr.id AS request_id, fr.created_at, u.* FROM friend_requests fr
               JOIN users u ON u.id=fr.requester_id
               WHERE fr.recipient_id=? AND fr.status='pending' ORDER BY fr.created_at DESC""",
            (me_id,),
        ).fetchall()
        outgoing_rows = db.execute(
            """SELECT fr.id AS request_id, fr.created_at, u.* FROM friend_requests fr
               JOIN users u ON u.id=fr.recipient_id
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


if __name__ == "__main__":
    import uvicorn
    bind_host = os.environ.get("MACE_BIND_HOST", "0.0.0.0")
    bind_port = int(os.environ.get("PORT", os.environ.get("MACE_PORT", "8000")))
    uvicorn.run(app, host=bind_host, port=bind_port, log_level=os.environ.get("MACE_LOG_LEVEL", "info"))
