"""Mailroom — панель управления почтовым сервером (Postfix + Dovecot + Rspamd).

Домены, ящики и алиасы хранятся в PostgreSQL. Postfix и Dovecot читают их
напрямую через представления mail_* (роль mailserver только на чтение), поэтому
изменения в панели действуют сразу, без перезагрузки сервисов.
"""
from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import smtplib
import struct
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

import psycopg2
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from passlib.hash import sha512_crypt
from psycopg2 import IntegrityError
from psycopg2.extras import Json, RealDictCursor

import mailcore
from mailcore import MailError

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("MAILROOM_DATA_DIR", str(BASE_DIR)))
VERSION = "2.0.0"
ARTICLE_URL = "https://tehalex.ru/pochtovyj-shlyuz-postfix/"

app = Flask(__name__)
SECRET_PATH = DATA_DIR / ".session-secret"
if SECRET_PATH.exists():
    app.secret_key = SECRET_PATH.read_bytes()
else:
    app.secret_key = secrets.token_bytes(32)
    SECRET_PATH.write_bytes(app.secret_key)
    SECRET_PATH.chmod(0o600)
COOKIE_SECURE = os.getenv("MAILROOM_COOKIE_SECURE", "1") == "1"
app.config.update(
    SESSION_COOKIE_NAME="__Host-mr_admin" if COOKIE_SECURE else "mr_admin",
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12), MAX_CONTENT_LENGTH=30 * 1024 * 1024,
)
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 900
ADMIN_IDLE_SECONDS = 3600


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------- пароли и 2FA ----------

def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"pbkdf2_sha256$310000${salt.hex()}${digest.hex()}"


def password_verify(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt_hex, digest_hex = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(actual.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def mailbox_password_hash(password: str) -> str:
    """SHA512-CRYPT: этот формат Dovecot проверяет сам (представление mail_users)."""
    return sha512_crypt.hash(password)


def mailbox_password_verify(password: str, encoded: str | None) -> bool:
    if not encoded or not encoded.startswith("$6$"):
        return False
    try:
        return bool(sha512_crypt.verify(password, encoded))
    except ValueError:
        return False


def password_problem(password: str, address: str = "") -> str | None:
    if len(password) < 12:
        return "Пароль должен содержать минимум 12 символов"
    if len(password) > 256:
        return "Слишком длинный пароль"
    if address and password.lower() in (address.lower(), address.split("@")[0].lower()):
        return "Пароль не должен совпадать с адресом"
    if len(set(password)) < 5:
        return "Пароль слишком простой"
    return None


def totp_code(secret: str, timestamp: int | None = None) -> str:
    counter = int((timestamp or time.time()) // 30)
    key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def verify_totp(secret: str, code: str) -> bool:
    return bool(secret) and any(
        hmac.compare_digest(totp_code(secret, int(time.time()) + drift * 30), code) for drift in (-1, 0, 1))


# ---------- база ----------

class Database:
    def __init__(self, dsn: str):
        self.connection = psycopg2.connect(dsn)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type:
            self.connection.rollback()
        else:
            self.connection.commit()
        self.connection.close()

    def execute(self, query: str, params=None):
        cursor = self.connection.cursor(cursor_factory=RealDictCursor)
        cursor.execute(query, params)
        return cursor

    def one(self, query: str, params=None):
        return self.execute(query, params).fetchone()

    def all(self, query: str, params=None):
        return [dict(r) for r in self.execute(query, params).fetchall()]


def db() -> Database:
    dsn = os.getenv("MAILROOM_DATABASE_URL")
    if not dsn and (BASE_DIR / ".db-url").exists():
        dsn = (BASE_DIR / ".db-url").read_text(encoding="utf-8").strip()
    if not dsn:
        raise RuntimeError("MAILROOM_DATABASE_URL не настроен")
    return Database(dsn)


SCHEMA = r"""
CREATE TABLE IF NOT EXISTS domains (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active',
    quota_mb INTEGER NOT NULL DEFAULT 10240,
    created_at TEXT NOT NULL
);
ALTER TABLE domains ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dns_settings JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dkim_selector TEXT;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dkim_public TEXT;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dkim_state TEXT NOT NULL DEFAULT 'none';
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dkim_created_at TEXT;

CREATE TABLE IF NOT EXISTS mailboxes (
    id BIGSERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    localpart TEXT NOT NULL,
    quota_mb INTEGER NOT NULL DEFAULT 2048,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    UNIQUE(domain_id, localpart)
);
ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS password_hash TEXT;
ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS password_changed_at TEXT;
ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS last_login_at TEXT;

CREATE TABLE IF NOT EXISTS aliases (
    id BIGSERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    localpart TEXT NOT NULL,
    destinations TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(domain_id, localpart)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    level TEXT NOT NULL DEFAULT 'INFO',
    event TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS actor TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator',
    totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    last_login_at TEXT
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS login_attempts (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    ip TEXT NOT NULL,
    success BOOLEAN NOT NULL DEFAULT FALSE,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS login_attempts_time_idx ON login_attempts (created_at);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Веб-почта
CREATE TABLE IF NOT EXISTS client_sessions (
    token_hash TEXT PRIMARY KEY,
    mailbox_id BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS mailbox_prefs (
    mailbox_id BIGINT PRIMARY KEY REFERENCES mailboxes(id) ON DELETE CASCADE,
    signature TEXT NOT NULL DEFAULT '',
    vacation JSONB NOT NULL DEFAULT '{}'::jsonb,
    forward JSONB NOT NULL DEFAULT '{}'::jsonb,
    filters JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS contacts (
    id BIGSERIAL PRIMARY KEY,
    mailbox_id BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    uses INTEGER NOT NULL DEFAULT 0,
    last_used INTEGER NOT NULL DEFAULT 0,
    UNIQUE(mailbox_id, email)
);
CREATE TABLE IF NOT EXISTS send_log (
    id BIGSERIAL PRIMARY KEY,
    mailbox_id BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    recipients INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS send_log_idx ON send_log (mailbox_id, created_at);

CREATE TABLE IF NOT EXISTS alert_state (
    key TEXT PRIMARY KEY,
    level TEXT NOT NULL,
    title TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    notified_at INTEGER NOT NULL DEFAULT 0
);

-- Представления для Postfix и Dovecot (роль mailserver читает только их).
CREATE OR REPLACE VIEW mail_domains AS
  SELECT lower(name) AS domain FROM domains WHERE status = 'active';

CREATE OR REPLACE VIEW mail_users AS
  SELECT lower(m.localpart || '@' || d.name) AS address,
         '{SHA512-CRYPT}' || m.password_hash AS password,
         '/var/vmail/' || lower(d.name) || '/' || lower(m.localpart) AS home,
         m.quota_mb::bigint * 1048576 AS quota_bytes
    FROM mailboxes m JOIN domains d ON d.id = m.domain_id
   WHERE m.status = 'active' AND d.status = 'active' AND m.password_hash LIKE '$6$%';

CREATE OR REPLACE VIEW mail_aliases AS
  SELECT CASE WHEN a.localpart = '*' THEN '@' || lower(d.name)
              ELSE lower(a.localpart || '@' || d.name) END AS address,
         replace(a.destinations, ' ', '') AS goto
    FROM aliases a JOIN domains d ON d.id = a.domain_id
   WHERE a.status = 'active' AND d.status = 'active';

CREATE OR REPLACE VIEW mail_sender_login AS
  SELECT address, address AS owner FROM mail_users
  UNION
  SELECT al.address, u.address
    FROM mail_aliases al
    JOIN mail_users u ON position(',' || u.address || ',' IN ',' || al.goto || ',') > 0
   WHERE al.address NOT LIKE '@%';
"""

DEFAULT_SETTINGS = {
    "hostname": "mail.example.net",
    "public_ip": "",
    "webmail_url": "",
    "message_size_mb": "25",
    "mynetworks": "127.0.0.0/8",
    "send_limit_hour": "100",
    "send_limit_message": "50",
    "imap_ports": "993",
    "ca_download": "1",
    "smtp_limit_hour": "100",
    "client_host": "",
    "alert_email": "",
    "telegram_token": "",
    "telegram_chat": "",
    "backup_keep": "7",
    "backup_remote": "",
    "backup_remote_port": "22",
}
SECRET_SETTINGS = {"telegram_token"}


def init_db() -> None:
    with db() as con:
        con.execute("SELECT pg_advisory_lock(42424201)")
        try:
            con.execute(SCHEMA)
            role = con.one("SELECT 1 AS ok FROM pg_roles WHERE rolname = 'mailserver'")
            if role:
                con.execute("GRANT SELECT ON mail_domains, mail_users, mail_aliases, mail_sender_login TO mailserver")
            con.execute("DELETE FROM settings WHERE key IN ('relay_mode','smtp_listen','tls_mode','trusted_networks')")
            if con.one("SELECT COUNT(*) AS n FROM users")["n"] == 0:
                bootstrap = os.getenv("MAILROOM_ADMIN_PASSWORD") or secrets.token_urlsafe(18)
                con.execute("INSERT INTO users(username, password_hash, role, created_at) VALUES (%s,%s,'admin',%s)",
                            ("admin", password_hash(bootstrap), now_iso()))
                path = DATA_DIR / ".bootstrap-admin"
                path.write_text(f"username=admin\npassword={bootstrap}\n", encoding="utf-8")
                path.chmod(0o600)
            for key, value in DEFAULT_SETTINGS.items():
                con.execute("INSERT INTO settings(key, value, updated_at) VALUES (%s,%s,%s) "
                            "ON CONFLICT (key) DO NOTHING", (key, value, now_iso()))
            con.execute("UPDATE domains SET name = lower(name) WHERE name <> lower(name)")
        finally:
            con.execute("SELECT pg_advisory_unlock(42424201)")


def get_settings(con=None) -> dict:
    def load(c):
        return {r["key"]: r["value"] for r in c.all("SELECT key, value FROM settings")}
    if con:
        return {**DEFAULT_SETTINGS, **load(con)}
    with db() as c:
        return {**DEFAULT_SETTINGS, **load(c)}


def audit(event: str, details: str = "", level: str = "INFO", actor: str | None = None) -> None:
    if actor is None:
        actor = session.get("username", "") if request else ""
    with db() as con:
        con.execute("INSERT INTO audit_log(level, event, details, actor, created_at) VALUES (%s,%s,%s,%s,%s)",
                    (level, event, details[:1000], actor, now_iso()))


def client_ip() -> str:
    return request.remote_addr or "unknown"


def login_blocked(key: str, ip: str) -> bool:
    cutoff = int(time.time()) - LOCKOUT_SECONDS
    with db() as con:
        row = con.one("SELECT COUNT(*) AS n FROM login_attempts WHERE created_at >= %s AND NOT success "
                      "AND (username = %s OR ip = %s)", (cutoff, key, ip))
    return row["n"] >= MAX_LOGIN_ATTEMPTS


def record_login(key: str, ip: str, success: bool) -> None:
    with db() as con:
        con.execute("INSERT INTO login_attempts(username, ip, success, created_at) VALUES (%s,%s,%s,%s)",
                    (key, ip, success, int(time.time())))
        if success:
            con.execute("DELETE FROM login_attempts WHERE NOT success AND username = %s", (key,))
        con.execute("DELETE FROM login_attempts WHERE created_at < %s", (int(time.time()) - 86_400,))


# ---------- проверка ввода ----------

DOMAIN_RE = re.compile(r"(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
LOCALPART_RE = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?")
EMAIL_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}")
HOST_RE = re.compile(r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?")
SELECTOR_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?")


def valid_domain(value: str) -> bool:
    return bool(DOMAIN_RE.fullmatch(value))


def valid_localpart(value: str) -> bool:
    return bool(LOCALPART_RE.fullmatch(value)) and ".." not in value


def valid_email(value: str) -> bool:
    return bool(EMAIL_RE.fullmatch(value))


def valid_hostname(value: str) -> bool:
    return bool(HOST_RE.fullmatch(value))


def as_int(value, default: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(low, min(high, number))


class BadRequest(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


@app.errorhandler(BadRequest)
def bad_request(exc: BadRequest):
    return jsonify({"error": str(exc)}), exc.status


@app.errorhandler(MailError)
def mail_error(exc: MailError):
    return jsonify({"error": str(exc)}), 502


@app.errorhandler(413)
def too_large(_exc):
    return jsonify({"error": "Слишком большой запрос: вложения больше 25 МБ"}), 413


def payload() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


# ---------- заголовки безопасности ----------

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
       "form-action 'self'; frame-ancestors 'none'")


@app.after_request
def security_headers(response):
    response.headers.setdefault("Content-Security-Policy", CSP)
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


# ---------- доступ администратора ----------

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    if time.time() - session.get("seen", 0) > ADMIN_IDLE_SECONDS:
        session.clear()
        return None
    with db() as con:
        user = con.one("SELECT id, username, role, totp_enabled, session_version FROM users WHERE id = %s", (uid,))
    if not user or user["session_version"] != session.get("sv"):
        session.clear()
        return None
    session["seen"] = int(time.time())
    session["role"] = user["role"]
    return user


def auth_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            if request.path.startswith("/api/"):
                return jsonify({"error": "Требуется вход"}), 401
            return redirect(url_for("login_page"))
        if request.method not in ("GET", "HEAD"):
            expected = session.get("csrf_token", "")
            supplied = request.headers.get("X-CSRF-Token", "")
            if not expected or not hmac.compare_digest(expected, supplied):
                return jsonify({"error": "Недействительный CSRF-токен, обновите страницу"}), 403
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if session.get("role") not in roles:
                return jsonify({"error": "Недостаточно прав"}), 403
            return view(*args, **kwargs)
        return wrapped
    return decorator


writer = role_required("admin", "operator")
admin_only = role_required("admin")


@app.get("/login")
def login_page():
    if current_user():
        return redirect(url_for("index"))
    return render_template("login.html")


@app.post("/api/auth/login")
def login():
    data = payload()
    username = str(data.get("username", "")).strip().lower()[:64]
    password = str(data.get("password", ""))
    ip = client_ip()
    generic = jsonify({"error": "Неверные учётные данные или временная блокировка"}), 401
    if not username or not password or login_blocked(username, ip):
        record_login(username, ip, False)
        return generic
    with db() as con:
        user = con.one("SELECT * FROM users WHERE username = %s", (username,))
    if not user or not password_verify(password, user["password_hash"]):
        record_login(username, ip, False)
        audit("Неудачный вход в панель", f"{username} с {ip}", "WARN", actor="")
        return generic
    if user["totp_enabled"]:
        session.clear()
        session["pending_2fa"] = {"id": user["id"], "at": int(time.time())}
        return jsonify({"status": "requires_2fa"})
    return finish_login(user, ip)


@app.post("/api/auth/verify-2fa")
def verify_second_factor():
    pending = session.get("pending_2fa") or {}
    if not pending or time.time() - pending.get("at", 0) > 300:
        session.clear()
        return jsonify({"error": "Время ввода кода истекло, войдите заново"}), 401
    code = re.sub(r"\D", "", str(payload().get("otp", "")))
    ip = client_ip()
    with db() as con:
        user = con.one("SELECT * FROM users WHERE id = %s", (pending["id"],))
    if not user or login_blocked(user["username"], ip) or not verify_totp(user["totp_secret"], code):
        record_login(user["username"] if user else "?", ip, False)
        return jsonify({"error": "Неверный код"}), 401
    return finish_login(user, ip)


def finish_login(user, ip: str):
    session.clear()
    session.permanent = True
    session.update(user_id=user["id"], username=user["username"], role=user["role"],
                   sv=user["session_version"], seen=int(time.time()), csrf_token=secrets.token_urlsafe(32))
    record_login(user["username"], ip, True)
    with db() as con:
        con.execute("UPDATE users SET last_login_at = %s WHERE id = %s", (now_iso(), user["id"]))
    audit("Вход в панель", f"с {ip}", actor=user["username"])
    return jsonify({"status": "ok"})


@app.post("/api/auth/logout")
def logout():
    if session.get("username"):
        audit("Выход из панели", "")
    session.clear()
    return jsonify({"status": "ok"})


@app.get("/api/auth/me")
@auth_required
def auth_me():
    user = current_user()
    return jsonify({"username": user["username"], "role": user["role"], "totp_enabled": bool(user["totp_enabled"]),
                    "csrf_token": session["csrf_token"], "version": VERSION})


@app.post("/api/auth/password")
@auth_required
def change_password():
    data = payload()
    new_password = str(data.get("new_password", ""))
    if len(new_password) < 14:
        raise BadRequest("Новый пароль должен содержать минимум 14 символов")
    with db() as con:
        user = con.one("SELECT password_hash FROM users WHERE id = %s", (session["user_id"],))
        if not password_verify(str(data.get("current_password", "")), user["password_hash"]):
            raise BadRequest("Текущий пароль указан неверно")
        con.execute("UPDATE users SET password_hash = %s, session_version = session_version + 1 WHERE id = %s",
                    (password_hash(new_password), session["user_id"]))
        session["sv"] = con.one("SELECT session_version FROM users WHERE id = %s", (session["user_id"],))["session_version"]
    if session.get("username") == "admin":
        (DATA_DIR / ".bootstrap-admin").unlink(missing_ok=True)
    audit("Пароль администратора изменён", "остальные сессии завершены")
    return jsonify({"status": "changed"})


@app.post("/api/auth/totp/setup")
@auth_required
def totp_setup():
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    session["totp_pending"] = secret
    username = session.get("username", "admin")
    return jsonify({"secret": secret, "otpauth_uri": f"otpauth://totp/Mailroom:{username}?secret={secret}&issuer=Mailroom"})


@app.post("/api/auth/totp/enable")
@auth_required
def totp_enable():
    secret = session.get("totp_pending")
    code = re.sub(r"\D", "", str(payload().get("code", "")))
    if not secret or not verify_totp(secret, code):
        raise BadRequest("Неверный код. Проверьте время на телефоне и введите новый код")
    with db() as con:
        con.execute("UPDATE users SET totp_secret = %s, totp_enabled = 1 WHERE id = %s", (secret, session["user_id"]))
    session.pop("totp_pending", None)
    audit("2FA включена", "")
    return jsonify({"status": "enabled"})


@app.post("/api/auth/totp/disable")
@auth_required
def totp_disable():
    with db() as con:
        user = con.one("SELECT password_hash FROM users WHERE id = %s", (session["user_id"],))
        if not password_verify(str(payload().get("password", "")), user["password_hash"]):
            raise BadRequest("Пароль указан неверно")
        con.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = %s", (session["user_id"],))
    audit("2FA отключена", "", "WARN")
    return jsonify({"status": "disabled"})


# ---------- пользователи панели ----------

@app.get("/api/users")
@auth_required
@admin_only
def list_users():
    with db() as con:
        rows = con.all("SELECT id, username, role, totp_enabled, created_at, last_login_at FROM users ORDER BY username")
    return jsonify({"items": rows})


@app.post("/api/users")
@auth_required
@admin_only
def create_user():
    data = payload()
    username = str(data.get("username", "")).strip().lower()
    password = str(data.get("password", ""))
    role = str(data.get("role", "operator"))
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,31}", username):
        raise BadRequest("Логин: 3–32 символа, латиница, цифры, . _ -")
    if len(password) < 14:
        raise BadRequest("Пароль должен содержать минимум 14 символов")
    if role not in {"admin", "operator", "viewer"}:
        raise BadRequest("Недопустимая роль")
    try:
        with db() as con:
            con.execute("INSERT INTO users(username, password_hash, role, created_at) VALUES (%s,%s,%s,%s)",
                        (username, password_hash(password), role, now_iso()))
    except IntegrityError:
        raise BadRequest("Такой пользователь уже существует", 409)
    audit("Пользователь панели добавлен", f"{username}, роль {role}")
    return jsonify({"status": "created"}), 201


@app.delete("/api/users/<int:user_id>")
@auth_required
@admin_only
def delete_user(user_id: int):
    if user_id == session.get("user_id"):
        raise BadRequest("Нельзя удалить самого себя")
    with db() as con:
        user = con.one("SELECT username FROM users WHERE id = %s", (user_id,))
        if not user:
            raise BadRequest("Пользователь не найден", 404)
        if con.one("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND id <> %s", (user_id,))["n"] == 0:
            raise BadRequest("Нельзя удалить последнего администратора")
        con.execute("DELETE FROM users WHERE id = %s", (user_id,))
    audit("Пользователь панели удалён", user["username"], "WARN")
    return jsonify({"status": "deleted"})


# ---------- страницы ----------

@app.get("/")
@auth_required
def index():
    return render_template("index.html", version=VERSION, article_url=ARTICLE_URL)


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "version": VERSION})


# ---------- обзор ----------

def service_state(name: str) -> str:
    ok, out = mailcore.run(["systemctl", "is-active", name], timeout=4)
    return out or ("active" if ok else "unknown")


def rspamd_stat() -> dict | None:
    import urllib.request
    try:
        with urllib.request.urlopen("http://127.0.0.1:11334/stat", timeout=3) as resp:
            data = json.loads(resp.read())
        return {"scanned": data.get("scanned", 0), "actions": data.get("actions", {}), "learned": data.get("learned", 0)}
    except (OSError, ValueError):
        return None


def queue_summary() -> dict:
    try:
        items = mailcore.postqueue_json()
    except MailError as exc:
        return {"available": False, "error": str(exc), "total": 0}
    oldest = min((i.get("arrival_time", 0) for i in items), default=0)
    return {"available": True, "total": len(items),
            "deferred": sum(1 for i in items if i.get("queue_name") == "deferred"),
            "hold": sum(1 for i in items if i.get("queue_name") == "hold"),
            "oldest_minutes": int((time.time() - oldest) / 60) if oldest else 0}


@app.get("/api/overview")
@auth_required
def overview():
    services = [{"name": n, "state": service_state(n)} for n in
                ("postfix", "dovecot", "rspamd", "redis-server", "postgresql", "radicale", "fail2ban")]
    with db() as con:
        counts = con.one("SELECT (SELECT COUNT(*) FROM domains) AS domains, (SELECT COUNT(*) FROM mailboxes) AS mailboxes, "
                         "(SELECT COUNT(*) FROM aliases) AS aliases, "
                         "(SELECT COUNT(*) FROM client_sessions WHERE last_seen > %s) AS webmail_online",
                         (int(time.time()) - 1800,))
    try:
        usage = shutil.disk_usage("/var/vmail")
        disk = {"total": usage.total, "used": usage.used, "free": usage.free}
    except OSError:
        disk = None
    return jsonify({"host": os.uname().nodename, "timestamp": now_iso(), "services": services,
                    "queue": queue_summary(), "counts": dict(counts), "disk": disk, "rspamd": rspamd_stat(),
                    "version": VERSION})


@app.get("/api/config")
@auth_required
def postfix_config():
    ok, output = mailcore.run(["postconf", "-n"])
    if not ok:
        return jsonify({"available": False, "values": [], "error": output})
    values = []
    for line in output.splitlines():
        key, sep, value = line.partition(" = ")
        if sep:
            if any(t in key.lower() for t in ("password", "secret", "sasl_passwd")):
                value = "********"
            values.append({"key": key, "value": value})
    return jsonify({"available": True, "values": values})


# ---------- домены ----------

def domain_row(con, domain_id: int):
    row = con.one("SELECT * FROM domains WHERE id = %s", (domain_id,))
    if not row:
        raise BadRequest("Домен не найден", 404)
    return row


def sync_dkim_selectors(con):
    rows = con.all("SELECT name, dkim_selector FROM domains WHERE dkim_state = 'active' AND status = 'active'")
    try:
        mailcore.dkim_write_selectors({r["name"]: r["dkim_selector"] for r in rows})
    except OSError as exc:
        raise MailError(f"Не удалось записать карту DKIM-селекторов: {exc}")


@app.get("/api/domains")
@auth_required
def list_domains():
    with db() as con:
        rows = con.all("""SELECT d.*, (SELECT COUNT(*) FROM mailboxes m WHERE m.domain_id = d.id) AS mailbox_count,
                                 (SELECT COUNT(*) FROM aliases a WHERE a.domain_id = d.id) AS alias_count,
                                 (SELECT COALESCE(SUM(quota_mb),0) FROM mailboxes m WHERE m.domain_id = d.id) AS allocated_mb
                            FROM domains d ORDER BY d.name""")
    return jsonify({"items": rows})


@app.post("/api/domains")
@auth_required
@writer
def create_domain():
    data = payload()
    name = str(data.get("name", "")).strip().lower().rstrip(".")
    quota_mb = as_int(data.get("quota_mb"), 10240, 1, 10_000_000)
    if not valid_domain(name):
        raise BadRequest("Укажите корректное доменное имя, например example.com")
    try:
        with db() as con:
            row = con.one("INSERT INTO domains(name, quota_mb, description, created_at) VALUES (%s,%s,%s,%s) RETURNING id",
                          (name, quota_mb, str(data.get("description", ""))[:200], now_iso()))
            if data.get("create_service_aliases", True):
                created = []
                admin_box = str(data.get("service_target", "")).strip().lower()
                if admin_box and valid_email(admin_box):
                    for local in ("postmaster", "abuse", "dmarc", "tlsrpt"):
                        con.execute("INSERT INTO aliases(domain_id, localpart, destinations, note, created_at) "
                                    "VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                                    (row["id"], local, admin_box, "служебный адрес", now_iso()))
                        created.append(local)
    except IntegrityError:
        raise BadRequest("Такой домен уже существует", 409)
    audit("Домен добавлен", f"{name}, квота {quota_mb} МБ")
    return jsonify({"status": "created", "id": row["id"]}), 201


@app.patch("/api/domains/<int:domain_id>")
@auth_required
@writer
def update_domain(domain_id: int):
    data = payload()
    with db() as con:
        row = domain_row(con, domain_id)
        changes = []
        if "status" in data:
            status = "active" if data["status"] == "active" else "disabled"
            con.execute("UPDATE domains SET status = %s WHERE id = %s", (status, domain_id))
            changes.append(f"статус {status}")
        if "quota_mb" in data:
            quota = as_int(data["quota_mb"], row["quota_mb"], 1, 10_000_000)
            con.execute("UPDATE domains SET quota_mb = %s WHERE id = %s", (quota, domain_id))
            changes.append(f"квота {quota} МБ")
        if "description" in data:
            con.execute("UPDATE domains SET description = %s WHERE id = %s", (str(data["description"])[:200], domain_id))
        if "dns_settings" in data and isinstance(data["dns_settings"], dict):
            settings = clean_dns_settings(data["dns_settings"], row["name"])
            con.execute("UPDATE domains SET dns_settings = %s WHERE id = %s", (Json(settings), domain_id))
            changes.append("параметры DNS")
        sync_dkim_selectors(con)
    if changes:
        audit("Домен изменён", f"{row['name']}: {', '.join(changes)}")
    return jsonify({"status": "updated"})


@app.delete("/api/domains/<int:domain_id>")
@auth_required
@admin_only
def delete_domain(domain_id: int):
    with db() as con:
        row = domain_row(con, domain_id)
        boxes = con.one("SELECT COUNT(*) AS n FROM mailboxes WHERE domain_id = %s", (domain_id,))["n"]
        if boxes and payload().get("confirm") != row["name"]:
            raise BadRequest(f"В домене {boxes} ящ. Для удаления введите имя домена для подтверждения")
        con.execute("DELETE FROM domains WHERE id = %s", (domain_id,))
        sync_dkim_selectors(con)
    if row["dkim_selector"]:
        mailcore.dkim_remove(row["name"], row["dkim_selector"])
    audit("Домен удалён", f"{row['name']} (письма на диске сохранены в /var/vmail)", "WARN")
    return jsonify({"status": "deleted"})


# --- DKIM ---

@app.post("/api/domains/<int:domain_id>/dkim")
@auth_required
@writer
def dkim_generate(domain_id: int):
    data = payload()
    selector = str(data.get("selector") or "").strip().lower() or f"mr{datetime.now():%Y%m}"
    bits = 2048 if str(data.get("bits", "2048")) != "1024" else 1024
    if not SELECTOR_RE.fullmatch(selector):
        raise BadRequest("Селектор: латиница, цифры и дефис, до 32 символов")
    with db() as con:
        row = domain_row(con, domain_id)
        if row["dkim_state"] == "active" and row["dkim_selector"] == selector:
            raise BadRequest("Этот селектор уже используется для подписи. Для смены ключа выберите новый селектор")
        try:
            public = mailcore.dkim_generate(row["name"], selector, bits)
        except OSError as exc:
            raise MailError(f"Не удалось сохранить ключ: {exc}")
        settings = dict(row["dns_settings"] or {})
        if row["dkim_state"] == "active":
            # Ротация: старый ключ подписывает, пока новый не опубликован и не подтверждён.
            settings["dkim_pending"] = {"selector": selector, "public": public, "created_at": now_iso()}
            con.execute("UPDATE domains SET dns_settings = %s WHERE id = %s", (Json(settings), domain_id))
        else:
            if row["dkim_selector"] and row["dkim_selector"] != selector:
                mailcore.dkim_remove(row["name"], row["dkim_selector"])
            con.execute("UPDATE domains SET dkim_selector = %s, dkim_public = %s, dkim_state = 'pending', "
                        "dkim_created_at = %s WHERE id = %s", (selector, public, now_iso(), domain_id))
    audit("DKIM-ключ создан", f"{row['name']}, селектор {selector}, {bits} бит")
    return jsonify({"status": "generated", "selector": selector, "record": f"{selector}._domainkey.{row['name']}",
                    "value": public})


@app.post("/api/domains/<int:domain_id>/dkim/activate")
@auth_required
@writer
def dkim_activate(domain_id: int):
    force = bool(payload().get("force"))
    with db() as con:
        row = domain_row(con, domain_id)
        settings = dict(row["dns_settings"] or {})
        pending = settings.get("dkim_pending")
        selector, public = (pending["selector"], pending["public"]) if pending else (row["dkim_selector"], row["dkim_public"])
        if not selector:
            raise BadRequest("Сначала создайте DKIM-ключ")
        published = mailcore.txt_records(f"{selector}._domainkey.{row['name']}", "v=DKIM1")
        matches = any(mailcore.parse_tags(v).get("p", "").replace(" ", "") == mailcore.parse_tags(public).get("p")
                      for v in published)
        if not matches and not force:
            raise BadRequest("Публичный ключ в DNS не найден или не совпадает. Опубликуйте запись и подождите "
                             "обновления DNS. Включить подпись принудительно можно кнопкой «Включить без проверки».", 409)
        old = row["dkim_selector"] if pending else None
        con.execute("UPDATE domains SET dkim_selector = %s, dkim_public = %s, dkim_state = 'active', dkim_created_at = %s, "
                    "dns_settings = dns_settings - 'dkim_pending' WHERE id = %s",
                    (selector, public, (pending or {}).get("created_at") or row["dkim_created_at"], domain_id))
        sync_dkim_selectors(con)
    if old and old != selector:
        settings_note = f"; старый селектор {old} оставьте в DNS ещё на 7 дней"
        mailcore.dkim_remove(row["name"], old)
    else:
        settings_note = ""
    audit("DKIM-подпись включена", f"{row['name']}, селектор {selector}{' (без проверки DNS)' if not matches else ''}{settings_note}")
    return jsonify({"status": "active", "selector": selector, "dns_verified": matches})


@app.post("/api/domains/<int:domain_id>/dkim/disable")
@auth_required
@writer
def dkim_disable(domain_id: int):
    with db() as con:
        row = domain_row(con, domain_id)
        con.execute("UPDATE domains SET dkim_state = CASE WHEN dkim_selector IS NULL THEN 'none' ELSE 'pending' END "
                    "WHERE id = %s", (domain_id,))
        sync_dkim_selectors(con)
    audit("DKIM-подпись выключена", row["name"], "WARN")
    return jsonify({"status": "disabled"})


# --- DNS-мастер ---

DMARC_DEFAULTS = {"p": "none", "sp": "", "pct": 100, "adkim": "r", "aspf": "r", "fo": "1", "rua": True, "ruf": False}


def clean_dns_settings(raw: dict, domain: str) -> dict:
    spf = raw.get("spf") or {}
    includes = [x.strip().lower() for x in spf.get("include", []) if x and HOST_RE.fullmatch(x.strip())][:8]
    ip4 = []
    for value in spf.get("ip4", []):
        try:
            ip4.append(str(ipaddress.ip_network(str(value).strip(), strict=False)))
        except ValueError:
            continue
    dmarc = {**DMARC_DEFAULTS, **(raw.get("dmarc") or {})}
    result = {
        "spf": {"mx": bool(spf.get("mx", True)), "a": bool(spf.get("a", False)), "include": includes, "ip4": ip4[:10],
                "all": spf.get("all") if spf.get("all") in ("-all", "~all") else "-all"},
        "dmarc": {
            "p": dmarc["p"] if dmarc["p"] in ("none", "quarantine", "reject") else "none",
            "sp": dmarc["sp"] if dmarc["sp"] in ("", "none", "quarantine", "reject") else "",
            "pct": as_int(dmarc["pct"], 100, 1, 100),
            "adkim": "s" if dmarc["adkim"] == "s" else "r",
            "aspf": "s" if dmarc["aspf"] == "s" else "r",
            "fo": dmarc["fo"] if dmarc["fo"] in ("0", "1", "d", "s") else "1",
            "rua": bool(dmarc["rua"]), "ruf": bool(dmarc["ruf"]),
        },
        "tlsrpt": bool(raw.get("tlsrpt", True)),
        "srv": bool(raw.get("srv", True)),
    }
    if "dkim_pending" in raw:
        result["dkim_pending"] = raw["dkim_pending"]
    return result


def dns_plan(row: dict, settings: dict) -> list[dict]:
    domain = row["name"]
    host = settings.get("hostname") or f"mail.{domain}"
    ip = settings.get("public_ip", "")
    cfg = clean_dns_settings(row["dns_settings"] or {}, domain)
    spf_parts = ["v=spf1"]
    if cfg["spf"]["mx"]:
        spf_parts.append("mx")
    if cfg["spf"]["a"]:
        spf_parts.append("a")
    if ip:
        spf_parts.append(f"ip4:{ip}")
    spf_parts += [f"ip4:{n}" for n in cfg["spf"]["ip4"] if n != ip and n != f"{ip}/32"]
    spf_parts += [f"include:{i}" for i in cfg["spf"]["include"]]
    spf_parts.append(cfg["spf"]["all"])
    d = cfg["dmarc"]
    dmarc = [f"v=DMARC1; p={d['p']}"]
    if d["sp"]:
        dmarc.append(f"sp={d['sp']}")
    if d["pct"] != 100:
        dmarc.append(f"pct={d['pct']}")
    if d["rua"]:
        dmarc.append(f"rua=mailto:dmarc@{domain}")
    if d["ruf"]:
        dmarc.append(f"ruf=mailto:dmarc@{domain}")
    if d["adkim"] == "s":
        dmarc.append("adkim=s")
    if d["aspf"] == "s":
        dmarc.append("aspf=s")
    if d["fo"] != "0":
        dmarc.append(f"fo={d['fo']}")
    plan = [
        {"key": "mx", "type": "MX", "name": domain, "value": f"10 {host}.", "required": True,
         "purpose": "Куда доставлять почту домена. Должен указывать на имя с A-записью, не на IP и не на CNAME."},
        {"key": "a", "type": "A", "name": host, "value": ip or "ВАШ_ПУБЛИЧНЫЙ_IP", "required": True,
         "purpose": "Адрес почтового сервера. Укажите публичный IP в настройках панели."},
        {"key": "ptr", "type": "PTR", "name": mailcore.reverse_name(ip) if ip else "(обратная зона IP)",
         "value": f"{host}.", "required": True,
         "purpose": "Обратная запись настраивается у провайдера IP, не в DNS домена. Без неё письма часто отклоняют."},
        {"key": "spf", "type": "TXT", "name": domain, "value": " ".join(spf_parts), "required": True,
         "purpose": "Кто вправе отправлять почту от имени домена. Только одна запись v=spf1 на имя."},
    ]
    if row.get("dkim_selector"):
        plan.append({"key": "dkim", "type": "TXT", "name": f"{row['dkim_selector']}._domainkey.{domain}",
                     "value": row["dkim_public"], "required": True,
                     "purpose": "Публичный ключ подписи DKIM. Закрытый ключ хранится на сервере и не публикуется."})
    pending = (row["dns_settings"] or {}).get("dkim_pending")
    if pending:
        plan.append({"key": "dkim_new", "type": "TXT", "name": f"{pending['selector']}._domainkey.{domain}",
                     "value": pending["public"], "required": True,
                     "purpose": "Новый ключ (ротация). Опубликуйте, проверьте и переключите подпись."})
    plan.append({"key": "dmarc", "type": "TXT", "name": f"_dmarc.{domain}", "value": "; ".join(dmarc), "required": True,
                 "purpose": "Политика для писем, не прошедших SPF/DKIM с выравниванием домена, и адрес отчётов."})
    if cfg["tlsrpt"]:
        plan.append({"key": "tlsrpt", "type": "TXT", "name": f"_smtp._tls.{domain}",
                     "value": f"v=TLSRPTv1; rua=mailto:tlsrpt@{domain}", "required": False,
                     "purpose": "Отчёты других серверов о проблемах TLS при доставке вам (RFC 8460)."})
    if cfg["srv"]:
        for svc, port in (("_imaps._tcp", 993), ("_submission._tcp", 587), ("_submissions._tcp", 465)):
            plan.append({"key": f"srv{port}", "type": "SRV", "name": f"{svc}.{domain}", "value": f"0 1 {port} {host}.",
                         "required": False, "purpose": "Автонастройка почтовых программ (RFC 6186 / 8314)."})
    return plan


POLICY_RANK = {"none": 0, "quarantine": 1, "reject": 2}


def adapt_plan(plan: list[dict], row: dict) -> list[dict]:
    """Учесть уже опубликованные SPF и DMARC, чтобы рекомендация не ломала действующую почту."""
    domain = row["name"]
    explicit = row["dns_settings"] or {}
    for rec in plan:
        if rec["key"] == "spf":
            live = [v for v in mailcore.dig(domain, "TXT") if v.lower().startswith("v=spf1")]
            if len(live) == 1:
                ours = rec["value"].split()
                extra = []
                for term in live[0].split()[1:]:
                    low = term.lower()
                    if low.startswith("redirect="):
                        term = "include:" + term.split("=", 1)[1]
                    elif low in ("-all", "~all", "?all", "+all", "all") or low.startswith("exp="):
                        continue
                    if term.lower() not in [o.lower() for o in ours] and term not in extra:
                        extra.append(term)
                if extra:
                    rec["value"] = " ".join(ours[:-1] + extra + ours[-1:])
                    rec["purpose"] += (" Рекомендация объединена с уже опубликованной записью «" + live[0] +
                                       "»: замените её этой, а не добавляйте вторую.")
        elif rec["key"] == "dmarc":
            live = [v for v in mailcore.dig(f"_dmarc.{domain}", "TXT") if v.lower().startswith("v=dmarc1")]
            if len(live) == 1 and "dmarc" not in explicit:
                tags = mailcore.parse_tags(live[0])
                want = mailcore.parse_tags(rec["value"])
                if POLICY_RANK.get(tags.get("p"), -1) > POLICY_RANK.get(want.get("p"), 0):
                    merged = {**want, **{k: v for k, v in tags.items() if k != "v"}}
                    for key in ("rua", "fo"):
                        if key not in tags and key in want:
                            merged[key] = want[key]
                    order = ["v", "p", "sp", "pct", "rua", "ruf", "adkim", "aspf", "fo", "ri"]
                    merged["v"] = "DMARC1"
                    rec["value"] = "; ".join(f"{k}={merged[k]}" for k in sorted(merged, key=lambda k: order.index(k) if k in order else 99))
                    rec["purpose"] += (f" Опубликована более строгая политика p={tags.get('p')} — она сохранена; "
                                       "добавлены только недостающие теги (адрес отчётов).")
    return plan


def check_record(rec: dict, row: dict, settings: dict) -> dict:
    t, name, want = rec["type"], rec["name"], rec["value"]
    host = (settings.get("hostname") or "").rstrip(".").lower()
    result = {"status": "fail", "found": [], "note": ""}
    if t == "PTR":
        ip = settings.get("public_ip")
        if not ip:
            return {**result, "status": "warn", "note": "Не задан публичный IP в настройках"}
        found = [f.rstrip(".").lower() for f in mailcore.dig(mailcore.reverse_name(ip), "PTR")]
        ok = host in found
        return {"status": "ok" if ok else "fail", "found": found,
                "note": "" if ok else "PTR должен указывать на имя сервера. Настраивается у провайдера."}
    found = mailcore.dig(name, t)
    result["found"] = found
    if t == "MX":
        hosts = [f.split()[-1].rstrip(".").lower() for f in found if f.split()]
        ok = host in hosts
        if ok or not hosts:
            result.update(status="ok" if ok else "fail", note="" if ok else "MX-записи нет: почту домена никто не принимает")
        else:
            result.update(status="warn", note=f"Почта домена сейчас обслуживается {', '.join(hosts)}. Меняйте MX на {host} "
                                              "только после переноса ящиков, иначе письма перестанут приходить туда")
    elif t == "A":
        ok = bool(settings.get("public_ip")) and settings["public_ip"] in found
        result.update(status="ok" if ok else ("warn" if not settings.get("public_ip") else "fail"),
                      note="" if ok else "A-запись не совпадает с публичным IP из настроек")
    elif rec["key"] == "spf":
        spf = [f for f in found if f.lower().startswith("v=spf1")]
        result["found"] = spf
        if not spf:
            result["note"] = "SPF-записи нет"
        elif len(spf) > 1:
            result["note"] = "Несколько записей v=spf1 — это ошибка, получатели засчитают permerror"
        else:
            terms = spf[0].lower().split()
            ip = settings.get("public_ip", "")
            covered = (ip and (f"ip4:{ip}" in terms or f"ip4:{ip}/32" in terms)) or "mx" in terms or "a" in terms
            if "+all" in terms or "?all" in terms:
                result.update(status="fail", note="+all/?all разрешает отправку кому угодно")
            elif not covered:
                result.update(status="fail", note="Запись не разрешает IP этого сервера")
            elif spf[0].strip() == want:
                result["status"] = "ok"
            else:
                result.update(status="warn", note="Запись есть и разрешает сервер, но отличается от рекомендуемой")
    elif rec["key"].startswith("dkim"):
        want_p = mailcore.parse_tags(want).get("p")
        got = [mailcore.parse_tags(f).get("p", "").replace(" ", "") for f in found if "p=" in f]
        ok = want_p in got
        result.update(status="ok" if ok else "fail", note="" if ok else ("Записи нет" if not got else "Ключ в DNS не совпадает"))
    elif rec["key"] == "dmarc":
        dm = [f for f in found if f.lower().startswith("v=dmarc1")]
        result["found"] = dm
        if len(dm) != 1:
            result["note"] = "DMARC-записи нет" if not dm else "Несколько записей DMARC"
        else:
            tags = mailcore.parse_tags(dm[0])
            if tags.get("p") not in ("none", "quarantine", "reject"):
                result["note"] = "Нет корректного тега p="
            elif {k: v.lower() for k, v in tags.items()} == {k: v.lower() for k, v in mailcore.parse_tags(want).items()}:
                result["status"] = "ok"
            else:
                want_tags = mailcore.parse_tags(want)
                missing = [k for k in want_tags if k not in tags]
                differs = [k for k in want_tags if k in tags and tags[k].lower() != want_tags[k].lower() and k != "v"]
                parts = []
                if missing:
                    parts.append("не хватает тегов: " + ", ".join(missing))
                if differs:
                    parts.append("отличаются: " + ", ".join(f"{k}={tags[k]} (рекомендуется {want_tags[k]})" for k in differs))
                result.update(status="warn", note="DMARC опубликован, но " + "; ".join(parts))
    else:
        norm = lambda s: s.replace(" ", "").rstrip(".").lower()
        ok = any(norm(f) == norm(want) for f in found)
        result.update(status="ok" if ok else ("warn" if not rec["required"] else "fail"),
                      note="" if ok else "Необязательная запись не опубликована" if not found else "Значение отличается")
    return result


@app.get("/api/domains/<int:domain_id>/dns")
@auth_required
def domain_dns(domain_id: int):
    with db() as con:
        row = domain_row(con, domain_id)
        settings = get_settings(con)
    plan = dns_plan(row, settings)
    if request.args.get("check") == "1":
        plan = adapt_plan(plan, row)
        for rec in plan:
            rec["check"] = check_record(rec, row, settings)
    return jsonify({"domain": row["name"], "records": plan,
                    "settings": clean_dns_settings(row["dns_settings"] or {}, row["name"]),
                    "dkim": {"selector": row["dkim_selector"], "state": row["dkim_state"],
                             "created_at": row["dkim_created_at"],
                             "pending": (row["dns_settings"] or {}).get("dkim_pending")},
                    "hostname": settings.get("hostname"), "public_ip": settings.get("public_ip")})


# ---------- ящики ----------

def mailbox_row(con, mailbox_id: int):
    row = con.one("SELECT m.*, d.name AS domain_name FROM mailboxes m JOIN domains d ON d.id = m.domain_id "
                  "WHERE m.id = %s", (mailbox_id,))
    if not row:
        raise BadRequest("Ящик не найден", 404)
    return row


def quota_usage() -> dict:
    ok, out = mailcore.helper("quota")
    if not ok:
        return {}
    try:
        return json.loads(out)
    except ValueError:
        return {}


@app.get("/api/mailboxes")
@auth_required
def list_mailboxes():
    with db() as con:
        rows = con.all("""SELECT m.id, m.localpart, m.quota_mb, m.status, m.created_at, m.display_name, m.last_login_at,
                                 m.password_changed_at, d.name AS domain_name, d.id AS domain_id, d.status AS domain_status
                            FROM mailboxes m JOIN domains d ON d.id = m.domain_id
                           ORDER BY d.name, m.localpart""")
    usage = quota_usage() if request.args.get("usage") == "1" else {}
    for row in rows:
        row["address"] = f"{row['localpart']}@{row['domain_name']}"
        row["used_bytes"] = usage.get(row["address"], {}).get("bytes")
        row["messages"] = usage.get(row["address"], {}).get("messages")
    return jsonify({"items": rows})


@app.post("/api/mailboxes")
@auth_required
@writer
def create_mailbox():
    data = payload()
    localpart = str(data.get("localpart", "")).strip().lower()
    domain_id = as_int(data.get("domain_id"), 0, 0, 2**31)
    quota_mb = as_int(data.get("quota_mb"), 2048, 1, 10_000_000)
    password = str(data.get("password") or "") or secrets.token_urlsafe(15)
    if not valid_localpart(localpart):
        raise BadRequest("Имя ящика: строчная латиница, цифры, точка, дефис и подчёркивание")
    with db() as con:
        domain = domain_row(con, domain_id)
        address = f"{localpart}@{domain['name']}"
        if problem := password_problem(password, address):
            raise BadRequest(problem)
        allocated = con.one("SELECT COALESCE(SUM(quota_mb),0) AS s FROM mailboxes WHERE domain_id = %s", (domain_id,))["s"]
        if allocated + quota_mb > domain["quota_mb"]:
            raise BadRequest(f"Превышена квота домена: свободно {domain['quota_mb'] - allocated} МБ")
        if con.one("SELECT 1 AS x FROM aliases WHERE domain_id = %s AND localpart = %s", (domain_id, localpart)):
            raise BadRequest("Такой адрес уже занят алиасом", 409)
        try:
            con.execute("INSERT INTO mailboxes(domain_id, localpart, quota_mb, password_hash, display_name, "
                        "password_changed_at, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                        (domain_id, localpart, quota_mb, mailbox_password_hash(password),
                         str(data.get("display_name", ""))[:100], now_iso(), now_iso()))
        except IntegrityError:
            raise BadRequest("Такой ящик уже существует", 409)
    mailcore.helper("dav-init", address)  # календарь и адресная книга по умолчанию
    audit("Ящик создан", f"{address}, квота {quota_mb} МБ")
    return jsonify({"status": "created", "address": address,
                    "generated_password": password if not data.get("password") else None}), 201


@app.patch("/api/mailboxes/<int:mailbox_id>")
@auth_required
@writer
def update_mailbox(mailbox_id: int):
    data = payload()
    with db() as con:
        row = mailbox_row(con, mailbox_id)
        address = f"{row['localpart']}@{row['domain_name']}"
        changes = []
        if "status" in data:
            status = "active" if data["status"] == "active" else "disabled"
            con.execute("UPDATE mailboxes SET status = %s WHERE id = %s", (status, mailbox_id))
            if status != "active":
                con.execute("DELETE FROM client_sessions WHERE mailbox_id = %s", (mailbox_id,))
            changes.append(f"статус {status}")
        if "quota_mb" in data:
            quota = as_int(data["quota_mb"], row["quota_mb"], 1, 10_000_000)
            domain = domain_row(con, row["domain_id"])
            allocated = con.one("SELECT COALESCE(SUM(quota_mb),0) AS s FROM mailboxes WHERE domain_id = %s AND id <> %s",
                                (row["domain_id"], mailbox_id))["s"]
            if allocated + quota > domain["quota_mb"]:
                raise BadRequest(f"Превышена квота домена: доступно {domain['quota_mb'] - allocated} МБ")
            con.execute("UPDATE mailboxes SET quota_mb = %s WHERE id = %s", (quota, mailbox_id))
            changes.append(f"квота {quota} МБ")
        if "display_name" in data:
            con.execute("UPDATE mailboxes SET display_name = %s WHERE id = %s", (str(data["display_name"])[:100], mailbox_id))
            changes.append("имя")
    if changes:
        audit("Ящик изменён", f"{address}: {', '.join(changes)}")
    return jsonify({"status": "updated"})


@app.delete("/api/mailboxes/<int:mailbox_id>")
@auth_required
@writer
def delete_mailbox(mailbox_id: int):
    purge = bool(payload().get("purge"))
    with db() as con:
        row = mailbox_row(con, mailbox_id)
        con.execute("DELETE FROM mailboxes WHERE id = %s", (mailbox_id,))
    address = f"{row['localpart']}@{row['domain_name']}"
    note = "письма оставлены на диске"
    if purge:
        ok, out = mailcore.helper("maildir-archive", row["domain_name"], row["localpart"])
        note = f"письма перенесены: {out}" if ok else f"письма НЕ перенесены: {out}"
    audit("Ящик удалён", f"{address}; {note}", "WARN")
    return jsonify({"status": "deleted", "note": note})


@app.post("/api/mailboxes/<int:mailbox_id>/password")
@auth_required
@writer
def reset_mailbox_password(mailbox_id: int):
    password = str(payload().get("password") or "") or secrets.token_urlsafe(15)
    with db() as con:
        row = mailbox_row(con, mailbox_id)
        address = f"{row['localpart']}@{row['domain_name']}"
        if problem := password_problem(password, address):
            raise BadRequest(problem)
        con.execute("UPDATE mailboxes SET password_hash = %s, password_changed_at = %s WHERE id = %s",
                    (mailbox_password_hash(password), now_iso(), mailbox_id))
        con.execute("DELETE FROM client_sessions WHERE mailbox_id = %s", (mailbox_id,))
    audit("Пароль ящика сброшен", address, "WARN")
    return jsonify({"address": address, "generated_password": password if not payload().get("password") else None})


# ---------- алиасы ----------

def parse_destinations(value) -> list[str]:
    items = value if isinstance(value, list) else re.split(r"[\s,;]+", str(value or ""))
    result = []
    for item in items:
        item = str(item).strip().lower()
        if not item:
            continue
        if not valid_email(item):
            raise BadRequest(f"Некорректный адрес получателя: {item}")
        if item not in result:
            result.append(item)
    if not result:
        raise BadRequest("Укажите хотя бы одного получателя")
    if len(result) > 50:
        raise BadRequest("Не больше 50 получателей у одного алиаса")
    return result


@app.get("/api/aliases")
@auth_required
def list_aliases():
    with db() as con:
        rows = con.all("SELECT a.*, d.name AS domain_name FROM aliases a JOIN domains d ON d.id = a.domain_id "
                       "ORDER BY d.name, a.localpart")
    for row in rows:
        row["address"] = f"@{row['domain_name']}" if row["localpart"] == "*" else f"{row['localpart']}@{row['domain_name']}"
    return jsonify({"items": rows})


@app.post("/api/aliases")
@auth_required
@writer
def create_alias():
    data = payload()
    localpart = str(data.get("localpart", "")).strip().lower()
    domain_id = as_int(data.get("domain_id"), 0, 0, 2**31)
    if localpart != "*" and not valid_localpart(localpart):
        raise BadRequest("Имя алиаса: строчная латиница, цифры, точка, дефис; * — любой адрес домена")
    destinations = parse_destinations(data.get("destinations"))
    with db() as con:
        domain = domain_row(con, domain_id)
        address = f"{localpart}@{domain['name']}"
        if address in destinations:
            raise BadRequest("Алиас не может пересылать сам на себя")
        if con.one("SELECT 1 AS x FROM mailboxes WHERE domain_id = %s AND localpart = %s", (domain_id, localpart)):
            raise BadRequest("Такой адрес уже занят ящиком", 409)
        try:
            con.execute("INSERT INTO aliases(domain_id, localpart, destinations, note, created_at) VALUES (%s,%s,%s,%s,%s)",
                        (domain_id, localpart, ",".join(destinations), str(data.get("note", ""))[:200], now_iso()))
        except IntegrityError:
            raise BadRequest("Такой алиас уже существует", 409)
    audit("Алиас создан", f"{address} → {', '.join(destinations)}")
    return jsonify({"status": "created"}), 201


@app.patch("/api/aliases/<int:alias_id>")
@auth_required
@writer
def update_alias(alias_id: int):
    data = payload()
    with db() as con:
        row = con.one("SELECT a.*, d.name AS domain_name FROM aliases a JOIN domains d ON d.id=a.domain_id WHERE a.id=%s",
                      (alias_id,))
        if not row:
            raise BadRequest("Алиас не найден", 404)
        if "destinations" in data:
            con.execute("UPDATE aliases SET destinations = %s WHERE id = %s",
                        (",".join(parse_destinations(data["destinations"])), alias_id))
        if "status" in data:
            con.execute("UPDATE aliases SET status = %s WHERE id = %s",
                        ("active" if data["status"] == "active" else "disabled", alias_id))
        if "note" in data:
            con.execute("UPDATE aliases SET note = %s WHERE id = %s", (str(data["note"])[:200], alias_id))
    audit("Алиас изменён", f"{row['localpart']}@{row['domain_name']}")
    return jsonify({"status": "updated"})


@app.delete("/api/aliases/<int:alias_id>")
@auth_required
@writer
def delete_alias(alias_id: int):
    with db() as con:
        row = con.one("SELECT a.localpart, d.name AS domain_name FROM aliases a JOIN domains d ON d.id=a.domain_id "
                      "WHERE a.id = %s", (alias_id,))
        if not row:
            raise BadRequest("Алиас не найден", 404)
        con.execute("DELETE FROM aliases WHERE id = %s", (alias_id,))
    audit("Алиас удалён", f"{row['localpart']}@{row['domain_name']}", "WARN")
    return jsonify({"status": "deleted"})


# ---------- очередь и трассировка ----------

QUEUE_ID_RE = re.compile(r"[0-9A-Za-z]{6,20}")


@app.get("/api/queue")
@auth_required
def queue_list():
    items = []
    for item in mailcore.postqueue_json()[:500]:
        reasons = [r.get("delay_reason", "") for r in item.get("recipients", []) if r.get("delay_reason")]
        items.append({"id": item.get("queue_id"), "queue": item.get("queue_name"), "sender": item.get("sender"),
                      "recipients": [r.get("address") for r in item.get("recipients", [])],
                      "reason": reasons[0] if reasons else "", "size": item.get("message_size"),
                      "arrival": datetime.fromtimestamp(item.get("arrival_time", 0), timezone.utc).isoformat()})
    return jsonify({"items": items, "summary": queue_summary()})


@app.post("/api/queue/action")
@auth_required
@writer
def queue_action():
    data = payload()
    action = data.get("action")
    if action == "flush":
        ok, out = mailcore.run(["postqueue", "-f"])
        audit("Очередь: повторная отправка всех писем", "")
        return jsonify({"ok": ok, "output": out})
    ids = [i for i in data.get("ids", []) if isinstance(i, str) and QUEUE_ID_RE.fullmatch(i)][:200]
    if action not in ("delete", "hold", "release", "requeue") or not ids:
        raise BadRequest("Не выбраны письма или неизвестное действие")
    ok, out = mailcore.helper(f"queue-{action}", *ids)
    audit(f"Очередь: {action}", ", ".join(ids), "WARN" if action == "delete" else "INFO")
    if not ok:
        raise MailError(out or "Помощник недоступен")
    return jsonify({"ok": True, "output": out})


@app.get("/api/trace")
@auth_required
def trace():
    query = request.args.get("q", "").strip()
    hours = as_int(request.args.get("hours"), 24, 1, 168)
    if len(query) < 4 or len(query) > 200:
        raise BadRequest("Укажите адрес, ID очереди или Message-ID (от 4 символов)")
    pattern = re.escape(query)
    ok, out = mailcore.run(["journalctl", "-u", "postfix@-", "-u", "postfix", "-u", "dovecot", "-u", "rspamd",
                            "--since", f"-{hours}h", "--no-pager", "-o", "short-iso", "-g", pattern, "-n", "400"],
                           timeout=20)
    lines = out.splitlines() if out else []
    # Вторая волна: все строки по найденным ID очереди, чтобы увидеть путь письма целиком.
    ids = sorted({m.group(1) for line in lines for m in [re.search(r"postfix/\S+\[\d+\]: ([0-9A-F]{6,20}):", line)] if m})[:20]
    if ids:
        ok2, out2 = mailcore.run(["journalctl", "-u", "postfix@-", "-u", "postfix", "-u", "dovecot",
                                  "--since", f"-{hours}h", "--no-pager", "-o", "short-iso",
                                  "-g", "|".join(ids), "-n", "1000"], timeout=20)
        if ok2 and out2:
            lines = sorted(set(lines) | set(out2.splitlines()))
    return jsonify({"query": query, "queue_ids": ids, "lines": [l for l in lines if not l.startswith("-- ")][-600:]})


@app.get("/api/logs")
@auth_required
def system_logs():
    units = {"postfix": ["postfix@-", "postfix"], "dovecot": ["dovecot"], "rspamd": ["rspamd"],
             "mailroom": ["mailroom"], "fail2ban": ["fail2ban"]}
    service = request.args.get("service", "postfix")
    if service not in units:
        raise BadRequest("Недопустимый сервис")
    cmd = ["journalctl", "--no-pager", "-o", "short-iso", "-n", "200"]
    for unit in units[service]:
        cmd += ["-u", unit]
    ok, output = mailcore.run(cmd, timeout=10)
    return jsonify({"service": service, "available": ok, "lines": output.splitlines()[-200:] if output else []})


@app.get("/api/audit")
@auth_required
def audit_list():
    limit = as_int(request.args.get("limit"), 200, 1, 1000)
    with db() as con:
        rows = con.all("SELECT * FROM audit_log ORDER BY id DESC LIMIT %s", (limit,))
    return jsonify({"items": rows})


# ---------- настройки ----------

@app.get("/api/settings")
@auth_required
def settings_get():
    items = get_settings()
    for key in SECRET_SETTINGS:
        items[key] = "••••••" if items.get(key) else ""
    return jsonify({"items": items})


@app.put("/api/settings")
@auth_required
@admin_only
def settings_put():
    data = payload()
    updates = {}
    if "hostname" in data:
        value = str(data["hostname"]).strip().lower().rstrip(".")
        if not valid_hostname(value) or "." not in value:
            raise BadRequest("Имя сервера должно быть полным (FQDN), например mail.example.com")
        updates["hostname"] = value
    if "public_ip" in data:
        value = str(data["public_ip"]).strip()
        if value:
            try:
                addr = ipaddress.IPv4Address(value)
            except ValueError:
                raise BadRequest("Публичный IP: адрес IPv4")
            value = str(addr)
        updates["public_ip"] = value
    if "client_host" in data:
        value = str(data["client_host"]).strip().lower().rstrip(".")
        if value and not (valid_hostname(value) and "." in value):
            raise BadRequest("Адрес для почтовых программ — имя (mail.example.com) или IP")
        updates["client_host"] = value
    if "webmail_url" in data:
        value = str(data["webmail_url"]).strip()
        if value and not re.fullmatch(r"https://[A-Za-z0-9.-]+(:\d+)?(/[\w./-]*)?", value):
            raise BadRequest("Адрес веб-почты должен начинаться с https://")
        updates["webmail_url"] = value
    if "message_size_mb" in data:
        updates["message_size_mb"] = str(as_int(data["message_size_mb"], 25, 1, 100))
    if "mynetworks" in data:
        nets = []
        for item in re.split(r"[\s,]+", str(data["mynetworks"])):
            if item:
                try:
                    nets.append(str(ipaddress.ip_network(item, strict=False)))
                except ValueError:
                    raise BadRequest(f"Некорректная сеть: {item}")
        if "127.0.0.0/8" not in nets:
            nets.insert(0, "127.0.0.0/8")
        updates["mynetworks"] = " ".join(nets)
    for key, low, high in (("send_limit_hour", 1, 10000), ("send_limit_message", 1, 500),
                           ("smtp_limit_hour", 1, 100000), ("backup_keep", 1, 365), ("backup_remote_port", 1, 65535)):
        if key in data:
            updates[key] = str(as_int(data[key], 100, low, high))
    if "alert_email" in data:
        value = str(data["alert_email"]).strip().lower()
        if value and not valid_email(value):
            raise BadRequest("Адрес для оповещений указан неверно")
        updates["alert_email"] = value
    if "telegram_token" in data and data["telegram_token"] != "••••••":
        value = str(data["telegram_token"]).strip()
        if value and not re.fullmatch(r"\d{5,15}:[A-Za-z0-9_-]{20,64}", value):
            raise BadRequest("Токен Telegram-бота имеет вид 123456789:AA…")
        updates["telegram_token"] = value
    if "telegram_chat" in data:
        value = str(data["telegram_chat"]).strip()
        if value and not re.fullmatch(r"-?\d{3,20}|@[A-Za-z0-9_]{5,32}", value):
            raise BadRequest("ID чата Telegram — число (например, 123456789) или @канал")
        updates["telegram_chat"] = value
    if "backup_remote" in data:
        value = str(data["backup_remote"]).strip()
        if value and not re.fullmatch(r"[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:/[A-Za-z0-9._/-]*", value):
            raise BadRequest("Удалённое хранилище: user@host:/путь/к/каталогу")
        updates["backup_remote"] = value
    if not updates:
        raise BadRequest("Нет допустимых настроек")
    with db() as con:
        for key, value in updates.items():
            con.execute("INSERT INTO settings(key, value, updated_at) VALUES (%s,%s,%s) ON CONFLICT (key) "
                        "DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at", (key, value, now_iso()))
    audit("Настройки изменены", ", ".join(f"{k}={v}" for k, v in updates.items()))
    return jsonify({"status": "updated", "items": updates})


@app.post("/api/settings/apply")
@auth_required
@admin_only
def settings_apply():
    """Применить к Postfix: myhostname, mynetworks, message_size_limit — через помощника."""
    s = get_settings()
    request_body = json.dumps({"myhostname": s["hostname"], "mynetworks": s["mynetworks"],
                               "message_size_limit": int(s["message_size_mb"]) * 1024 * 1024})
    ok, out = mailcore.helper("postconf-apply", stdin=request_body)
    audit("Настройки применены к Postfix", out[:300], "INFO" if ok else "ERROR")
    if not ok:
        raise MailError(out or "Помощник не выполнил команду")
    ok2, out2 = mailcore.helper("ratelimit-apply", s["smtp_limit_hour"])
    audit("Лимит отправки применён к Rspamd", out2[:200], "INFO" if ok2 else "ERROR")
    if not ok2:
        raise MailError("Postfix применён, но лимит Rspamd — нет: " + out2)
    return jsonify({"status": "applied", "output": f"{out}; {out2}"})


# ---------- диагностика ----------

@app.get("/api/diagnostics/dns")
@auth_required
def diag_dns():
    domain = request.args.get("domain", "").strip().lower()
    selector = request.args.get("selector", "").strip().lower()
    if not valid_domain(domain):
        raise BadRequest("Укажите корректный домен")
    if selector and not SELECTOR_RE.fullmatch(selector):
        raise BadRequest("Недопустимый DKIM-селектор")
    checks = [("MX", domain, "MX"), ("A", domain, "A"), ("SPF", domain, "TXT"), ("DMARC", f"_dmarc.{domain}", "TXT"),
              ("MTA-STS", f"_mta-sts.{domain}", "TXT"), ("TLS-RPT", f"_smtp._tls.{domain}", "TXT")]
    if selector:
        checks.append(("DKIM", f"{selector}._domainkey.{domain}", "TXT"))
    result = []
    for label, name, rtype in checks:
        values = mailcore.dig(name, rtype)
        if label == "SPF":
            values = [v for v in values if v.lower().startswith("v=spf1")]
        if label == "DMARC":
            values = [v for v in values if v.lower().startswith("v=dmarc1")]
        result.append({"name": label, "target": name, "ok": bool(values), "values": values})
    mx_hosts = [v.split()[-1].rstrip(".") for v in mailcore.dig(domain, "MX") if v.split()]
    for host in mx_hosts[:3]:
        ips = mailcore.dig(host, "A")
        for ip in ips[:2]:
            ptr = [p.rstrip(".") for p in mailcore.dig(mailcore.reverse_name(ip), "PTR")]
            result.append({"name": "PTR", "target": f"{host} ({ip})", "ok": host.lower() in [p.lower() for p in ptr],
                           "values": ptr or ["нет PTR"]})
    return jsonify({"domain": domain, "checks": result})


@app.get("/api/diagnostics/smtp")
@auth_required
def diag_smtp():
    host = request.args.get("host", "").strip()
    port = as_int(request.args.get("port"), 25, 1, 65535)
    if not valid_hostname(host) or port not in (25, 465, 587):
        raise BadRequest("Укажите имя или IP и порт 25, 465 или 587")
    steps = []
    started = time.time()
    try:
        client = smtplib.SMTP_SSL(host, port, timeout=10) if port == 465 else smtplib.SMTP(host, port, timeout=10)
        steps.append(f"Соединение: {int((time.time() - started) * 1000)} мс")
        code, ehlo = client.ehlo("mailroom.check")
        features = ehlo.decode(errors="replace").splitlines()
        steps.append(f"EHLO {code}: {features[0] if features else ''}")
        if port != 465 and client.has_extn("starttls"):
            client.starttls()
            client.ehlo("mailroom.check")
            steps.append("STARTTLS: успешно")
        elif port != 465:
            steps.append("STARTTLS: не предлагается")
        auth = client.esmtp_features.get("auth", "")
        steps.append(f"AUTH: {auth or 'не предлагается'}" + (" (на 25 так и должно быть)" if port == 25 and not auth else ""))
        client.quit()
        return jsonify({"ok": True, "steps": steps})
    except (OSError, smtplib.SMTPException) as exc:
        steps.append(f"Ошибка: {exc}")
        return jsonify({"ok": False, "steps": steps})


@app.get("/api/diagnostics/tls")
@auth_required
def diag_tls():
    host = request.args.get("host", "").strip()
    port = as_int(request.args.get("port"), 993, 1, 65535)
    if not valid_hostname(host) or port not in (25, 143, 465, 587, 993, 995, 443, 5080):
        raise BadRequest("Укажите имя и один из портов 25, 465, 587, 993, 995, 443")
    return jsonify(mailcore.tls_check(host, port))


@app.get("/api/diagnostics/dnsbl")
@auth_required
def diag_dnsbl():
    ip = request.args.get("ip", "").strip() or get_settings().get("public_ip", "")
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise BadRequest("Укажите IPv4-адрес (или задайте публичный IP в настройках)")
    return jsonify({"ip": ip, "lists": mailcore.dnsbl_check(ip)})


@app.post("/api/diagnostics/headers")
@auth_required
def diag_headers():
    text = str(payload().get("headers", ""))
    if len(text) < 20 or len(text) > 200_000:
        raise BadRequest("Вставьте заголовки письма целиком (Received, Authentication-Results и т. д.)")
    return jsonify(mailcore.analyze_headers(text))


@app.post("/api/diagnostics/send-test")
@auth_required
@writer
def diag_send_test():
    data = payload()
    to = str(data.get("to", "")).strip()
    sender = str(data.get("from", "")).strip().lower()
    if not valid_email(to):
        raise BadRequest("Укажите адрес получателя")
    with db() as con:
        users = {r["address"] for r in con.all("SELECT address FROM mail_users")}
    if sender not in users:
        raise BadRequest("Отправитель должен быть активным ящиком этого сервера")
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = f"Mailroom: тестовое письмо {datetime.now():%d.%m.%Y %H:%M}"
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=sender.split("@")[1])
    msg.set_content("Тестовое письмо из панели Mailroom.\n\nПроверьте у получателя заголовок "
                    "Authentication-Results: spf=pass, dkim=pass, dmarc=pass.\n"
                    "Вставьте заголовки в «Диагностика → Разбор заголовков», чтобы увидеть подробности.\n")
    try:
        with smtplib.SMTP(mailcore.SMTP_HOST, mailcore.SMTP_PORT, timeout=20) as smtp:
            response = smtp.send_message(msg)
            code, text = smtp.noop()
    except (OSError, smtplib.SMTPException) as exc:
        raise MailError(f"Postfix не принял письмо: {exc}")
    audit("Отправлено тестовое письмо", f"{sender} → {to}")
    return jsonify({"status": "queued", "message_id": msg["Message-ID"], "refused": response})


# ---------- рекомендации ----------

def rec(level: str, area: str, title: str, detail: str, fix: str = "", target: str = "", alert: bool = False) -> dict:
    """alert=True — эксплуатационная проблема: о ней приходит оповещение."""
    return {"level": level, "area": area, "title": title, "detail": detail, "fix": fix, "target": target, "alert": alert}


@app.get("/api/recommendations")
@auth_required
def recommendations():
    items = compute_recommendations()
    order = {"fail": 0, "warn": 1, "info": 2}
    return jsonify({"items": items, "summary": {k: sum(1 for i in items if i["level"] == k) for k in order},
                    "article": ARTICLE_URL})


def compute_recommendations(include_domains: bool = True) -> list[dict]:
    items = []
    with db() as con:
        settings = get_settings(con)
        domains = con.all("SELECT * FROM domains ORDER BY name")
        users = con.all("SELECT username, role, totp_enabled FROM users")
        aliases = {r["address"] for r in con.all("SELECT address FROM mail_aliases")}
        boxes = {r["address"] for r in con.all("SELECT address FROM mail_users")}
    host = settings.get("hostname", "")
    ip = settings.get("public_ip", "")
    ok, myhost = mailcore.run(["postconf", "-h", "myhostname"])
    if not host or host.endswith("example.net"):
        items.append(rec("fail", "Сервер", "Не задано имя почтового сервера",
                         "Имя используется в HELO, MX, сертификате и PTR.", "Настройки → Имя сервера", "settings"))
    elif ok and myhost.strip() != host:
        items.append(rec("warn", "Сервер", "Postfix использует другое имя",
                         f"В Postfix myhostname = {myhost.strip()}, в панели — {host}.",
                         "Настройки → «Применить к Postfix».", "settings"))
    if not ip:
        items.append(rec("warn", "Сервер", "Не указан публичный IP",
                         "Без него панель не сможет проверить A, PTR, SPF и чёрные списки.", "Настройки → Публичный IP", "settings"))
    else:
        try:
            if ipaddress.IPv4Address(ip).is_private:
                items.append(rec("warn", "Сервер", "Публичный IP — частный адрес",
                                 f"{ip} не маршрутизируется в Интернете: внешние серверы не смогут доставлять почту.",
                                 "Укажите внешний адрес NAT и пробросьте порты 25, 465, 587, 993.", "settings"))
        except ValueError:
            pass
    tls = mailcore.tls_check("127.0.0.1", 993)
    if not tls.get("ok"):
        items.append(rec("fail", "TLS", "IMAPS (993) не отвечает", tls.get("error", ""), "Проверьте Dovecot: Логи → Dovecot", alert=True))
    else:
        if tls["days_left"] < 14:
            items.append(rec("fail" if tls["days_left"] < 3 else "warn", "TLS", "Сертификат скоро истекает",
                             f"Осталось {tls['days_left']} дн.", "Обновите сертификат и перезагрузите Postfix и Dovecot.", alert=True))
        if host and host not in tls.get("san", []):
            items.append(rec("warn", "TLS", "Сертификат не содержит имя сервера",
                             f"В сертификате: {', '.join(tls.get('san', [])) or tls.get('subject')}.",
                             "Выпустите сертификат на имя сервера."))
        if tls.get("self_signed") or "Mailroom" in tls.get("issuer", ""):
            items.append(rec("info", "TLS", "Сертификат выпущен собственным CA",
                             "Для внутренней сети это нормально, но почтовые программы будут предупреждать, "
                             "пока пользователи не установят корневой сертификат (он доступен в веб-почте).",
                             "Для публичного сервера получите сертификат Let's Encrypt (certbot)."))
    services = ["postfix", "dovecot", "rspamd", "redis-server", "postgresql"]
    if shutil.which("radicale") or Path("/usr/bin/radicale").exists():
        services.append("radicale")
    for svc in services:
        if service_state(svc) != "active":
            items.append(rec("fail", "Сервисы", f"Сервис {svc} не работает", "", f"systemctl status {svc}", "logs", alert=True))
    if service_state("fail2ban") != "active":
        items.append(rec("warn", "Безопасность", "Fail2ban не работает",
                         "Без него перебор паролей SMTP/IMAP ничем не ограничен.", "apt install fail2ban; включите jail postfix-sasl и dovecot",
                         alert=True))
    q = queue_summary()
    if q.get("deferred", 0) > 20 or q.get("oldest_minutes", 0) > 240:
        items.append(rec("warn", "Очередь", "Письма задерживаются в очереди",
                         f"Отложено: {q.get('deferred')}, старейшее — {q.get('oldest_minutes')} мин.",
                         "Очередь → причина задержки; Трассировка по адресу.", "queue", alert=True))
    for user in users:
        if user["role"] == "admin" and not user["totp_enabled"]:
            items.append(rec("warn", "Безопасность", f"У администратора {user['username']} нет 2FA",
                             "Пароль — единственная защита панели, которая управляет всей почтой.", "Безопасность → Настроить 2FA", "security"))
    if (DATA_DIR / ".bootstrap-admin").exists():
        items.append(rec("warn", "Безопасность", "Не сменён стартовый пароль администратора",
                         "Файл .bootstrap-admin с паролем ещё лежит на сервере.", "Безопасность → Изменить пароль", "security"))
    try:
        usage = shutil.disk_usage("/var/vmail")
        free_pct = usage.free * 100 / usage.total
        if free_pct < 15:
            items.append(rec("fail" if free_pct < 5 else "warn", "Сервер", "Мало места для почты",
                             f"Свободно {free_pct:.0f} %.", "Расширьте диск или уменьшите квоты.", alert=True))
    except OSError:
        items.append(rec("fail", "Сервер", "Нет каталога /var/vmail", "", "Запустите deploy/install.sh", alert=True))
    items += backup_recommendations(settings)
    items += sending_recommendations(settings)
    if ip:
        for item in mailcore.dnsbl_check(ip):
            if item["status"] == "fail":
                items.append(rec("fail", "Репутация", f"IP в чёрном списке {item['list']}", item["detail"],
                                 "Найдите причину (взломанный ящик, открытый relay) и подайте заявку на удаление.", alert=True))
    for domain in (domains if include_domains else []):
        name = domain["name"]
        if domain["status"] != "active":
            continue
        for local in ("postmaster", "abuse"):
            if f"{local}@{name}" not in aliases and f"{local}@{name}" not in boxes:
                items.append(rec("warn", name, f"Нет адреса {local}@{name}",
                                 "RFC 5321/2142 требуют эти адреса; на них пишут о проблемах с вашей почтой.",
                                 "Алиасы → создать алиас на ящик администратора.", "aliases"))
        if domain["dkim_state"] == "none":
            items.append(rec("fail", name, "Нет DKIM-ключа",
                             "Без подписи DKIM письма хуже доставляются, а DMARC держится только на SPF.",
                             "Домены → DNS и DKIM → Создать ключ.", f"domain:{domain['id']}"))
        elif domain["dkim_state"] == "pending":
            items.append(rec("warn", name, "DKIM-ключ создан, но подпись не включена",
                             "Опубликуйте TXT-запись и нажмите «Проверить и включить».", "Домены → DNS и DKIM", f"domain:{domain['id']}"))
        plan = adapt_plan(dns_plan(domain, settings), domain)
        for record in plan:
            if record["key"] in ("ptr", "a") and not ip:
                continue
            if not record["required"]:
                continue
            check = check_record(record, domain, settings)
            if check["status"] != "ok":
                items.append(rec(check["status"], name, f"{record['type']} {record['name']}: {check['note'] or 'не совпадает'}",
                                 record["purpose"], f"Опубликуйте: {record['name']} {record['type']} {record['value']}",
                                 f"domain:{domain['id']}"))
        dmarc = mailcore.txt_records(f"_dmarc.{name}", "v=DMARC1")
        if dmarc:
            policy = mailcore.parse_tags(dmarc[0]).get("p")
            if policy == "none":
                items.append(rec("info", name, "DMARC в режиме наблюдения (p=none)",
                                 "Это правильный старт. Через 2–4 недели отчётов без ошибок легальных отправителей "
                                 "переходите к p=quarantine, затем к p=reject.", "Домены → DNS → DMARC", f"domain:{domain['id']}"))
    order = {"fail": 0, "warn": 1, "info": 2}
    items.sort(key=lambda i: order.get(i["level"], 3))
    return items


# ---------- резервные копии ----------

def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def read_backup_status() -> dict | None:
    try:
        return json.loads((DATA_DIR / "backup-status.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def backup_recommendations(settings: dict) -> list[dict]:
    status = read_backup_status()
    if not status:
        return [rec("warn", "Резервные копии", "Резервных копий ещё не было",
                    "Без копий сбой диска или ошибка уничтожат всю почту, ключи DKIM и базу.",
                    "Резервные копии → «Создать копию сейчас»; включите отправку на другой сервер.", "backups", alert=True)]
    items = []
    age_h = (datetime.now(timezone.utc) - datetime.fromisoformat(status["finished_at"])).total_seconds() / 3600
    if not status.get("ok"):
        items.append(rec("fail", "Резервные копии", "Последнее копирование завершилось ошибкой", status.get("error", ""),
                         "Резервные копии → журнал; journalctl -u mailroom-backup", "backups", alert=True))
    elif age_h > 48:
        items.append(rec("fail", "Резервные копии", "Копия устарела", f"Последняя успешная — {int(age_h)} ч назад.",
                         "Проверьте таймер: systemctl status mailroom-backup.timer", "backups", alert=True))
    if status.get("ok") and settings.get("backup_remote") and not str(status.get("remote", "")).startswith("отправлено"):
        items.append(rec("warn", "Резервные копии", "Копия не отправлена на удалённый сервер", status.get("remote", ""),
                         "Добавьте публичный ключ панели на сервер хранения (Резервные копии).", "backups", alert=True))
    if not settings.get("backup_remote"):
        items.append(rec("info", "Резервные копии", "Копии хранятся только на этом сервере",
                         "Если сервер выйдет из строя, пропадут и копии.", "Укажите удалённое хранилище в разделе «Резервные копии».",
                         "backups"))
    return items


@app.get("/api/backups")
@auth_required
def backups_list():
    ok, out = mailcore.helper("backup-list")
    data = json.loads(out) if ok and out.startswith("{") else {"items": [], "running": False, "error": out}
    s = get_settings()
    data.update(status=read_backup_status(), pubkey=read_text(DATA_DIR / "backup_ed25519.pub"),
                remote=s["backup_remote"], remote_port=s["backup_remote_port"], keep=s["backup_keep"])
    return jsonify(data)


@app.post("/api/backups/run")
@auth_required
@admin_only
def backups_run():
    ok, out = mailcore.helper("backup-start")
    audit("Запущено резервное копирование", out[:200], "INFO" if ok else "ERROR")
    if not ok:
        raise MailError(out or "Не удалось запустить копирование")
    return jsonify({"status": "started"})


# ---------- активность ящиков (по журналам) ----------

SASL_RE = re.compile(r"postfix/(submissions?)/smtpd\[\d+\]: [0-9A-F]+: client=[^\[]*\[([^\]]+)\].*sasl_username=(\S+)")
SASL_FAIL_RE = re.compile(r"postfix/\S+/smtpd\[\d+\]: warning: [^\[]*\[([^\]]+)\]: SASL \S+ authentication failed")
DOVE_LOGIN_RE = re.compile(r"(imap|pop3|managesieve)-login: Login: user=<([^>]*)>.*?rip=([0-9a-fA-F.:]+)")
DOVE_FAIL_RE = re.compile(r"(imap|pop3)-login: .*auth failed.*?user=<([^>]*)>.*?rip=([0-9a-fA-F.:]+)")
STAMP_RE = re.compile(r"^(\S+)")


def collect_activity(hours: int = 24) -> dict:
    since = f"-{hours}h"
    ok1, post = mailcore.run(["journalctl", "-u", "postfix", "-u", "postfix@-", "--since", since, "-o", "short-iso",
                              "--no-pager", "-g", "sasl_username=|authentication failed|Ratelimit"], timeout=20)
    ok2, dove = mailcore.run(["journalctl", "-u", "dovecot", "--since", since, "-o", "short-iso", "--no-pager",
                              "-g", "Login: user=|auth failed"], timeout=20)
    boxes: dict[str, dict] = {}
    fails: dict[str, int] = {}
    ratelimited = 0
    hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)

    def box(user):
        return boxes.setdefault(user.lower(), {"sent": 0, "sent_hour": 0, "send_ips": set(), "logins": 0,
                                               "login_ips": set(), "last_login": "", "failures": 0})

    def stamp(line):
        try:
            return datetime.fromisoformat(STAMP_RE.match(line).group(1))
        except (ValueError, AttributeError):
            return None

    for line in (post or "").splitlines():
        if m := SASL_RE.search(line):
            b = box(m.group(3))
            b["sent"] += 1
            b["send_ips"].add(m.group(2))
            ts = stamp(line)
            if ts and ts >= hour_ago:
                b["sent_hour"] += 1
        elif m := SASL_FAIL_RE.search(line):
            fails[m.group(1)] = fails.get(m.group(1), 0) + 1
        elif "Ratelimit" in line:
            ratelimited += 1
    for line in (dove or "").splitlines():
        if m := DOVE_LOGIN_RE.search(line):
            if m.group(3) in ("127.0.0.1", "::1"):
                continue  # веб-почта и служебные проверки
            b = box(m.group(2).split("*")[0])
            b["logins"] += 1
            b["login_ips"].add(m.group(3))
            b["last_login"] = STAMP_RE.match(line).group(1)
        elif m := DOVE_FAIL_RE.search(line):
            fails[m.group(3)] = fails.get(m.group(3), 0) + 1
            if m.group(2):
                box(m.group(2))["failures"] += 1
    result = {user: {**v, "send_ips": sorted(v["send_ips"]), "login_ips": sorted(v["login_ips"])} for user, v in boxes.items()}
    top_fails = sorted(fails.items(), key=lambda kv: -kv[1])[:20]
    return {"hours": hours, "mailboxes": result, "failed_ips": [{"ip": ip, "count": n} for ip, n in top_fails],
            "ratelimited": ratelimited, "journal_ok": ok1 and ok2}


@app.get("/api/activity")
@auth_required
def activity():
    return jsonify(collect_activity(as_int(request.args.get("hours"), 24, 1, 168)))


def sending_recommendations(settings: dict) -> list[dict]:
    items = []
    limit = int(settings.get("smtp_limit_hour") or 100)
    data = collect_activity(1)
    for user, v in data["mailboxes"].items():
        if v["sent_hour"] >= max(5, limit * 0.8):
            items.append(rec("warn", "Отправка", f"Всплеск отправки: {user}",
                             f"{v['sent_hour']} писем за час (лимит {limit}) с адресов {', '.join(v['send_ips'])}.",
                             "Если владелец не делал рассылку — смените пароль ящика: возможно, он украден.", "activity", alert=True))
    if data["ratelimited"]:
        items.append(rec("fail", "Отправка", "Сработал лимит отправки",
                         f"За час отклонено писем по лимиту: {data['ratelimited']}.",
                         "Активность → кто отправлял; при подозрении на взлом смените пароль ящика.", "activity", alert=True))
    total_fails = sum(f["count"] for f in data["failed_ips"])
    if total_fails >= 50:
        items.append(rec("warn", "Безопасность", "Перебор паролей",
                         f"За час неудачных входов: {total_fails}, больше всего с {data['failed_ips'][0]['ip']}.",
                         "Fail2ban блокирует адреса автоматически; проверьте, что он работает.", "activity", alert=True))
    return items


# ---------- оповещения ----------

def notify(subject: str, text: str, settings: dict | None = None) -> list[str]:
    """Отправить оповещение на почту и в Telegram. → список результатов по каналам."""
    import urllib.parse
    import urllib.request
    s = settings or get_settings()
    results = []
    if s.get("alert_email"):
        msg = EmailMessage()
        msg["From"] = f"Mailroom <mailroom@{s['hostname']}>"
        msg["To"] = s["alert_email"]
        msg["Subject"] = subject
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain=s["hostname"])
        msg.set_content(text)
        try:
            with smtplib.SMTP(mailcore.SMTP_HOST, mailcore.SMTP_PORT, timeout=20) as smtp:
                smtp.send_message(msg)
            results.append(f"почта: {s['alert_email']}")
        except (OSError, smtplib.SMTPException) as exc:
            results.append(f"почта: ошибка {exc}")
    if s.get("telegram_token") and s.get("telegram_chat"):
        body = urllib.parse.urlencode({"chat_id": s["telegram_chat"], "text": f"{subject}\n\n{text}"[:4000]}).encode()
        try:
            req = urllib.request.Request(f"https://api.telegram.org/bot{s['telegram_token']}/sendMessage", data=body)
            with urllib.request.urlopen(req, timeout=15) as resp:
                results.append("Telegram: доставлено" if resp.status == 200 else f"Telegram: HTTP {resp.status}")
        except OSError as exc:
            results.append(f"Telegram: ошибка {getattr(exc, 'code', '')} {exc}".strip())
    return results


def run_alerts(send: bool = True) -> dict:
    """Сравнить текущие проблемы с прошлым запуском и оповестить о новых, повторных (раз в сутки) и решённых."""
    now = int(time.time())
    current = {f"{i['area']}|{i['title']}": i for i in compute_recommendations(include_domains=False)
               if i["alert"] and i["level"] in ("fail", "warn")}
    with db() as con:
        state = {r["key"]: r for r in con.all("SELECT * FROM alert_state")}
        new = [k for k in current if k not in state]
        repeat = [k for k in current if k in state and now - state[k]["notified_at"] > 86400]
        resolved = [k for k in state if k not in current]
        for k in new:
            con.execute("INSERT INTO alert_state(key, level, title, first_seen, notified_at) VALUES (%s,%s,%s,%s,0)",
                        (k, current[k]["level"], current[k]["title"], now))
        for k in resolved:
            con.execute("DELETE FROM alert_state WHERE key = %s", (k,))
        settings = get_settings(con)
    sent = []
    if send and (new or repeat or resolved) and (settings.get("alert_email") or settings.get("telegram_token")):
        lines = []
        for k in new + repeat:
            i = current[k]
            mark = "ОШИБКА" if i["level"] == "fail" else "внимание"
            lines.append(f"[{mark}] {i['title']}\n  {i['detail']}\n  Что делать: {i['fix']}".rstrip())
        for k in resolved:
            lines.append(f"[решено] {state[k]['title']}")
        problems = len(current)
        subject = (f"Mailroom {settings['hostname']}: " +
                   (f"проблем — {problems}" if problems else "все проблемы решены"))
        sent = notify(subject, "\n\n".join(lines) + "\n\nПанель: https://" + settings["hostname"] + ":5080/#recommendations",
                      settings)
        with db() as con:
            for k in new + repeat:
                con.execute("UPDATE alert_state SET notified_at = %s WHERE key = %s", (now, k))
    return {"problems": list(current), "new": new, "repeat": repeat, "resolved": resolved, "sent": sent}


@app.post("/api/alerts/test")
@auth_required
@admin_only
def alerts_test():
    s = get_settings()
    if not s.get("alert_email") and not (s.get("telegram_token") and s.get("telegram_chat")):
        raise BadRequest("Укажите адрес почты или Telegram-бота и сохраните настройки")
    results = notify(f"Mailroom {s['hostname']}: тестовое оповещение",
                     "Если вы видите это сообщение, оповещения настроены правильно.", s)
    audit("Тестовое оповещение", "; ".join(results))
    return jsonify({"results": results})


@app.get("/api/alerts")
@auth_required
def alerts_state():
    with db() as con:
        rows = con.all("SELECT * FROM alert_state ORDER BY first_seen")
    return jsonify({"items": rows})


# ---------- веб-почта ----------

from webmail import bp as webmail_bp  # noqa: E402

app.register_blueprint(webmail_bp)

if os.getenv("MAILROOM_SKIP_INIT") != "1":
    init_db()

if __name__ == "__main__":
    app.run(host=os.getenv("MAIL_GATEWAY_HOST", "127.0.0.1"), port=int(os.getenv("MAIL_GATEWAY_PORT", "5080")))
