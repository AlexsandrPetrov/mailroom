from __future__ import annotations

import json
import base64
import functools
import hashlib
import hmac
import os
import re
import secrets
import struct
import shutil
import subprocess
import time
import socket
import smtplib
from setup_runner import load_profile, run as run_setup
try:
    from passlib.hash import sha512_crypt
except ImportError:
    sha512_crypt = None
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
import psycopg2
from psycopg2 import IntegrityError
from psycopg2.extras import RealDictCursor


BASE_DIR = Path(__file__).resolve().parent
DB_URL_PATH = BASE_DIR / ".db-url"
app = Flask(__name__)
SECRET_PATH = BASE_DIR / ".session-secret"
if SECRET_PATH.exists():
    SESSION_SECRET = SECRET_PATH.read_bytes()
else:
    SESSION_SECRET = secrets.token_bytes(32)
    SECRET_PATH.write_bytes(SESSION_SECRET)
    SECRET_PATH.chmod(0o600)
app.secret_key = SESSION_SECRET
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=False)
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 900


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
    if sha512_crypt:
        return sha512_crypt.hash(password)
    return password_hash(password)


def mailbox_password_verify(password: str, encoded: str | None) -> bool:
    if not encoded:
        return False
    if encoded.startswith("$6$") and sha512_crypt:
        return bool(sha512_crypt.verify(password, encoded))
    return password_verify(password, encoded)


def totp_code(secret: str, timestamp: int | None = None) -> str:
    counter = int((timestamp or time.time()) // 30)
    key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def verify_totp(secret: str, code: str) -> bool:
    return any(hmac.compare_digest(totp_code(secret, int(time.time()) + drift * 30), code) for drift in (-1, 0, 1))


def auth_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Требуется авторизация"}), 401
            return redirect(url_for("login_page"))
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


def client_auth_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("client_mailbox_id"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Требуется вход в клиентский портал"}), 401
            return redirect(url_for("client_login_page"))
        return view(*args, **kwargs)
    return wrapped


def csrf_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        expected = session.get("csrf_token")
        supplied = request.headers.get("X-CSRF-Token")
        if not expected or not supplied or not hmac.compare_digest(expected, supplied):
            return jsonify({"error": "Недействительный CSRF-токен"}), 403
        return view(*args, **kwargs)
    return wrapped


class DatabaseConnection:
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

    def execute(self, query: str, params=()):
        query = query.replace("?", "%s")
        cursor = self.connection.cursor(cursor_factory=RealDictCursor)
        cursor.execute(query, params)
        return cursor

    def executescript(self, query: str):
        cursor = self.connection.cursor()
        cursor.execute(query)
        cursor.close()


def db_connection() -> DatabaseConnection:
    dsn = os.getenv("MAILROOM_DATABASE_URL")
    if not dsn and DB_URL_PATH.exists():
        dsn = DB_URL_PATH.read_text(encoding="utf-8").strip()
    if not dsn:
        raise RuntimeError("MAILROOM_DATABASE_URL не настроен")
    return DatabaseConnection(dsn)


def init_db() -> None:
    with db_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS domains (
                id BIGSERIAL PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'active',
                quota_mb INTEGER NOT NULL DEFAULT 10240,
                created_at TEXT NOT NULL
            );
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
            CREATE TABLE IF NOT EXISTS audit_log (
                id BIGSERIAL PRIMARY KEY,
                level TEXT NOT NULL DEFAULT 'INFO',
                event TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
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
            CREATE TABLE IF NOT EXISTS login_attempts (
                id BIGSERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                ip TEXT NOT NULL,
                success BOOLEAN NOT NULL DEFAULT FALSE,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        if connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"] == 0:
            bootstrap_password = os.getenv("MAILROOM_ADMIN_PASSWORD") or secrets.token_urlsafe(18)
            now = datetime.now(timezone.utc).isoformat()
            connection.execute(
                "INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                ("admin", password_hash(bootstrap_password), "admin", now),
            )
            bootstrap_path = BASE_DIR / ".bootstrap-admin"
            bootstrap_path.write_text(f"username=admin\npassword={bootstrap_password}\n", encoding="utf-8")
            bootstrap_path.chmod(0o600)
            connection.execute(
                "INSERT INTO audit_log(level, event, details, created_at) VALUES (?, ?, ?, ?)",
                ("WARN", "Создан bootstrap-администратор", f"Данные сохранены в {bootstrap_path.name}", now),
            )
        if connection.execute("SELECT COUNT(*) AS count FROM domains").fetchone()["count"] == 0:
            now = datetime.now(timezone.utc).isoformat()
            connection.execute(
                "INSERT INTO domains(name, quota_mb, created_at) VALUES (?, ?, ?)",
                ("example.net", 10240, now),
            )
            connection.execute(
                "INSERT INTO mailboxes(domain_id, localpart, quota_mb, created_at) VALUES (1, ?, ?, ?)",
                ("postmaster", 2048, now),
            )
            connection.execute(
                "INSERT INTO audit_log(level, event, details, created_at) VALUES (?, ?, ?, ?)",
                ("INFO", "Демонстрационные данные созданы", "example.net / postmaster", now),
            )
        defaults = {
            "hostname": "mail.example.net",
            "mail_domain": "example.net",
            "relay_mode": "internet",
            "trusted_networks": "127.0.0.0/8",
            "smtp_listen": "loopback-only",
            "tls_mode": "may",
        }
        for key, value in defaults.items():
            connection.execute(
                "INSERT INTO settings(key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO NOTHING",
                (key, value, datetime.now(timezone.utc).isoformat()),
            )
        missing_passwords = connection.execute(
            """SELECT mailboxes.id, mailboxes.localpart, domains.name AS domain_name
               FROM mailboxes JOIN domains ON domains.id = mailboxes.domain_id
               WHERE mailboxes.password_hash IS NULL"""
        ).fetchall()
        if missing_passwords:
            bootstrap_lines = []
            for mailbox in missing_passwords:
                generated = secrets.token_urlsafe(15)
                connection.execute("UPDATE mailboxes SET password_hash = ? WHERE id = ?", (mailbox_password_hash(generated), mailbox["id"]))
                bootstrap_lines.append(f"{mailbox['localpart']}@{mailbox['domain_name']}={generated}")
            bootstrap_path = BASE_DIR / ".bootstrap-mailboxes"
            bootstrap_path.write_text("\n".join(bootstrap_lines) + "\n", encoding="utf-8")
            bootstrap_path.chmod(0o600)


def login_blocked(username: str, ip: str) -> bool:
    cutoff = int(time.time()) - LOCKOUT_SECONDS
    with db_connection() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS failures FROM login_attempts WHERE created_at >= ? AND success = FALSE AND (username = ? OR ip = ?)",
            (cutoff, username, ip),
        ).fetchone()
    return row["failures"] >= MAX_LOGIN_ATTEMPTS


def record_login(username: str, ip: str, success: bool) -> None:
    with db_connection() as connection:
        connection.execute(
            "INSERT INTO login_attempts(username, ip, success, created_at) VALUES (?, ?, ?, ?)",
            (username, ip, success, int(time.time())),
        )
        connection.execute("DELETE FROM login_attempts WHERE created_at < ?", (int(time.time()) - 86_400,))


def audit(event: str, details: str = "", level: str = "INFO") -> None:
    with db_connection() as connection:
        connection.execute(
            "INSERT INTO audit_log(level, event, details, created_at) VALUES (?, ?, ?, ?)",
            (level, event, details, datetime.now(timezone.utc).isoformat()),
        )


def valid_domain(value: str) -> bool:
    return bool(re.fullmatch(r"(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value.lower()))


def valid_localpart(value: str) -> bool:
    return bool(re.fullmatch(r"[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}", value))


def valid_hostname(value: str) -> bool:
    return bool(re.fullmatch(r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", value))


def run_readonly(command: list[str], timeout: int = 4) -> tuple[bool, str]:
    """Run a fixed, read-only system command without invoking a shell."""
    if not shutil.which(command[0]):
        return False, f"{command[0]} не установлен"
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    output = (result.stdout or result.stderr).strip()
    return result.returncode == 0, output


def service_status(service: str) -> dict:
    if not shutil.which("systemctl"):
        return {"name": service, "state": "unknown", "detail": "systemd недоступен"}
    ok, output = run_readonly(["systemctl", "is-active", service])
    state = output if ok else "inactive"
    return {"name": service, "state": state, "detail": output or "нет ответа"}


def queue_snapshot() -> dict:
    ok, output = run_readonly(["postqueue", "-p"])
    if not ok:
        return {"available": False, "count": 0, "raw": output}
    first_line = output.splitlines()[0] if output else ""
    count = 0
    if "Mail queue is empty" not in output:
        count = sum(1 for line in output.splitlines() if line and line[0].isalnum() and "*" not in line)
    return {"available": True, "count": count, "raw": first_line}


def postfix_config() -> dict:
    ok, output = run_readonly(["postconf", "-n"])
    if not ok:
        return {"available": False, "values": [], "error": output}
    hidden = {"sasl_passwd", "password", "api_key", "apikey", "secret"}
    values = []
    for line in output.splitlines():
        key, separator, value = line.partition(" = ")
        if not separator:
            continue
        if any(token in key.lower() for token in hidden):
            value = "********"
        values.append({"key": key, "value": value})
    return {"available": True, "values": values, "error": None}


def rows_as_dict(rows: list[dict]) -> list[dict]:
    return [dict(row) for row in rows]


@app.get("/login")
def login_page():
    if session.get("user_id"):
        return redirect(url_for("index"))
    return render_template("login.html")


@app.post("/api/auth/login")
def login():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip().lower()
    password = str(payload.get("password", ""))
    otp = str(payload.get("otp", "")).strip()
    ip = request.remote_addr or "unknown"
    if not username or not password or login_blocked(username, ip):
        record_login(username, ip, False)
        audit("Неудачная попытка входа", f"{username} from {ip}", "WARN")
        return jsonify({"error": "Неверные учётные данные или временная блокировка"}), 401
    with db_connection() as connection:
        user = connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not user or not password_verify(password, user["password_hash"]):
        record_login(username, ip, False)
        audit("Неудачная попытка входа", f"{username} from {ip}", "WARN")
        return jsonify({"error": "Неверные учётные данные или временная блокировка"}), 401
    if user["totp_enabled"] and not otp:
        session.clear()
        session["pending_2fa_user_id"] = user["id"]
        session["pending_2fa_username"] = user["username"]
        return jsonify({"status": "requires_2fa"})
    if user["totp_enabled"] and not verify_totp(user["totp_secret"], otp):
        record_login(username, ip, False)
        return jsonify({"error": "Неверный код 2FA"}), 401
    return finish_login(user, ip)


def finish_login(user, ip: str):
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    record_login(user["username"], ip, True)
    with db_connection() as connection:
        connection.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (datetime.now(timezone.utc).isoformat(), user["id"]))
    audit("Успешный вход", f"{user['username']} from {ip}")
    return jsonify({"status": "ok", "csrf_token": session["csrf_token"], "totp_enabled": bool(user["totp_enabled"])})


@app.post("/api/auth/verify-2fa")
def verify_second_factor():
    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        return jsonify({"error": "Сессия 2FA не найдена"}), 401
    payload = request.get_json(silent=True) or {}
    code = str(payload.get("otp", "")).strip()
    ip = request.remote_addr or "unknown"
    with db_connection() as connection:
        user = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or not verify_totp(user["totp_secret"], code):
        record_login(user["username"] if user else "unknown", ip, False)
        return jsonify({"error": "Неверный код 2FA"}), 401
    return finish_login(user, ip)


@app.post("/api/auth/logout")
def logout():
    username = session.get("username", "unknown")
    session.clear()
    audit("Выход из панели", username)
    return jsonify({"status": "ok"})


@app.get("/api/auth/me")
@auth_required
def auth_me():
    with db_connection() as connection:
        user = connection.execute("SELECT username, totp_enabled FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return jsonify({"username": user["username"], "totp_enabled": bool(user["totp_enabled"]), "csrf_token": session["csrf_token"]})


@app.post("/api/auth/totp/setup")
@auth_required
@csrf_required
def totp_setup():
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    with db_connection() as connection:
        connection.execute("UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?", (secret, session["user_id"]))
    username = session.get("username", "admin")
    uri = f"otpauth://totp/Mailroom:{username}?secret={secret}&issuer=Mailroom"
    return jsonify({"secret": secret, "otpauth_uri": uri})


@app.post("/api/auth/password")
@auth_required
@csrf_required
def change_password():
    payload = request.get_json(silent=True) or {}
    current = str(payload.get("current_password", ""))
    new_password = str(payload.get("new_password", ""))
    if len(new_password) < 14:
        return jsonify({"error": "Новый пароль должен содержать минимум 14 символов"}), 400
    with db_connection() as connection:
        user = connection.execute("SELECT password_hash FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if not user or not password_verify(current, user["password_hash"]):
            return jsonify({"error": "Текущий пароль указан неверно"}), 400
        connection.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash(new_password), session["user_id"]))
    audit("Пароль администратора изменён", session.get("username", "admin"))
    return jsonify({"status": "changed"})


@app.post("/api/auth/totp/enable")
@auth_required
@csrf_required
def totp_enable():
    payload = request.get_json(silent=True) or {}
    code = str(payload.get("code", "")).strip()
    with db_connection() as connection:
        user = connection.execute("SELECT totp_secret FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if not user or not user["totp_secret"] or not verify_totp(user["totp_secret"], code):
            return jsonify({"error": "Неверный код 2FA"}), 400
        connection.execute("UPDATE users SET totp_enabled = 1 WHERE id = ?", (session["user_id"],))
    audit("2FA включена", session.get("username", "admin"))
    return jsonify({"status": "enabled"})


@app.get("/client/login")
def client_login_page():
    if session.get("client_mailbox_id"):
        return redirect(url_for("client_index"))
    return render_template("client_login.html")


@app.post("/api/client/login")
def client_login():
    payload = request.get_json(silent=True) or {}
    address = str(payload.get("address", "")).strip().lower()
    password = str(payload.get("password", ""))
    if "@" not in address or not password:
        return jsonify({"error": "Укажите адрес ящика и пароль"}), 400
    localpart, domain_name = address.rsplit("@", 1)
    with db_connection() as connection:
        mailbox = connection.execute(
            """SELECT mailboxes.id, mailboxes.password_hash, mailboxes.status,
                      mailboxes.localpart, domains.name AS domain_name
               FROM mailboxes JOIN domains ON domains.id = mailboxes.domain_id
               WHERE lower(mailboxes.localpart) = ? AND lower(domains.name) = ?""",
            (localpart, domain_name),
        ).fetchone()
    if not mailbox or mailbox["status"] != "active" or not mailbox_password_verify(password, mailbox["password_hash"]):
        return jsonify({"error": "Неверный адрес или пароль"}), 401
    session["client_mailbox_id"] = mailbox["id"]
    session["client_address"] = f"{mailbox['localpart']}@{mailbox['domain_name']}"
    return jsonify({"status": "ok"})


@app.post("/api/client/logout")
def client_logout():
    session.pop("client_mailbox_id", None)
    session.pop("client_address", None)
    return jsonify({"status": "ok"})


@app.get("/client")
@client_auth_required
def client_index():
    return render_template("client.html")


@app.get("/api/client/me")
@client_auth_required
def client_me():
    with db_connection() as connection:
        mailbox = connection.execute(
            """SELECT mailboxes.localpart, mailboxes.quota_mb, mailboxes.status,
                      domains.name AS domain_name
               FROM mailboxes JOIN domains ON domains.id = mailboxes.domain_id
               WHERE mailboxes.id = ?""", (session["client_mailbox_id"],)
        ).fetchone()
    if not mailbox:
        session.pop("client_mailbox_id", None)
        return jsonify({"error": "Ящик не найден"}), 404
    return jsonify({"address": f"{mailbox['localpart']}@{mailbox['domain_name']}", "quota_mb": mailbox["quota_mb"], "status": mailbox["status"], "imap": {"host": "mail.example.net", "ports": [993, 995], "tls": True}, "smtp": {"host": "mail.example.net", "port": 587, "tls": True}})


@app.post("/api/client/password")
@client_auth_required
def client_change_password():
    payload = request.get_json(silent=True) or {}
    current = str(payload.get("current_password", ""))
    new_password = str(payload.get("new_password", ""))
    if len(new_password) < 14:
        return jsonify({"error": "Пароль должен содержать минимум 14 символов"}), 400
    with db_connection() as connection:
        mailbox = connection.execute("SELECT password_hash FROM mailboxes WHERE id = ?", (session["client_mailbox_id"],)).fetchone()
        if not mailbox or not mailbox_password_verify(current, mailbox["password_hash"]):
            return jsonify({"error": "Текущий пароль указан неверно"}), 400
        connection.execute("UPDATE mailboxes SET password_hash = ? WHERE id = ?", (mailbox_password_hash(new_password), session["client_mailbox_id"]))
    audit("Клиент изменил пароль ящика", session.get("client_address", ""))
    return jsonify({"status": "changed"})


@app.get("/api/users")
@auth_required
@role_required("admin")
def list_users():
    with db_connection() as connection:
        rows = connection.execute("SELECT id, username, role, totp_enabled, created_at, last_login_at FROM users ORDER BY username").fetchall()
    return jsonify({"items": [dict(row) for row in rows]})


@app.post("/api/users")
@auth_required
@role_required("admin")
@csrf_required
def create_user():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip().lower()
    password = str(payload.get("password", ""))
    role = str(payload.get("role", "operator"))
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,31}", username):
        return jsonify({"error": "Логин: 3-32 символа, латиница, цифры, . _ -"}), 400
    if len(password) < 14:
        return jsonify({"error": "Пароль должен содержать минимум 14 символов"}), 400
    if role not in {"admin", "operator", "viewer"}:
        return jsonify({"error": "Недопустимая роль"}), 400
    try:
        with db_connection() as connection:
            connection.execute("INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, ?, ?)", (username, password_hash(password), role, datetime.now(timezone.utc).isoformat()))
        audit("Пользователь добавлен", f"{username}, роль {role}")
    except IntegrityError:
        return jsonify({"error": "Такой пользователь уже существует"}), 409
    return jsonify({"status": "created"}), 201


@app.delete("/api/users/<int:user_id>")
@auth_required
@role_required("admin")
@csrf_required
def delete_user(user_id: int):
    if user_id == session.get("user_id"):
        return jsonify({"error": "Нельзя удалить текущего пользователя"}), 400
    with db_connection() as connection:
        user = connection.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return jsonify({"error": "Пользователь не найден"}), 404
        connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
    audit("Пользователь удалён", user["username"], "WARN")
    return jsonify({"status": "deleted"})


@app.get("/api/diagnostics/dns")
@auth_required
def dns_diagnostics():
    domain = request.args.get("domain", "").strip().lower()
    selector = request.args.get("selector", "default").strip()
    if not valid_domain(domain):
        return jsonify({"error": "Укажите корректный почтовый домен"}), 400
    if not re.fullmatch(r"[a-zA-Z0-9._-]{1,63}", selector):
        return jsonify({"error": "Недопустимый DKIM selector"}), 400
    checks = []
    queries = [("A/AAAA", ["A", "AAAA"]), ("MX", ["MX"]), ("SPF", ["TXT"]), ("DMARC", ["TXT"], f"_dmarc.{domain}"), ("DKIM", ["TXT"], f"{selector}._domainkey.{domain}")]
    for entry in queries:
        label, record_types = entry[:2]
        name = entry[2] if len(entry) > 2 else domain
        command = ["dig", "+short", name, *record_types]
        ok, output = run_readonly(command, timeout=5)
        checks.append({"name": label, "target": name, "ok": bool(ok and output), "value": output or "нет записи"})
    return jsonify({"domain": domain, "checks": checks})


@app.get("/api/diagnostics/smtp")
@auth_required
def smtp_diagnostics():
    host = request.args.get("host", "").strip()
    try:
        port = int(request.args.get("port", "25"))
    except ValueError:
        return jsonify({"error": "Порт должен быть числом"}), 400
    if not valid_hostname(host) or port not in {25, 465, 587}:
        return jsonify({"error": "Разрешены корректный hostname и порты 25, 465, 587"}), 400
    try:
        if port == 465:
            client = smtplib.SMTP_SSL(host, port, timeout=8)
        else:
            client = smtplib.SMTP(host, port, timeout=8)
        code, banner = client.noop()
        if port == 587:
            client.starttls()
        client.quit()
        return jsonify({"ok": code < 400, "code": code, "banner": banner.decode(errors="replace") if isinstance(banner, bytes) else str(banner)})
    except (OSError, smtplib.SMTPException) as exc:
        return jsonify({"ok": False, "error": str(exc)})


@app.get("/api/setup/plan")
@auth_required
def setup_plan():
    return jsonify(run_setup(load_profile(), apply=False))


@app.post("/api/setup/run")
@auth_required
@role_required("admin")
@csrf_required
def setup_run():
    payload = request.get_json(silent=True) or {}
    if payload.get("apply") is not True:
        return jsonify(run_setup(load_profile(), apply=False))
    try:
        report = run_setup(load_profile(), apply=True)
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 403
    audit("Запущена автоматическая настройка", f"mode={report['mode']}")
    return jsonify(report)


@app.get("/")
@auth_required
def index():
    return render_template("index.html")


@app.get("/api/overview")
@auth_required
def overview():
    services = [service_status(name) for name in ("postfix", "dovecot", "rspamd")]
    return jsonify(
        {
            "host": os.uname().nodename,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "services": services,
            "queue": queue_snapshot(),
            "mode": "PostgreSQL control plane",
        }
    )


@app.get("/api/config")
@auth_required
def config():
    return jsonify(postfix_config())


@app.get("/api/collectors")
@auth_required
def collectors():
    # Storage will be added with authentication and encrypted secrets in the next slice.
    return jsonify(
        {
            "items": [
                {
                    "id": "demo-support",
                    "name": "support@example.org",
                    "protocol": "IMAPS",
                    "destination": "support@example.net",
                    "schedule": "Каждые 5 минут",
                    "state": "Ожидает настройки",
                }
            ]
        }
    )


@app.get("/api/domains")
@auth_required
def list_domains():
    with db_connection() as connection:
        domains = rows_as_dict(connection.execute("SELECT * FROM domains ORDER BY name").fetchall())
        for domain in domains:
            domain["mailbox_count"] = connection.execute(
                "SELECT COUNT(*) AS count FROM mailboxes WHERE domain_id = ?", (domain["id"],)
            ).fetchone()["count"]
    return jsonify({"items": domains})


@app.post("/api/domains")
@auth_required
@csrf_required
def create_domain():
    from flask import request

    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip().lower()
    quota_mb = int(payload.get("quota_mb", 10240))
    if not valid_domain(name):
        return jsonify({"error": "Укажите корректное полное доменное имя"}), 400
    if quota_mb < 1 or quota_mb > 10_000_000:
        return jsonify({"error": "Квота должна быть от 1 до 10000000 МБ"}), 400
    try:
        with db_connection() as connection:
            connection.execute(
                "INSERT INTO domains(name, quota_mb, created_at) VALUES (?, ?, ?)",
                (name, quota_mb, datetime.now(timezone.utc).isoformat()),
            )
        audit("Домен добавлен", f"{name}, квота {quota_mb} МБ")
    except IntegrityError:
        return jsonify({"error": "Такой домен уже существует"}), 409
    return jsonify({"status": "created"}), 201


@app.delete("/api/domains/<int:domain_id>")
@auth_required
@csrf_required
def delete_domain(domain_id: int):
    with db_connection() as connection:
        domain = connection.execute("SELECT name FROM domains WHERE id = ?", (domain_id,)).fetchone()
        if not domain:
            return jsonify({"error": "Домен не найден"}), 404
        connection.execute("DELETE FROM domains WHERE id = ?", (domain_id,))
    audit("Домен удалён", domain["name"], "WARN")
    return jsonify({"status": "deleted"})


@app.get("/api/mailboxes")
@auth_required
def list_mailboxes():
    with db_connection() as connection:
        rows = connection.execute(
            """SELECT mailboxes.*, domains.name AS domain_name
               FROM mailboxes JOIN domains ON domains.id = mailboxes.domain_id
               ORDER BY domains.name, mailboxes.localpart"""
        ).fetchall()
    return jsonify({"items": rows_as_dict(rows)})


@app.post("/api/mailboxes")
@auth_required
@csrf_required
def create_mailbox():
    from flask import request

    payload = request.get_json(silent=True) or {}
    localpart = str(payload.get("localpart", "")).strip()
    domain_id = int(payload.get("domain_id", 0))
    quota_mb = int(payload.get("quota_mb", 2048))
    mailbox_password = str(payload.get("password", "")) or secrets.token_urlsafe(15)
    if not valid_localpart(localpart):
        return jsonify({"error": "Недопустимое имя почтового ящика"}), 400
    if quota_mb < 1 or quota_mb > 10_000_000:
        return jsonify({"error": "Квота должна быть от 1 до 10000000 МБ"}), 400
    try:
        with db_connection() as connection:
            domain = connection.execute("SELECT name FROM domains WHERE id = ?", (domain_id,)).fetchone()
            if not domain:
                return jsonify({"error": "Домен не найден"}), 404
            connection.execute(
                "INSERT INTO mailboxes(domain_id, localpart, quota_mb, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (domain_id, localpart, quota_mb, mailbox_password_hash(mailbox_password), datetime.now(timezone.utc).isoformat()),
            )
        audit("Почтовый ящик добавлен", f"{localpart}@{domain['name']}, квота {quota_mb} МБ")
    except IntegrityError:
        return jsonify({"error": "Такой почтовый ящик уже существует"}), 409
    return jsonify({"status": "created", "address": f"{localpart}@{domain['name']}", "generated_password": mailbox_password}), 201


@app.delete("/api/mailboxes/<int:mailbox_id>")
@auth_required
@csrf_required
def delete_mailbox(mailbox_id: int):
    with db_connection() as connection:
        mailbox = connection.execute(
            """SELECT mailboxes.localpart, domains.name AS domain_name
               FROM mailboxes JOIN domains ON domains.id = mailboxes.domain_id
               WHERE mailboxes.id = ?""", (mailbox_id,)
        ).fetchone()
        if not mailbox:
            return jsonify({"error": "Почтовый ящик не найден"}), 404
        connection.execute("DELETE FROM mailboxes WHERE id = ?", (mailbox_id,))
    audit("Почтовый ящик удалён", f"{mailbox['localpart']}@{mailbox['domain_name']}", "WARN")
    return jsonify({"status": "deleted"})


@app.post("/api/mailboxes/<int:mailbox_id>/password")
@auth_required
@csrf_required
def reset_mailbox_password(mailbox_id: int):
    generated_password = secrets.token_urlsafe(15)
    with db_connection() as connection:
        mailbox = connection.execute(
            """SELECT mailboxes.localpart, domains.name AS domain_name
               FROM mailboxes JOIN domains ON domains.id = mailboxes.domain_id
               WHERE mailboxes.id = ?""", (mailbox_id,)
        ).fetchone()
        if not mailbox:
            return jsonify({"error": "Почтовый ящик не найден"}), 404
        connection.execute("UPDATE mailboxes SET password_hash = ? WHERE id = ?", (mailbox_password_hash(generated_password), mailbox_id))
    address = f"{mailbox['localpart']}@{mailbox['domain_name']}"
    audit("Пароль почтового ящика сброшен", address, "WARN")
    return jsonify({"address": address, "generated_password": generated_password})


@app.get("/api/settings")
@auth_required
def get_settings():
    with db_connection() as connection:
        rows = connection.execute("SELECT key, value, updated_at FROM settings ORDER BY key").fetchall()
    return jsonify({"items": [dict(row) for row in rows]})


@app.put("/api/settings")
@auth_required
@role_required("admin", "operator")
@csrf_required
def update_settings():
    payload = request.get_json(silent=True) or {}
    allowed = {"hostname", "mail_domain", "relay_mode", "trusted_networks", "smtp_listen", "tls_mode"}
    updates = {str(key): str(value).strip() for key, value in payload.items() if key in allowed}
    if not updates:
        return jsonify({"error": "Нет допустимых настроек"}), 400
    if "mail_domain" in updates and not valid_domain(updates["mail_domain"]):
        return jsonify({"error": "Некорректный почтовый домен"}), 400
    if "hostname" in updates and not valid_hostname(updates["hostname"]):
        return jsonify({"error": "Некорректное имя сервера"}), 400
    if "relay_mode" in updates and updates["relay_mode"] not in {"internet", "smarthost", "internal"}:
        return jsonify({"error": "Недопустимый режим relay"}), 400
    if "smtp_listen" in updates and updates["smtp_listen"] not in {"loopback-only", "all"}:
        return jsonify({"error": "Недопустимый режим прослушивания SMTP"}), 400
    now = datetime.now(timezone.utc).isoformat()
    with db_connection() as connection:
        for key, value in updates.items():
            connection.execute("INSERT INTO settings(key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at", (key, value, now))
    audit("Настройки сервера изменены", ", ".join(sorted(updates)))
    return jsonify({"status": "updated", "items": updates})


@app.get("/api/audit")
@auth_required
def audit_log():
    limit = min(max(int(__import__("flask").request.args.get("limit", 100)), 1), 500)
    with db_connection() as connection:
        rows = connection.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return jsonify({"items": rows_as_dict(rows)})


@app.get("/api/logs")
@auth_required
def system_logs():
    from flask import request

    service = request.args.get("service", "postfix")
    if service not in {"postfix", "dovecot", "rspamd"}:
        return jsonify({"error": "Недопустимый сервис"}), 400
    ok, output = run_readonly(["journalctl", "-u", service, "-n", "80", "--no-pager", "-o", "short-iso"])
    return jsonify({"service": service, "available": ok, "lines": output.splitlines()[-80:] if output else []})


@app.get("/api/health")
def health():
    return jsonify({"status": "ok"})


init_db()

if __name__ == "__main__":
    app.run(host=os.getenv("MAIL_GATEWAY_HOST", "127.0.0.1"), port=int(os.getenv("MAIL_GATEWAY_PORT", "5080")))
