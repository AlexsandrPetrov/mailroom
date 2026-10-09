"""Веб-почта Mailroom (см. docs/PROMPT_WEBMAIL.md).

Пароль пользователя проверяется по базе Mailroom и нигде не сохраняется:
IMAP и ManageSieve открываются через мастер-пользователя Dovecot.
Сессии хранятся на сервере (client_sessions), cookie содержит только случайный токен.
"""
from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import html as htmllib
import os
import re
import secrets
import smtplib
import threading
import time
from email.message import EmailMessage
from email.utils import formataddr, formatdate, getaddresses, make_msgid
from pathlib import Path

from flask import Blueprint, Response, g, jsonify, redirect, render_template, request, stream_with_context, url_for
from psycopg2.extras import Json

import mailcore
from mailcore import MailError

bp = Blueprint("webmail", __name__)

COOKIE = "__Host-mr_mail" if os.getenv("MAILROOM_COOKIE_SECURE", "1") == "1" else "mr_mail"
IDLE_SECONDS = 30 * 60
MAX_SECONDS = 12 * 3600
PAGE_SIZE = 50
MAX_ATTACH = 20 * 1024 * 1024
CA_PATH = Path(os.getenv("MAILROOM_CA_CERT", "/etc/mailroom/tls/ca.crt"))


def app_module():
    import app as main  # отложенный импорт: app импортирует этот модуль
    return main


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ---------- сессия ----------

def load_session():
    token = request.cookies.get(COOKIE, "")
    if not token or len(token) > 100:
        return None
    main = app_module()
    now = int(time.time())
    with main.db() as con:
        row = con.one("""SELECT s.*, m.localpart, m.display_name, m.status AS m_status, m.quota_mb,
                                d.name AS domain_name, d.status AS d_status
                           FROM client_sessions s JOIN mailboxes m ON m.id = s.mailbox_id
                           JOIN domains d ON d.id = m.domain_id WHERE s.token_hash = %s""", (token_hash(token),))
        if not row:
            return None
        if (row["m_status"] != "active" or row["d_status"] != "active" or now - row["last_seen"] > IDLE_SECONDS
                or now - row["created_at"] > MAX_SECONDS):
            con.execute("DELETE FROM client_sessions WHERE token_hash = %s", (row["token_hash"],))
            return None
        if now - row["last_seen"] > 60:
            con.execute("UPDATE client_sessions SET last_seen = %s WHERE token_hash = %s", (now, row["token_hash"]))
    row = dict(row)
    row["address"] = f"{row['localpart']}@{row['domain_name']}"
    return row


def mail_auth(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        sess = load_session()
        if not sess:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Сессия завершена, войдите снова"}), 401
            return redirect(url_for("webmail.login_page"))
        if request.method not in ("GET", "HEAD"):
            supplied = request.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(sess["csrf"], supplied):
                return jsonify({"error": "Недействительный токен, обновите страницу"}), 403
        g.mail = sess
        return view(*args, **kwargs)
    return wrapped


def bad(message: str, status: int = 400):
    main = app_module()
    raise main.BadRequest(message, status)


def form_or_json() -> dict:
    if request.mimetype == "multipart/form-data":
        return request.form.to_dict()
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def folder_param(data=None) -> str:
    name = str((data or request.args).get("folder", "INBOX"))
    if not mailcore.valid_folder_name(name):
        bad("Недопустимое имя папки")
    return name


def uid_param(data=None) -> int:
    try:
        uid = int((data or request.args).get("uid", 0))
    except (TypeError, ValueError):
        uid = 0
    if uid <= 0:
        bad("Не указано письмо")
    return uid


# ---------- страницы ----------

@bp.get("/client/login")
@bp.get("/client")
def legacy_client():
    return redirect(url_for("webmail.index"))


@bp.get("/mail/login")
def login_page():
    if load_session():
        return redirect(url_for("webmail.index"))
    return render_template("mail_login.html")


@bp.get("/mail")
@mail_auth
def index():
    return render_template("mail.html")


@bp.get("/mail/ca.crt")
def ca_certificate():
    if not CA_PATH.exists():
        return Response("Сертификат CA не используется", status=404, mimetype="text/plain")
    return Response(CA_PATH.read_bytes(), mimetype="application/x-x509-ca-cert",
                    headers={"Content-Disposition": 'attachment; filename="mailroom-ca.crt"'})


# ---------- вход ----------

@bp.post("/api/mail/login")
def login():
    main = app_module()
    data = request.get_json(silent=True) or {}
    address = str(data.get("address", "")).strip().lower()[:254]
    password = str(data.get("password", ""))
    ip = main.client_ip()
    key = f"mail:{address}"
    error = jsonify({"error": "Неверный адрес или пароль. После 5 ошибок вход блокируется на 15 минут"}), 401
    if "@" not in address or not password or main.login_blocked(key, ip):
        main.record_login(key, ip, False)
        return error
    localpart, domain = address.rsplit("@", 1)
    with main.db() as con:
        box = con.one("""SELECT m.id, m.password_hash, m.status, d.status AS d_status
                           FROM mailboxes m JOIN domains d ON d.id = m.domain_id
                          WHERE m.localpart = %s AND d.name = %s""", (localpart, domain))
    if not box or box["status"] != "active" or box["d_status"] != "active" \
            or not main.mailbox_password_verify(password, box["password_hash"]):
        main.record_login(key, ip, False)
        main.audit("Неудачный вход в веб-почту", f"{address} с {ip}", "WARN", actor="")
        return error
    main.record_login(key, ip, True)
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    now = int(time.time())
    with main.db() as con:
        con.execute("DELETE FROM client_sessions WHERE last_seen < %s", (now - MAX_SECONDS,))
        con.execute("INSERT INTO client_sessions(token_hash, mailbox_id, csrf, created_at, last_seen, ip, user_agent) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (token_hash(token), box["id"], csrf, now, now, ip, request.user_agent.string[:200]))
        con.execute("UPDATE mailboxes SET last_login_at = %s WHERE id = %s", (main.now_iso(), box["id"]))
    main.audit("Вход в веб-почту", f"с {ip}", actor=address)
    response = jsonify({"status": "ok"})
    response.set_cookie(COOKIE, token, httponly=True, secure=COOKIE.startswith("__Host-"), samesite="Lax",
                        path="/", max_age=MAX_SECONDS)
    return response


@bp.post("/api/mail/logout")
def logout():
    token = request.cookies.get(COOKIE, "")
    if token:
        with app_module().db() as con:
            con.execute("DELETE FROM client_sessions WHERE token_hash = %s", (token_hash(token),))
    response = jsonify({"status": "ok"})
    response.delete_cookie(COOKIE, path="/", secure=COOKIE.startswith("__Host-"), samesite="Lax")
    return response


@bp.get("/api/mail/me")
@mail_auth
def me():
    main = app_module()
    s = g.mail
    with main.db() as con:
        prefs = con.one("SELECT signature FROM mailbox_prefs WHERE mailbox_id = %s", (s["mailbox_id"],))
        settings = main.get_settings(con)
    quota = None
    try:
        with mailcore.Mailbox(s["address"]) as box:
            quota = box.quota()
    except MailError:
        pass
    host = settings.get("hostname")
    return jsonify({
        "address": s["address"], "display_name": s["display_name"], "csrf": s["csrf"],
        "signature": prefs["signature"] if prefs else "", "quota": quota, "quota_mb": s["quota_mb"],
        "client": {"imap": f"{host}:993 (SSL/TLS)", "smtp": f"{host}:587 (STARTTLS) или :465 (SSL/TLS)",
                   "login": s["address"], "ca": CA_PATH.exists()},
        "limits": {"hour": int(settings["send_limit_hour"]), "message": int(settings["send_limit_message"]),
                   "attach_mb": MAX_ATTACH // 1024 // 1024},
    })


# ---------- мгновенные уведомления (IMAP IDLE → Server-Sent Events) ----------

def session_alive(token_digest: str) -> bool:
    """Проверка без продления: открытая вкладка не должна отменять автовыход по бездействию."""
    now = int(time.time())
    with app_module().db() as con:
        row = con.one("""SELECT s.last_seen, s.created_at, m.status, d.status AS d_status FROM client_sessions s
                           JOIN mailboxes m ON m.id = s.mailbox_id JOIN domains d ON d.id = m.domain_id
                          WHERE s.token_hash = %s""", (token_digest,))
    return bool(row and row["status"] == "active" and row["d_status"] == "active"
                and now - row["last_seen"] <= IDLE_SECONDS and now - row["created_at"] <= MAX_SECONDS)


@bp.get("/api/mail/events")
@mail_auth
def events():
    address, digest = g.mail["address"], g.mail["token_hash"]

    def stream():
        yield "retry: 5000\n\n"
        try:
            box = mailcore.Mailbox(address)
        except MailError:
            yield "event: unavailable\ndata: {}\n\n"
            return
        try:
            box.select("INBOX", readonly=True)
            deadline = time.time() + 600  # затем браузер переподключится сам
            while time.time() < deadline:
                changed = box.idle(25)
                if not session_alive(digest):
                    yield "event: logout\ndata: {}\n\n"
                    return
                yield "event: change\ndata: {}\n\n" if changed else ": ping\n\n"
        except (MailError, OSError):
            return
        finally:
            box.__exit__(None, None, None)

    return Response(stream_with_context(stream()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


# ---------- папки ----------

@bp.get("/api/mail/folders")
@mail_auth
def folders():
    with mailcore.Mailbox(g.mail["address"]) as box:
        return jsonify({"items": box.folders()})


@bp.post("/api/mail/folders")
@mail_auth
def folder_create():
    name = str((request.get_json(silent=True) or {}).get("name", "")).strip()
    if not mailcore.valid_folder_name(name) or name.upper() == "INBOX":
        bad("Недопустимое имя папки: без кавычек, \\, %, * и пустых частей")
    with mailcore.Mailbox(g.mail["address"]) as box:
        box.create_folder(name)
    return jsonify({"status": "created"})


def ensure_custom(box, name: str):
    for item in box.folders():
        if item["name"] == name:
            if item["system"]:
                bad("Системную папку нельзя переименовать или удалить")
            return
    bad("Папка не найдена", 404)


@bp.patch("/api/mail/folders")
@mail_auth
def folder_rename():
    data = request.get_json(silent=True) or {}
    old, new = str(data.get("name", "")), str(data.get("new_name", "")).strip()
    if not mailcore.valid_folder_name(new):
        bad("Недопустимое новое имя папки")
    with mailcore.Mailbox(g.mail["address"]) as box:
        ensure_custom(box, old)
        box.rename_folder(old, new)
    return jsonify({"status": "renamed"})


@bp.delete("/api/mail/folders")
@mail_auth
def folder_delete():
    name = str((request.get_json(silent=True) or {}).get("name", ""))
    with mailcore.Mailbox(g.mail["address"]) as box:
        ensure_custom(box, name)
        box.delete_folder(name)
    return jsonify({"status": "deleted"})


@bp.post("/api/mail/folders/empty")
@mail_auth
def folder_empty():
    name = folder_param(request.get_json(silent=True) or {})
    with mailcore.Mailbox(g.mail["address"]) as box:
        kinds = {f["name"]: f["special"] for f in box.folders()}
        if kinds.get(name) not in ("Trash", "Junk"):
            bad("Очищать можно только «Корзину» и «Спам»")
        box.select(name)
        uids = box.search()
        box.expunge(uids)
    return jsonify({"status": "emptied", "count": len(uids)})


# ---------- письма ----------

@bp.get("/api/mail/messages")
@mail_auth
def messages():
    folder = folder_param()
    page = max(1, int(request.args.get("page", 1) or 1))
    query = request.args.get("q", "").strip()[:200]
    field = request.args.get("field", "all")
    unseen, flagged = request.args.get("unseen") == "1", request.args.get("flagged") == "1"
    threaded = request.args.get("threads") == "1"
    with mailcore.Mailbox(g.mail["address"]) as box:
        box.select(folder, readonly=True)
        if threaded:
            groups = box.threads(query, field, unseen, flagged)
            total = len(groups)
            chunk = groups[(page - 1) * PAGE_SIZE: page * PAGE_SIZE]
            heads = {h["uid"]: h for h in box.headers([u for g in chunk for u in g])}
            items = []
            for group in chunk:
                members = [heads[u] for u in group if u in heads]
                if not members:
                    continue
                last = dict(members[-1])
                last["thread"] = group
                last["count"] = len(group)
                last["participants"] = list({a["email"]: a for m in members for a in m["from_"]}.values())
                last["thread_unseen"] = sum(1 for m in members if "\\Seen" not in m["flags"])
                last["has_attachments"] = any(m["has_attachments"] for m in members)
                last["flagged"] = any("\\Flagged" in m["flags"] for m in members)
                items.append(last)
        else:
            uids = box.search(query, field, unseen, flagged)
            total = len(uids)
            items = box.headers(uids[(page - 1) * PAGE_SIZE: page * PAGE_SIZE])
    for item in items:
        item["from"] = item.pop("from_")
    return jsonify({"items": items, "total": total, "page": page, "pages": max(1, -(-total // PAGE_SIZE)),
                    "threads": threaded})


REMOTE_IMG = re.compile(r"""(?:src|background)\s*=\s*["']?\s*(?:https?:)?//|url\(\s*["']?\s*(?:https?:)?//""", re.I)


@bp.get("/api/mail/message")
@mail_auth
def message():
    folder, uid = folder_param(), uid_param()
    with mailcore.Mailbox(g.mail["address"]) as box:
        box.select(folder)
        return jsonify(message_detail(box, folder, uid))


@bp.get("/api/mail/thread")
@mail_auth
def thread():
    folder = folder_param()
    try:
        uids = sorted({int(u) for u in request.args.get("uids", "").split(",") if u.strip()})[:100]
    except ValueError:
        uids = []
    if not uids:
        bad("Не указаны письма цепочки")
    with mailcore.Mailbox(g.mail["address"]) as box:
        box.select(folder)
        items = []
        for uid in uids:
            try:
                items.append(message_detail(box, folder, uid))
            except MailError:
                continue
    return jsonify({"items": items})


def message_detail(box, folder: str, uid: int) -> dict:
    msg = box.fetch(uid)
    box.flags([uid], "\\Seen", True)
    typ, data = box.conn.uid("FETCH", str(uid), "(FLAGS)")
    flags = re.search(rb"FLAGS \(([^)]*)\)", data[0] or b"") if typ == "OK" and data and data[0] else None
    parts = mailcore.message_parts(msg)
    for item in parts["attachments"]:
        item["preview"] = preview_kind(item["type"], item["filename"])
    return ({
        "uid": uid, "folder": folder,
        "subject": str(msg.get("Subject") or ""), "date": mailcore.iso_date(msg.get("Date")),
        "from": mailcore.address_list(msg.get("From")), "to": mailcore.address_list(msg.get("To")),
        "cc": mailcore.address_list(msg.get("Cc")), "reply_to": mailcore.address_list(msg.get("Reply-To")),
        "text": parts["text"], "has_html": parts["html"] is not None,
        "remote_images": bool(parts["html"] and REMOTE_IMG.search(parts["html"])),
        "attachments": parts["attachments"],
        "flags": flags.group(1).decode().split() if flags else [],
        "spam": str(msg.get("X-Spam") or "").lower() == "yes",
        "list_unsubscribe": str(msg.get("List-Unsubscribe") or "")[:500],
        "message_id": str(msg.get("Message-ID") or ""),
    })


FRAME_STYLE = ("body{font:15px/1.55 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;margin:14px;color:#17221f;"
               "background:#fff;overflow-wrap:anywhere}img{max-width:100%;height:auto}"
               "table{max-width:100%}pre{white-space:pre-wrap}a{color:#1d6b48}")


@bp.get("/api/mail/message/html")
@mail_auth
def message_html():
    folder, uid = folder_param(), uid_param()
    images = request.args.get("images") == "1"
    with mailcore.Mailbox(g.mail["address"]) as box:
        box.select(folder, readonly=True)
        msg = box.fetch(uid)
    parts = mailcore.message_parts(msg)
    body = parts["html"] or ""

    def inline_cid(match):
        index = parts["inline"].get(match.group(2))
        part = mailcore.walk_part(msg, index) if index is not None else None
        if not part:
            return match.group(1) + "data:,"
        data = part.get_payload(decode=True) or b""
        if len(data) > 3 * 1024 * 1024:
            return match.group(1) + "data:,"
        return f"{match.group(1)}data:{part.get_content_type()};base64,{base64.b64encode(data).decode()}"

    body = re.sub(r"""(src\s*=\s*["']?)cid:([^"'\s>]+)""", inline_cid, body, flags=re.I)
    document = ('<!doctype html><html><head><meta charset="utf-8"><meta name="referrer" content="no-referrer">'
                f'<base target="_blank"><style>{FRAME_STYLE}</style></head><body>{body}</body></html>')
    img = "data: https: http:" if images else "data:"
    csp = (f"default-src 'none'; style-src 'unsafe-inline'; img-src {img}; font-src data:; base-uri 'none'; "
           "form-action 'none'; frame-ancestors 'self'; sandbox allow-popups allow-popups-to-escape-sandbox")
    return Response(document, mimetype="text/html", headers={
        "Content-Security-Policy": csp, "X-Frame-Options": "SAMEORIGIN", "Referrer-Policy": "no-referrer",
        "Cache-Control": "private, no-store"})


@bp.get("/api/mail/message/raw")
@mail_auth
def message_raw():
    folder, uid = folder_param(), uid_param()
    with mailcore.Mailbox(g.mail["address"]) as box:
        box.select(folder, readonly=True)
        raw = box.fetch_raw(uid)
    return Response(raw, mimetype="text/plain", headers={"Content-Disposition": f'inline; filename="message-{uid}.eml"'})


def safe_filename(name: str) -> str:
    name = re.sub(r'[\x00-\x1f"\\/]', "_", name or "file").strip() or "file"
    return name[:150]


PREVIEW_TYPES = {"image/png": "image", "image/jpeg": "image", "image/gif": "image", "image/webp": "image",
                 "application/pdf": "pdf", "text/plain": "text", "text/csv": "text"}


def preview_kind(ctype: str, filename: str) -> str | None:
    """Что можно безопасно показать в браузере. SVG и HTML — только скачиванием (могут содержать скрипты)."""
    kind = PREVIEW_TYPES.get((ctype or "").lower())
    if kind:
        return kind
    ext = (filename or "").lower().rsplit(".", 1)[-1]
    return {"png": "image", "jpg": "image", "jpeg": "image", "gif": "image", "webp": "image", "pdf": "pdf",
            "txt": "text", "csv": "text", "log": "text"}.get(ext)


@bp.get("/api/mail/attachment")
@mail_auth
def attachment():
    folder, uid = folder_param(), uid_param()
    index = int(request.args.get("index", -1))
    with mailcore.Mailbox(g.mail["address"]) as box:
        box.select(folder, readonly=True)
        msg = box.fetch(uid)
    part = mailcore.walk_part(msg, index)
    if part is None or part.is_multipart():
        bad("Вложение не найдено", 404)
    name = safe_filename(part.get_filename() or f"attachment-{index}")
    data = part.get_payload(decode=True) or b""
    kind = preview_kind(part.get_content_type(), name) if request.args.get("inline") == "1" else None
    if kind:
        ext = name.lower().rsplit(".", 1)[-1]
        ctype = {"image": f"image/{'jpeg' if ext in ('jpg', 'jpeg') else ext if ext in ('png', 'gif', 'webp') else 'png'}",
                 "pdf": "application/pdf", "text": "text/plain; charset=utf-8"}[kind]
        if kind == "image" and part.get_content_type() in PREVIEW_TYPES:
            ctype = part.get_content_type()
        if kind == "text":
            charset = part.get_content_charset() or "utf-8"
            data = data.decode(charset, errors="replace").encode()
        headers = {"Content-Disposition": "inline", "X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-store",
                   "Content-Security-Policy": "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; "
                                              "frame-ancestors 'self'",
                   "X-Frame-Options": "SAMEORIGIN"}
        if kind == "pdf":
            headers["Content-Security-Policy"] = "frame-ancestors 'self'"
        return Response(data, mimetype=ctype, headers=headers)
    ascii_name = name.encode("ascii", "replace").decode().replace("?", "_")
    quoted = re.sub(r"[^A-Za-z0-9._-]", lambda m: "%%%02X" % ord(m.group()) if ord(m.group()) < 128 else
                    "".join("%%%02X" % b for b in m.group().encode()), name)
    return Response(data, mimetype="application/octet-stream", headers={
        "Content-Disposition": f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quoted}",
        "X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-store"})


@bp.post("/api/mail/messages/action")
@mail_auth
def message_action():
    data = request.get_json(silent=True) or {}
    folder = folder_param(data)
    try:
        uids = sorted({int(u) for u in data.get("uids", [])})[:1000]
    except (TypeError, ValueError):
        uids = []
    action = data.get("action")
    if not uids:
        bad("Не выбраны письма")
    with mailcore.Mailbox(g.mail["address"]) as box:
        special = {f["special"]: f["name"] for f in box.folders() if f["special"]}
        box.select(folder)
        if action in ("read", "unread"):
            box.flags(uids, "\\Seen", action == "read")
        elif action in ("flag", "unflag"):
            box.flags(uids, "\\Flagged", action == "flag")
        elif action == "delete":
            trash = special.get("Trash", "Trash")
            if folder == trash or data.get("permanent"):
                box.expunge(uids)
            else:
                box.move(uids, trash)
        elif action in ("spam", "notspam"):
            # Письма сначала читаем, затем перемещаем и обучаем Rspamd в фоне.
            raws = [box.fetch_raw(u) for u in uids[:50]]
            box.move(uids, special.get("Junk", "Junk") if action == "spam" else "INBOX")
            kind = "spam" if action == "spam" else "ham"
            threading.Thread(target=lambda: [mailcore.rspamd_learn(kind, r) for r in raws], daemon=True).start()
        elif action == "move":
            target = str(data.get("target", ""))
            if not mailcore.valid_folder_name(target) or target == folder:
                bad("Выберите другую папку")
            box.move(uids, target)
        else:
            bad("Неизвестное действие")
    return jsonify({"status": "ok"})


# ---------- написание ----------

def quote_text(msg) -> str:
    parts = mailcore.message_parts(msg)
    text = parts["text"]
    if text is None and parts["html"]:
        text = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", parts["html"], flags=re.S | re.I)
        text = re.sub(r"<br\s*/?>|</p>|</div>|</tr>", "\n", text, flags=re.I)
        text = htmllib.unescape(re.sub(r"<[^>]+>", "", text))
        text = re.sub(r"\n{3,}", "\n\n", text)
    return text or ""


def original_html(msg) -> str:
    """HTML исходного письма для редактора: очищенный, встроенные картинки cid → data:."""
    parts = mailcore.message_parts(msg)
    if not parts["html"]:
        return htmllib.escape(parts["text"] or "").replace("\n", "<br>")
    body = parts["html"]

    def inline(m):
        index = parts["inline"].get(m.group(1))
        part = mailcore.walk_part(msg, index) if index is not None else None
        data = (part.get_payload(decode=True) or b"") if part else b""
        if not part or len(data) > 3 * 1024 * 1024 or part.get_content_subtype() not in ("png", "jpeg", "gif", "webp"):
            return 'src=""'
        return f'src="data:image/{part.get_content_subtype()};base64,{base64.b64encode(data).decode()}"'

    body = re.sub(r"""src\s*=\s*["']?cid:([^"'\s>]+)["']?""", inline, body, flags=re.I)
    return mailcore.sanitize_html(body)


def human_date(value) -> str:
    try:
        from email.utils import parsedate_to_datetime
        return parsedate_to_datetime(str(value)).strftime("%d.%m.%Y %H:%M")
    except (TypeError, ValueError):
        return str(value or "")


def subject_with(prefix: str, subject: str) -> str:
    return subject if re.match(rf"^\s*{prefix}:", subject, re.I) else f"{prefix}: {subject}"


@bp.get("/api/mail/compose")
@mail_auth
def compose_source():
    """Заготовка ответа, пересылки или черновика."""
    folder, uid = folder_param(), uid_param()
    mode = request.args.get("mode", "reply")
    me = g.mail["address"]
    with mailcore.Mailbox(me) as box:
        box.select(folder, readonly=True)
        msg = box.fetch(uid)
    subject = str(msg.get("Subject") or "")
    sender = mailcore.address_list(msg.get("Reply-To")) or mailcore.address_list(msg.get("From"))
    # Для поля ввода — читаемые имена, без кодирования RFC 2047 (его сделает отправка).
    fmt = lambda lst: ", ".join(f'"{a["name"].replace(chr(34), "")}" <{a["email"]}>' if a["name"] else a["email"] for a in lst)
    result = {"mode": mode, "to": "", "cc": "", "subject": subject, "body": "", "attachments": [],
              "in_reply_to": "", "references": "", "source": {"folder": folder, "uid": uid}}
    if mode == "draft":
        has_html = mailcore.message_parts(msg)["html"] is not None
        result.update(to=str(msg.get("To") or ""), cc=str(msg.get("Cc") or ""), bcc=str(msg.get("Bcc") or ""),
                      body=quote_text(msg), body_html=original_html(msg) if has_html else "",
                      in_reply_to=str(msg.get("In-Reply-To") or ""),
                      references=str(msg.get("References") or ""),
                      attachments=mailcore.message_parts(msg)["attachments"])
        return jsonify(result)
    date = human_date(msg.get("Date"))
    who = fmt(mailcore.address_list(msg.get("From")))
    esc = lambda s: htmllib.escape(str(s or ""))
    if mode == "forward":
        header = (f"\n\n-------- Пересылаемое сообщение --------\nТема: {subject}\nДата: {date}\nОт: {who}\n"
                  f"Кому: {msg.get('To') or ''}\n\n")
        result.update(subject=subject_with("Fwd", subject), body=header + quote_text(msg),
                      body_html=(f"<p><br></p><p>-------- Пересылаемое сообщение --------<br>Тема: {esc(subject)}<br>"
                                 f"Дата: {esc(date)}<br>От: {esc(who)}<br>Кому: {esc(msg.get('To'))}</p>"
                                 f"<div>{original_html(msg)}</div>"),
                      attachments=mailcore.message_parts(msg)["attachments"])
        return jsonify(result)
    quoted = "\n".join("> " + line for line in quote_text(msg).splitlines())
    result["subject"] = subject_with("Re", subject)
    result["body"] = f"\n\n{date}, {who} пишет:\n{quoted}"
    result["body_html"] = f"<p><br></p><p>{esc(date)}, {esc(who)} пишет:</p><blockquote>{original_html(msg)}</blockquote>"
    result["to"] = fmt(sender)
    if mode == "replyall":
        others = [a for a in mailcore.address_list(msg.get("To")) + mailcore.address_list(msg.get("Cc"))
                  if a["email"].lower() != me and a["email"].lower() not in [s["email"].lower() for s in sender]]
        result["cc"] = fmt(others)
    msgid = str(msg.get("Message-ID") or "").strip()
    result["in_reply_to"] = msgid
    result["references"] = (str(msg.get("References") or "") + " " + msgid).strip()
    return jsonify(result)


def parse_recipients(value: str) -> list[tuple[str, str]]:
    main = app_module()
    result = []
    for name, addr in getaddresses([value or ""]):
        addr = addr.strip()
        if not addr:
            continue
        if not main.valid_email(addr):
            bad(f"Некорректный адрес: {addr}")
        result.append((name.strip(), addr))
    return result


def build_message(data: dict, files, me: dict, draft: bool = False):
    """→ (EmailMessage для отправки, список получателей, bytes для «Отправленных»/«Черновиков»)."""
    to = parse_recipients(data.get("to", ""))
    cc = parse_recipients(data.get("cc", ""))
    bcc = parse_recipients(data.get("bcc", ""))
    if not draft and not (to or cc or bcc):
        bad("Укажите хотя бы одного получателя")
    subject = str(data.get("subject", "")).replace("\r", " ").replace("\n", " ")[:300]
    body = str(data.get("body", ""))
    if len(body) > 2_000_000:
        bad("Слишком длинный текст письма")
    domain = me["address"].split("@")[1]
    msg = EmailMessage()
    msg["From"] = formataddr((me["display_name"], me["address"])) if me["display_name"] else me["address"]
    if to:
        msg["To"] = ", ".join(formataddr(x) for x in to)
    if cc:
        msg["Cc"] = ", ".join(formataddr(x) for x in cc)
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=domain)
    for header in ("in_reply_to", "references"):
        value = re.sub(r"[\r\n]+", " ", str(data.get(header, "")))[:2000].strip()
        if value and re.fullmatch(r"(<[^<>\s]+>\s*)+", value):
            msg["In-Reply-To" if header == "in_reply_to" else "References"] = value
    msg["User-Agent"] = "Mailroom Webmail"
    body_html = str(data.get("body_html", "") or "")
    related = []
    if body_html.strip():
        if len(body_html) > 15_000_000:
            bad("Слишком большое письмо")
        clean, related = mailcore.split_data_images(mailcore.sanitize_html(body_html))
        # Цитату оформляем так же, как почтовые клиенты (стили санитайзер не пропускает — добавляем свои).
        clean = clean.replace("<blockquote>", '<blockquote style="margin:0 0 0 .8ex;border-left:2px solid #ccc;padding-left:1ex">')
        msg.set_content(mailcore.html_to_text(clean))
        msg.add_alternative('<!doctype html><html><head><meta charset="utf-8"></head><body>'
                            '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.5">'
                            f"{clean}</div></body></html>", subtype="html")
        html_part = msg.get_payload()[1]
        for cid, subtype, image in related:
            html_part.add_related(image, maintype="image", subtype=subtype, cid=f"<{cid}>")
    else:
        msg.set_content(body)
    total = sum(len(image) for _cid, _sub, image in related)
    for file in files:
        data_bytes = file.read()
        total += len(data_bytes)
        if total > MAX_ATTACH:
            bad(f"Вложения больше {MAX_ATTACH // 1024 // 1024} МБ")
        ctype = (file.mimetype or "application/octet-stream").split("/", 1)
        if len(ctype) != 2:
            ctype = ["application", "octet-stream"]
        msg.add_attachment(data_bytes, maintype=ctype[0], subtype=ctype[1], filename=safe_filename(file.filename))
    source = data.get("source_folder"), data.get("source_uid")
    keep = [int(i) for i in str(data.get("keep_attachments", "")).split(",") if i.strip().isdigit()]
    if keep and source[0] and source[1]:
        with mailcore.Mailbox(me["address"]) as box:
            box.select(folder_param({"folder": source[0]}), readonly=True)
            original = box.fetch(uid_param({"uid": source[1]}))
        for index in keep:
            part = mailcore.walk_part(original, index)
            if part is None or part.is_multipart():
                continue
            payload = part.get_payload(decode=True) or b""
            total += len(payload)
            if total > MAX_ATTACH:
                bad(f"Вложения больше {MAX_ATTACH // 1024 // 1024} МБ")
            maintype, subtype = part.get_content_type().split("/", 1)
            msg.add_attachment(payload, maintype=maintype, subtype=subtype,
                               filename=safe_filename(part.get_filename() or f"attachment-{index}"))
    recipients = [a for _, a in to + cc + bcc]
    stored = EmailMessage()
    for key, value in msg.items():
        stored[key] = value
    copy = msg.as_bytes()
    if bcc:
        # В копии для себя сохраняем скрытых получателей, в отправляемом письме их нет.
        copy = f"Bcc: {', '.join(formataddr(x) for x in bcc)}\r\n".encode() + copy
    return msg, recipients, copy, to + cc + bcc


def remember_contacts(con, mailbox_id: int, people):
    now = int(time.time())
    for name, addr in people:
        con.execute("""INSERT INTO contacts(mailbox_id, email, name, uses, last_used) VALUES (%s,%s,%s,1,%s)
                       ON CONFLICT (mailbox_id, email) DO UPDATE SET uses = contacts.uses + 1, last_used = EXCLUDED.last_used,
                       name = CASE WHEN EXCLUDED.name <> '' THEN EXCLUDED.name ELSE contacts.name END""",
                    (mailbox_id, addr.lower(), name[:100], now))


@bp.post("/api/mail/send")
@mail_auth
def send():
    main = app_module()
    me = g.mail
    data = form_or_json()
    msg, recipients, copy, people = build_message(data, request.files.getlist("files"), me)
    with main.db() as con:
        settings = main.get_settings(con)
        per_message = int(settings["send_limit_message"])
        per_hour = int(settings["send_limit_hour"])
        if len(recipients) > per_message:
            bad(f"Не больше {per_message} получателей в одном письме")
        sent = con.one("SELECT COALESCE(SUM(recipients),0) AS n FROM send_log WHERE mailbox_id = %s AND created_at > %s",
                       (me["mailbox_id"], int(time.time()) - 3600))["n"]
        if sent + len(recipients) > per_hour:
            main.audit("Превышен лимит отправки", f"{sent} получателей за час", "WARN", actor=me["address"])
            bad(f"Лимит {per_hour} получателей в час исчерпан. Попробуйте позже", 429)
    try:
        with smtplib.SMTP(mailcore.SMTP_HOST, mailcore.SMTP_PORT, timeout=30) as smtp:
            refused = smtp.send_message(msg, from_addr=me["address"], to_addrs=recipients)
    except smtplib.SMTPRecipientsRefused as exc:
        bad("Сервер отклонил всех получателей: " + "; ".join(
            f"{a}: {c} {m.decode(errors='replace') if isinstance(m, bytes) else m}" for a, (c, m) in exc.recipients.items()))
    except (OSError, smtplib.SMTPException) as exc:
        raise MailError(f"Письмо не отправлено: {exc}")
    with main.db() as con:
        con.execute("INSERT INTO send_log(mailbox_id, recipients, created_at) VALUES (%s,%s,%s)",
                    (me["mailbox_id"], len(recipients), int(time.time())))
        remember_contacts(con, me["mailbox_id"], people)
    warnings = []
    with mailcore.Mailbox(me["address"]) as box:
        special = {f["special"]: f["name"] for f in box.folders() if f["special"]}
        try:
            box.append(special.get("Sent", "Sent"), copy, "(\\Seen)")
        except MailError:
            warnings.append("копия не сохранена в «Отправленных»")
        if data.get("reply_folder") and data.get("reply_uid"):
            try:
                box.select(folder_param({"folder": data["reply_folder"]}))
                box.flags([uid_param({"uid": data["reply_uid"]})], "\\Answered", True)
            except MailError:
                pass
        if data.get("draft_uid"):
            try:
                box.select(special.get("Drafts", "Drafts"))
                box.expunge([uid_param({"uid": data["draft_uid"]})])
            except MailError:
                pass
    return jsonify({"status": "sent", "refused": list(refused), "warnings": warnings})


@bp.post("/api/mail/draft")
@mail_auth
def save_draft():
    me = g.mail
    data = form_or_json()
    _msg, _rcpt, copy, _people = build_message(data, request.files.getlist("files"), me, draft=True)
    with mailcore.Mailbox(me["address"]) as box:
        drafts = next((f["name"] for f in box.folders() if f["special"] == "Drafts"), "Drafts")
        uid = box.append(drafts, copy, "(\\Seen \\Draft)")
        if data.get("draft_uid"):
            try:
                box.select(drafts)
                box.expunge([uid_param({"uid": data["draft_uid"]})])
            except MailError:
                pass
    return jsonify({"status": "saved", "uid": uid})


# ---------- контакты ----------

@bp.get("/api/mail/contacts")
@mail_auth
def contacts():
    q = request.args.get("q", "").strip().lower()[:100]
    with app_module().db() as con:
        if q:
            rows = con.all("SELECT id, email, name, uses FROM contacts WHERE mailbox_id = %s AND "
                           "(email ILIKE %s OR name ILIKE %s) ORDER BY uses DESC, last_used DESC LIMIT 10",
                           (g.mail["mailbox_id"], f"%{q}%", f"%{q}%"))
        else:
            rows = con.all("SELECT id, email, name, uses FROM contacts WHERE mailbox_id = %s ORDER BY name, email",
                           (g.mail["mailbox_id"],))
    return jsonify({"items": rows})


@bp.post("/api/mail/contacts")
@mail_auth
def contact_add():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    if not app_module().valid_email(email):
        bad("Некорректный адрес")
    with app_module().db() as con:
        con.execute("INSERT INTO contacts(mailbox_id, email, name, last_used) VALUES (%s,%s,%s,%s) "
                    "ON CONFLICT (mailbox_id, email) DO UPDATE SET name = EXCLUDED.name",
                    (g.mail["mailbox_id"], email, str(data.get("name", ""))[:100], int(time.time())))
    return jsonify({"status": "saved"})


@bp.delete("/api/mail/contacts/<int:contact_id>")
@mail_auth
def contact_delete(contact_id: int):
    with app_module().db() as con:
        con.execute("DELETE FROM contacts WHERE id = %s AND mailbox_id = %s", (contact_id, g.mail["mailbox_id"]))
    return jsonify({"status": "deleted"})


# ---------- настройки ----------

@bp.get("/api/mail/settings")
@mail_auth
def settings_get():
    with app_module().db() as con:
        prefs = con.one("SELECT signature, vacation, forward, filters FROM mailbox_prefs WHERE mailbox_id = %s",
                        (g.mail["mailbox_id"],))
        sessions = con.all("SELECT created_at, last_seen, ip, user_agent, token_hash = %s AS current FROM client_sessions "
                           "WHERE mailbox_id = %s ORDER BY last_seen DESC",
                           (token_hash(request.cookies.get(COOKIE, "")), g.mail["mailbox_id"]))
    prefs = dict(prefs) if prefs else {"signature": "", "vacation": {}, "forward": {}, "filters": []}
    return jsonify({**prefs, "display_name": g.mail["display_name"], "sessions": sessions})


DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


@bp.put("/api/mail/settings")
@mail_auth
def settings_put():
    main = app_module()
    me = g.mail
    data = request.get_json(silent=True) or {}
    vac = data.get("vacation") or {}
    fwd = data.get("forward") or {}
    vacation = {"enabled": bool(vac.get("enabled")), "subject": str(vac.get("subject", ""))[:200],
                "text": str(vac.get("text", ""))[:5000], "days": main.as_int(vac.get("days"), 7, 1, 30),
                "start": vac.get("start") if DATE_RE.fullmatch(str(vac.get("start", ""))) else "",
                "end": vac.get("end") if DATE_RE.fullmatch(str(vac.get("end", ""))) else ""}
    if vacation["enabled"] and not vacation["text"].strip():
        bad("Напишите текст автоответа")
    forward = {"enabled": bool(fwd.get("enabled")), "address": str(fwd.get("address", "")).strip().lower(),
               "keep": bool(fwd.get("keep", True))}
    if forward["enabled"]:
        if not main.valid_email(forward["address"]):
            bad("Укажите корректный адрес переадресации")
        if forward["address"] == me["address"]:
            bad("Нельзя переадресовывать почту на этот же ящик")
    filters = []
    for rule in (data.get("filters") or [])[:50]:
        field = rule.get("field") if rule.get("field") in ("from", "to", "subject") else None
        action = rule.get("action") if rule.get("action") in ("move", "read", "delete") else None
        value = str(rule.get("value", "")).strip()[:200]
        folder = str(rule.get("folder", "")).strip()
        if not field or not action or not value:
            bad("В каждом фильтре укажите поле, значение и действие")
        if action == "move" and not mailcore.valid_folder_name(folder):
            bad("В фильтре с перемещением выберите папку")
        filters.append({"field": field, "value": value, "action": action, "folder": folder if action == "move" else "",
                        "enabled": bool(rule.get("enabled", True))})
    prefs = {"vacation": vacation, "forward": forward, "filters": filters}
    script = mailcore.build_sieve(me["address"], prefs)
    with mailcore.Sieve(me["address"]) as sieve:
        if script:
            sieve.put_active("mailroom", script)
        else:
            sieve.deactivate()
    signature = str(data.get("signature", ""))[:2000]
    display_name = re.sub(r"[\r\n<>\"]", "", str(data.get("display_name", me["display_name"])))[:100].strip()
    with main.db() as con:
        old = con.one("SELECT forward FROM mailbox_prefs WHERE mailbox_id = %s", (me["mailbox_id"],))
        con.execute("""INSERT INTO mailbox_prefs(mailbox_id, signature, vacation, forward, filters, updated_at)
                       VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (mailbox_id) DO UPDATE SET signature = EXCLUDED.signature,
                       vacation = EXCLUDED.vacation, forward = EXCLUDED.forward, filters = EXCLUDED.filters,
                       updated_at = EXCLUDED.updated_at""",
                    (me["mailbox_id"], signature, Json(vacation), Json(forward), Json(filters), main.now_iso()))
        con.execute("UPDATE mailboxes SET display_name = %s WHERE id = %s", (display_name, me["mailbox_id"]))
    if (old["forward"] if old else {}) != forward:
        main.audit("Изменена переадресация", f"{'включена на ' + forward['address'] if forward['enabled'] else 'выключена'}",
                   "WARN", actor=me["address"])
    return jsonify({"status": "saved", "sieve": bool(script)})


@bp.post("/api/mail/password")
@mail_auth
def change_password():
    main = app_module()
    me = g.mail
    data = request.get_json(silent=True) or {}
    new = str(data.get("new_password", ""))
    if problem := main.password_problem(new, me["address"]):
        bad(problem)
    with main.db() as con:
        box = con.one("SELECT password_hash FROM mailboxes WHERE id = %s", (me["mailbox_id"],))
        if not main.mailbox_password_verify(str(data.get("current_password", "")), box["password_hash"]):
            bad("Текущий пароль указан неверно")
        con.execute("UPDATE mailboxes SET password_hash = %s, password_changed_at = %s WHERE id = %s",
                    (main.mailbox_password_hash(new), main.now_iso(), me["mailbox_id"]))
        con.execute("DELETE FROM client_sessions WHERE mailbox_id = %s AND token_hash <> %s",
                    (me["mailbox_id"], me["token_hash"]))
    main.audit("Пароль ящика изменён пользователем", "другие сессии завершены", actor=me["address"])
    return jsonify({"status": "changed"})
