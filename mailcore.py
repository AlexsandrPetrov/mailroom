"""Почтовые протоколы и проверки для Mailroom.

Здесь нет Flask: только IMAP (через мастер-пользователя Dovecot), ManageSieve,
сборка Sieve-скриптов, DKIM-ключи, DNS/TLS-проверки и разбор заголовков.
Внешние команды запускаются без shell, с фиксированным набором аргументов.
"""
from __future__ import annotations

import base64
import email
import email.policy
import imaplib
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from pathlib import Path

IMAP_HOST = os.getenv("MAILROOM_IMAP_HOST", "127.0.0.1")
IMAP_PORT = int(os.getenv("MAILROOM_IMAP_PORT", "143"))
SIEVE_PORT = int(os.getenv("MAILROOM_SIEVE_PORT", "4190"))
SMTP_HOST = os.getenv("MAILROOM_SMTP_HOST", "127.0.0.1")
SMTP_PORT = int(os.getenv("MAILROOM_SMTP_PORT", "25"))
MASTER_USER = os.getenv("MAILROOM_IMAP_MASTER_USER", "mailroom")
DKIM_DIR = Path(os.getenv("MAILROOM_DKIM_DIR", "/var/lib/mailroom/dkim"))
HELPER = os.getenv("MAILROOM_HELPER", "/usr/local/sbin/mailroom-helper")

SPECIAL_FOLDERS = ["INBOX", "Drafts", "Sent", "Junk", "Trash"]
FOLDER_TITLES = {"INBOX": "Входящие", "Sent": "Отправленные", "Drafts": "Черновики",
                 "Trash": "Корзина", "Junk": "Спам"}


class MailError(Exception):
    """Ошибка, текст которой можно показать пользователю."""


# ---------- внешние команды ----------

def run(command: list[str], timeout: int = 8, stdin: str | None = None) -> tuple[bool, str]:
    if not shutil.which(command[0]) and not os.path.exists(command[0]):
        return False, f"{command[0]} не установлен"
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                                check=False, input=stdin)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    return result.returncode == 0, (result.stdout or result.stderr).strip()


def helper(*args: str, stdin: str | None = None, timeout: int = 30) -> tuple[bool, str]:
    """Привилегированный помощник: sudo с белым списком подкоманд (deploy/mailroom-helper)."""
    return run(["sudo", "-n", HELPER, *args], timeout=timeout, stdin=stdin)


# ---------- IMAP modified UTF-7 (RFC 3501, 5.1.3) ----------

def utf7_encode(text: str) -> str:
    out, buf = [], []

    def flush():
        if buf:
            raw = "".join(buf).encode("utf-16-be")
            out.append("&" + base64.b64encode(raw).decode().rstrip("=").replace("/", ",") + "-")
            buf.clear()

    for ch in text:
        if 0x20 <= ord(ch) <= 0x7E:
            flush()
            out.append("&-" if ch == "&" else ch)
        else:
            buf.append(ch)
    flush()
    return "".join(out)


def utf7_decode(text: str) -> str:
    out, i = [], 0
    while i < len(text):
        if text[i] == "&":
            j = text.index("-", i)
            if j == i + 1:
                out.append("&")
            else:
                chunk = text[i + 1:j].replace(",", "/")
                out.append(base64.b64decode(chunk + "=" * (-len(chunk) % 4)).decode("utf-16-be"))
            i = j + 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def folder_arg(name: str) -> str:
    return quote(utf7_encode(name))


def valid_folder_name(name: str) -> bool:
    if not name or len(name) > 200 or name.strip() != name:
        return False
    if any(ch in name for ch in '"\\%*\r\n\t') or ord(min(name)) < 32:
        return False
    return all(part and part not in (".", "..") for part in name.split("/"))


# ---------- IMAP ----------

LIST_RE = re.compile(r'\((?P<flags>[^)]*)\) (?:"(?P<sep>[^"]*)"|NIL) (?P<name>.+)$')
FETCH_META_RE = re.compile(rb"UID (\d+)|FLAGS \(([^)]*)\)|RFC822\.SIZE (\d+)|INTERNALDATE \"([^\"]+)\"")


class Mailbox:
    """IMAP-сеанс конкретного ящика через мастер-пользователя. Использовать как контекст."""

    def __init__(self, address: str):
        password = os.getenv("MAILROOM_IMAP_MASTER_PASSWORD", "")
        if not password:
            raise MailError("Веб-почта не настроена: нет мастер-пароля IMAP")
        try:
            self.conn = imaplib.IMAP4(IMAP_HOST, IMAP_PORT, timeout=15)
            self.conn.login(f"{address}*{MASTER_USER}", password)
        except (OSError, imaplib.IMAP4.error) as exc:
            raise MailError("Почтовый сервер недоступен, попробуйте позже") from exc
        self.selected = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        try:
            if self.selected:
                self.conn.close()
            self.conn.logout()
        except (OSError, imaplib.IMAP4.error):
            pass

    def _ok(self, typ, data, message="Операция с почтой не выполнена"):
        if typ != "OK":
            detail = data[0].decode(errors="replace") if data and isinstance(data[0], bytes) else ""
            raise MailError(f"{message}: {detail}" if detail else message)
        return data

    # --- папки ---
    def folders(self) -> list[dict]:
        typ, data = self.conn.list()
        self._ok(typ, data)
        result = []
        for raw in data:
            if not isinstance(raw, bytes):
                continue
            match = LIST_RE.match(raw.decode(errors="replace"))
            if not match:
                continue
            flags = match.group("flags").split()
            name = match.group("name")
            if name.startswith('"'):
                name = name[1:-1].replace('\\"', '"').replace("\\\\", "\\")
            name = utf7_decode(name)
            if "\\Noselect" in flags or "\\NonExistent" in flags:
                continue
            special = next((f[1:] for f in flags if f in ("\\Sent", "\\Drafts", "\\Trash", "\\Junk")), None)
            if name == "INBOX":
                special = "INBOX"
            result.append({"name": name, "special": special})
        for item in result:
            typ, data = self.conn.status(folder_arg(item["name"]), "(MESSAGES UNSEEN)")
            text = data[0].decode(errors="replace") if typ == "OK" and data and data[0] else ""
            item["total"] = int(m.group(1)) if (m := re.search(r"MESSAGES (\d+)", text)) else 0
            item["unseen"] = int(m.group(1)) if (m := re.search(r"UNSEEN (\d+)", text)) else 0
            key = item["special"] if item["special"] in FOLDER_TITLES else item["name"]
            item["title"] = FOLDER_TITLES.get(key, item["name"].split("/")[-1])
            item["system"] = item["special"] is not None
        order = {name: i for i, name in enumerate(["INBOX", "Drafts", "Sent", "Junk", "Trash"])}
        result.sort(key=lambda f: (order.get(f["special"], 99), f["name"].lower()))
        return result

    def special_folder(self, kind: str) -> str:
        for item in self.folders():
            if item["special"] == kind:
                return item["name"]
        return kind

    def create_folder(self, name: str):
        self._ok(*self.conn.create(folder_arg(name)), "Не удалось создать папку")
        self.conn.subscribe(folder_arg(name))

    def rename_folder(self, old: str, new: str):
        self._ok(*self.conn.rename(folder_arg(old), folder_arg(new)), "Не удалось переименовать папку")
        self.conn.unsubscribe(folder_arg(old))
        self.conn.subscribe(folder_arg(new))

    def delete_folder(self, name: str):
        self._ok(*self.conn.delete(folder_arg(name)), "Не удалось удалить папку (возможно, в ней есть вложенные)")

    def select(self, folder: str, readonly: bool = False) -> int:
        typ, data = self.conn.select(folder_arg(folder), readonly=readonly)
        self._ok(typ, data, "Папка не найдена")
        self.selected = folder
        return int(data[0] or 0)

    # --- список писем ---
    def search(self, query: str = "", field: str = "all", unseen: bool = False, flagged: bool = False) -> list[int]:
        criteria = []
        if unseen:
            criteria.append("UNSEEN")
        if flagged:
            criteria.append("FLAGGED")
        key = {"from": "FROM", "subject": "SUBJECT", "body": "BODY", "to": "TO"}.get(field, "TEXT")
        if query:
            criteria.append(key)
            self.conn.literal = query.encode()
            typ, data = self.conn.uid("SORT", "(REVERSE ARRIVAL)", "UTF-8", *criteria)
        else:
            typ, data = self.conn.uid("SORT", "(REVERSE ARRIVAL)", "UTF-8", *(criteria or ["ALL"]))
        self._ok(typ, data, "Поиск не выполнен")
        return [int(x) for x in (data[0] or b"").split()]

    def headers(self, uids: list[int]) -> list[dict]:
        if not uids:
            return []
        fields = "FROM TO CC SUBJECT DATE CONTENT-TYPE"
        typ, data = self.conn.uid("FETCH", ",".join(map(str, uids)),
                                  f"(UID FLAGS RFC822.SIZE INTERNALDATE BODY.PEEK[HEADER.FIELDS ({fields})])")
        self._ok(typ, data)
        items = {}
        for part in data:
            if not isinstance(part, tuple):
                continue
            meta, raw = part
            info = {}
            for m in FETCH_META_RE.finditer(meta):
                if m.group(1):
                    info["uid"] = int(m.group(1))
                elif m.group(2) is not None:
                    info["flags"] = m.group(2).decode().split()
                elif m.group(3):
                    info["size"] = int(m.group(3))
                elif m.group(4):
                    info["internaldate"] = m.group(4).decode()
            msg = email.message_from_bytes(raw, policy=email.policy.default)
            ctype = (msg.get("Content-Type") or "").lower()
            info.update(
                from_=address_list(msg.get("From")),
                to=address_list(msg.get("To")),
                subject=str(msg.get("Subject") or ""),
                date=iso_date(msg.get("Date"), info.get("internaldate")),
                has_attachments=ctype.startswith("multipart/mixed"),
            )
            info.setdefault("flags", [])
            items[info["uid"]] = info
        return [items[u] for u in uids if u in items]

    # --- одно письмо ---
    def fetch_raw(self, uid: int) -> bytes:
        typ, data = self.conn.uid("FETCH", str(uid), "(BODY.PEEK[])")
        self._ok(typ, data)
        for part in data:
            if isinstance(part, tuple):
                return part[1]
        raise MailError("Письмо не найдено (возможно, уже удалено)")

    def fetch(self, uid: int):
        return email.message_from_bytes(self.fetch_raw(uid), policy=email.policy.default)

    def flags(self, uids: list[int], flag: str, on: bool):
        if uids:
            self._ok(*self.conn.uid("STORE", ",".join(map(str, uids)), "+FLAGS" if on else "-FLAGS", f"({flag})"))

    def move(self, uids: list[int], target: str):
        if uids:
            self._ok(*self.conn.uid("MOVE", ",".join(map(str, uids)), folder_arg(target)), "Не удалось переместить")

    def expunge(self, uids: list[int]):
        if uids:
            self.flags(uids, "\\Deleted", True)
            self._ok(*self.conn.uid("EXPUNGE", ",".join(map(str, uids))))

    def append(self, folder: str, raw: bytes, flags: str = "(\\Seen)") -> int | None:
        typ, data = self.conn.append(folder_arg(folder), flags, None, raw)
        self._ok(typ, data, "Не удалось сохранить письмо")
        m = re.search(rb"APPENDUID \d+ (\d+)", data[0] or b"")
        return int(m.group(1)) if m else None

    def idle(self, timeout: float = 25) -> bool:
        """IMAP IDLE на выбранной папке: True, если сервер сообщил об изменениях за timeout секунд."""
        import select
        tag = self.conn._new_tag().decode()
        self.conn.send(f"{tag} IDLE\r\n".encode())
        if not self.conn.readline().startswith(b"+"):
            raise MailError("Сервер не поддерживает IDLE")
        changed = False
        ready, _, _ = select.select([self.conn.sock], [], [], timeout)
        if ready:
            line = self.conn.readline()
            changed = line.startswith(b"*")
        self.conn.send(b"DONE\r\n")
        while True:
            line = self.conn.readline()
            if not line:
                raise MailError("Соединение с почтовым сервером разорвано")
            if line.startswith(b"*"):
                changed = True
            if line.startswith(tag.encode()):
                return changed

    def threads(self, query: str = "", field: str = "all", unseen: bool = False, flagged: bool = False) -> list[list[int]]:
        """Цепочки (THREAD REFERENCES): группы UID, новые сверху."""
        criteria = (["UNSEEN"] if unseen else []) + (["FLAGGED"] if flagged else [])
        if query:
            criteria.append({"from": "FROM", "subject": "SUBJECT", "body": "BODY", "to": "TO"}.get(field, "TEXT"))
            self.conn.literal = query.encode()
        typ, data = self.conn.uid("THREAD", "REFERENCES", "UTF-8", *(criteria or ["ALL"]))
        self._ok(typ, data, "Цепочки не построены")
        raw = (data[0] or b"").decode()
        groups, depth, current = [], 0, []
        for token in re.findall(r"\(|\)|\d+", raw):
            if token == "(":
                depth += 1
            elif token == ")":
                depth -= 1
                if depth == 0 and current:
                    groups.append(current)
                    current = []
            else:
                current.append(int(token))
        groups = [sorted(g) for g in groups]
        groups.sort(key=lambda g: -g[-1])
        return groups

    def quota(self) -> dict | None:
        typ, data = self.conn.getquotaroot("INBOX")
        if typ != "OK":
            return None
        for item in data:
            for line in item if isinstance(item, list) else [item]:
                text = line.decode(errors="replace") if isinstance(line, bytes) else str(line)
                m = re.search(r"STORAGE (\d+) (\d+)", text)
                if m:
                    return {"used_kb": int(m.group(1)), "limit_kb": int(m.group(2))}
        return None


def address_list(value) -> list[dict]:
    if not value:
        return []
    return [{"name": n, "email": e} for n, e in getaddresses([str(value)]) if e]


def iso_date(header, internaldate=None) -> str:
    try:
        if header:
            dt = parsedate_to_datetime(str(header))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
    except (TypeError, ValueError):
        pass
    if internaldate:
        try:
            return datetime.strptime(internaldate, "%d-%b-%Y %H:%M:%S %z").isoformat()
        except ValueError:
            pass
    return ""


def message_parts(msg) -> dict:
    """Текст, HTML и вложения письма. Номера вложений — индексы в walk()."""
    text_part = msg.get_body(preferencelist=("plain",))
    html_part = msg.get_body(preferencelist=("html",))
    attachments = []
    inline = {}
    for index, part in enumerate(msg.walk()):
        if part.is_multipart() or part in (text_part, html_part):
            continue
        cid = (part.get("Content-ID") or "").strip("<> ")
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if cid and disposition != "attachment" and part.get_content_maintype() == "image":
            inline[cid] = index
            if not filename:
                continue
        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append({"index": index, "filename": filename or f"attachment-{index}",
                                "type": part.get_content_type(), "size": len(payload)})
    return {
        "text": safe_content(text_part),
        "html": safe_content(html_part),
        "attachments": attachments,
        "inline": inline,
    }


def safe_content(part) -> str | None:
    if part is None:
        return None
    try:
        return part.get_content()
    except (LookupError, ValueError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def walk_part(msg, index: int):
    for i, part in enumerate(msg.walk()):
        if i == index:
            return part
    return None


# ---------- HTML писем, которые пишет пользователь ----------

from html.parser import HTMLParser
import html as _html

ALLOWED_TAGS = {"p", "br", "div", "span", "b", "strong", "i", "em", "u", "s", "strike", "ul", "ol", "li",
                "blockquote", "a", "img", "h1", "h2", "h3", "pre", "code", "hr", "sub", "sup"}
VOID_TAGS = {"br", "img", "hr"}
DATA_IMG = re.compile(r"data:image/(png|jpeg|gif|webp);base64,([A-Za-z0-9+/=\s]+)$")


class _Sanitizer(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out, self.stack, self.skip = [], [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "iframe", "object", "embed", "head", "title", "svg", "math"):
            self.skip += 1
            return
        if self.skip or tag not in ALLOWED_TAGS:
            return
        keep = []
        for name, value in attrs:
            value = (value or "").strip()
            if tag == "a" and name == "href" and re.match(r"(https?:|mailto:)", value, re.I):
                keep.append(f'href="{_html.escape(value, quote=True)}"')
            elif tag == "img" and name == "src" and (DATA_IMG.match(value) or value.startswith("cid:")):
                keep.append(f'src="{_html.escape(value, quote=True)}"')
            elif tag == "img" and name == "alt":
                keep.append(f'alt="{_html.escape(value, quote=True)}"')
        if tag == "img" and not any(k.startswith("src=") for k in keep):
            return
        if tag == "a":
            keep.append('rel="noopener noreferrer"')
        self.out.append(f"<{tag}{(' ' + ' '.join(keep)) if keep else ''}>")
        if tag not in VOID_TAGS:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in ("script", "style", "iframe", "object", "embed", "head", "title", "svg", "math"):
            self.skip = max(0, self.skip - 1)
            return
        if self.skip or tag not in self.stack:
            return
        while self.stack:
            top = self.stack.pop()
            self.out.append(f"</{top}>")
            if top == tag:
                break

    def handle_data(self, data):
        if not self.skip:
            self.out.append(_html.escape(data, quote=False))

    def result(self):
        while self.stack:
            self.out.append(f"</{self.stack.pop()}>")
        return "".join(self.out)


def sanitize_html(text: str) -> str:
    parser = _Sanitizer()
    parser.feed(text or "")
    parser.close()
    return parser.result()


def html_to_text(text: str) -> str:
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", text or "", flags=re.S | re.I)
    text = re.sub(r"<li[^>]*>", "\n• ", text, flags=re.I)
    text = re.sub(r'<a [^>]*href="([^"]+)"[^>]*>(.*?)</a>', lambda m: m.group(2) if m.group(1) in m.group(2)
                  else f"{m.group(2)} ({m.group(1)})", text, flags=re.I | re.S)
    text = re.sub(r"<blockquote[^>]*>(.*?)</blockquote>",
                  lambda m: "\n" + "\n".join("> " + l for l in html_to_text(m.group(1)).splitlines()) + "\n",
                  text, flags=re.I | re.S)
    text = re.sub(r"<br\s*/?>|</p>|</div>|</h[1-3]>|</tr>|</ul>|</ol>|<hr[^>]*>", "\n", text, flags=re.I)
    text = _html.unescape(re.sub(r"<[^>]+>", "", text))
    return re.sub(r"\n{3,}", "\n\n", text).strip() + "\n"


def split_data_images(text: str) -> tuple[str, list[tuple[str, str, bytes]]]:
    """Картинки data: из редактора → вложения cid. → (html, [(cid, subtype, bytes)])"""
    images = []

    def repl(m):
        found = DATA_IMG.match(_html.unescape(m.group(1)))
        if not found:
            return m.group(0)
        data = base64.b64decode(found.group(2))
        cid = f"img{len(images) + 1}.{secrets_hex()}@mailroom"
        images.append((cid, found.group(1), data))
        return f'src="cid:{cid}"'

    return re.sub(r'src="(data:image/[^"]+)"', repl, text), images


def secrets_hex() -> str:
    import secrets
    return secrets.token_hex(6)


# ---------- ManageSieve ----------

class Sieve:
    def __init__(self, address: str):
        password = os.getenv("MAILROOM_IMAP_MASTER_PASSWORD", "")
        try:
            self.sock = socket.create_connection((IMAP_HOST, SIEVE_PORT), timeout=10)
        except OSError as exc:
            raise MailError("Сервис фильтров недоступен") from exc
        self.file = self.sock.makefile("rb")
        self._response()
        token = base64.b64encode(f"{address}\0{MASTER_USER}\0{password}".encode()).decode()
        self._command(f'AUTHENTICATE "PLAIN" "{token}"')

    def _response(self) -> list[str]:
        lines = []
        while True:
            line = self.file.readline()
            if not line:
                raise MailError("Сервис фильтров разорвал соединение")
            text = line.decode(errors="replace").rstrip("\r\n")
            if m := re.search(r"\{(\d+)\+?\}$", text):
                text += self.file.read(int(m.group(1))).decode(errors="replace")
                self.file.readline()
            if text.startswith(("OK", "NO", "BYE")):
                if not text.startswith("OK"):
                    raise MailError("Ошибка фильтров: " + text.split(" ", 1)[-1].strip('"'))
                return lines
            lines.append(text)

    def _command(self, line: str, literal: bytes | None = None) -> list[str]:
        data = line.encode()
        if literal is not None:
            data += b" {%d+}\r\n" % len(literal) + literal
        self.sock.sendall(data + b"\r\n")
        return self._response()

    def put_active(self, name: str, script: str):
        body = script.encode()
        self._command(f'CHECKSCRIPT', literal=body)
        self._command(f"PUTSCRIPT {quote(name)}", literal=body)
        self._command(f"SETACTIVE {quote(name)}")

    def deactivate(self):
        self._command('SETACTIVE ""')

    def close(self):
        try:
            self.sock.sendall(b"LOGOUT\r\n")
            self.sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def sieve_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_sieve(address: str, prefs: dict) -> str | None:
    """Один скрипт из автоответа, переадресации и фильтров. None — ничего не включено."""
    vacation = prefs.get("vacation") or {}
    forward = prefs.get("forward") or {}
    filters = [f for f in (prefs.get("filters") or []) if f.get("enabled", True)]
    if not vacation.get("enabled") and not forward.get("enabled") and not filters:
        return None
    lines = ['require ["fileinto", "mailbox", "vacation", "copy", "date", "relational", "imap4flags"];',
             f"# Создано Mailroom для {address}. Изменения вручную будут перезаписаны."]
    if vacation.get("enabled"):
        conds = ['not header :contains "X-Spam" "Yes"', 'not exists "List-Id"',
                 'not header :contains "Precedence" ["bulk", "list", "junk"]']
        if vacation.get("start"):
            conds.append(f'currentdate :value "ge" "date" {sieve_string(vacation["start"])}')
        if vacation.get("end"):
            conds.append(f'currentdate :value "le" "date" {sieve_string(vacation["end"])}')
        days = max(1, min(int(vacation.get("days") or 7), 30))
        lines += [f"if allof ({', '.join(conds)}) {{",
                  f"  vacation :days {days} :subject {sieve_string(vacation.get('subject') or 'Автоответ')}"
                  f" :from {sieve_string(address)} {sieve_string(vacation.get('text') or '')};",
                  "}"]
    if forward.get("enabled") and forward.get("address"):
        copy = ":copy " if forward.get("keep", True) else ""
        lines.append(f"redirect {copy}{sieve_string(forward['address'])};")
    header_names = {"from": '"from"', "to": '["to", "cc"]', "subject": '"subject"'}
    for rule in filters:
        field = header_names.get(rule.get("field"), '"subject"')
        test = f"header :contains {field} {sieve_string(rule.get('value', ''))}"
        action = rule.get("action")
        if action == "move" and rule.get("folder"):
            # В Sieve имена папок в UTF-8 (RFC 5228), не в IMAP UTF-7.
            body = f"fileinto :create {sieve_string(rule['folder'])}; stop;"
        elif action == "read":
            body = 'addflag "\\\\Seen";'
        elif action == "delete":
            body = "discard; stop;"
        else:
            continue
        lines.append(f"if {test} {{ {body} }}")
    return "\n".join(lines) + "\n"


# ---------- DKIM ----------

def dkim_generate(domain: str, selector: str, bits: int = 2048) -> str:
    """Создаёт закрытый ключ для Rspamd и возвращает значение TXT-записи."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    DKIM_DIR.mkdir(parents=True, exist_ok=True)
    path = DKIM_DIR / f"{domain}.{selector}.key"
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    os.chmod(tmp, 0o640)
    tmp.replace(path)
    der = key.public_key().public_bytes(serialization.Encoding.DER,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode()


def dkim_remove(domain: str, selector: str):
    try:
        (DKIM_DIR / f"{domain}.{selector}.key").unlink()
    except FileNotFoundError:
        pass


def dkim_write_selectors(active: dict[str, str]):
    """selectors.map для Rspamd: «домен селектор». Rspamd перечитывает карту сам."""
    DKIM_DIR.mkdir(parents=True, exist_ok=True)
    tmp = DKIM_DIR / "selectors.map.tmp"
    tmp.write_text("".join(f"{d} {s}\n" for d, s in sorted(active.items())), encoding="utf-8")
    os.chmod(tmp, 0o640)
    tmp.replace(DKIM_DIR / "selectors.map")


# ---------- DNS ----------

def dig(name: str, rtype: str) -> list[str]:
    ok, out = run(["dig", "+short", "+time=3", "+tries=1", name, rtype], timeout=8)
    if not ok:
        return []
    values = [line.strip() for line in out.splitlines() if line.strip() and not line.startswith(";")]
    if rtype == "TXT":
        values = ["".join(re.findall(r'"((?:[^"\\]|\\.)*)"', v)) or v for v in values]
    return values


def txt_records(name: str, prefix: str) -> list[str]:
    return [v for v in dig(name, "TXT") if v.lower().startswith(prefix.lower())]


def reverse_name(ip: str) -> str:
    return ipaddress.ip_address(ip).reverse_pointer


def parse_tags(record: str) -> dict:
    tags = {}
    for item in record.split(";"):
        key, sep, value = item.strip().partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    return tags


DNSBL = [
    ("zen.spamhaus.org", "Spamhaus ZEN"),
    ("bl.spamcop.net", "SpamCop"),
    ("b.barracudacentral.org", "Barracuda"),
    ("psbl.surriel.com", "PSBL"),
]


def dnsbl_check(ip: str) -> list[dict]:
    addr = ipaddress.ip_address(ip)
    if addr.is_private or addr.is_loopback:
        return [{"list": title, "status": "skip", "detail": "частный адрес — проверка не имеет смысла"}
                for _, title in DNSBL]
    rev = ".".join(reversed(ip.split(".")))
    result = []
    for zone, title in DNSBL:
        answer = dig(f"{rev}.{zone}", "A")
        if not answer:
            result.append({"list": title, "status": "ok", "detail": "не в списке"})
        elif any(a.startswith("127.255.255.") for a in answer):
            result.append({"list": title, "status": "skip",
                           "detail": "список отказал резолверу (публичный DNS); нужен свой резолвер"})
        else:
            result.append({"list": title, "status": "fail", "detail": "в списке: " + ", ".join(answer)})
    return result


# ---------- TLS ----------

def tls_check(host: str, port: int) -> dict:
    """Сертификат сервера и доверие к нему из системного хранилища CA."""
    from cryptography import x509

    raw_ctx = ssl.create_default_context()
    raw_ctx.check_hostname = False
    raw_ctx.verify_mode = ssl.CERT_NONE

    def fetch(ctx):
        sock = socket.create_connection((host, port), timeout=8)
        try:
            if port in (25, 587):
                file = sock.makefile("rb")
                file.readline()
                sock.sendall(b"EHLO mailroom.check\r\n")
                while (line := file.readline()) and line[3:4] == b"-":
                    pass
                sock.sendall(b"STARTTLS\r\n")
                if not file.readline().startswith(b"220"):
                    raise ssl.SSLError("сервер не поддерживает STARTTLS")
            elif port == 143:
                file = sock.makefile("rb")
                file.readline()
                sock.sendall(b"a STARTTLS\r\n")
                file.readline()
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert(binary_form=True), tls.version()
        finally:
            sock.close()

    try:
        der, version = fetch(raw_ctx)
    except (OSError, ssl.SSLError) as exc:
        return {"ok": False, "error": str(exc)}
    cert = x509.load_der_x509_certificate(der)
    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san = [str(v) for v in names.get_values_for_type(x509.DNSName)] + \
              [str(v) for v in names.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        san = []
    not_after = cert.not_valid_after_utc
    trusted, trust_error = True, ""
    try:
        fetch(ssl.create_default_context())
    except ssl.SSLCertVerificationError as exc:
        trusted, trust_error = False, exc.verify_message or str(exc)
    except (OSError, ssl.SSLError) as exc:
        trusted, trust_error = False, str(exc)
    return {
        "ok": True, "version": version, "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(), "san": san,
        "not_after": not_after.isoformat(),
        "days_left": (not_after - datetime.now(timezone.utc)).days,
        "self_signed": cert.issuer == cert.subject,
        "trusted": trusted, "trust_error": trust_error,
    }


# ---------- Разбор заголовков ----------

def analyze_headers(text: str) -> dict:
    msg = email.message_from_string(text.replace("\r\n", "\n").lstrip(), policy=email.policy.default)
    results = []
    for value in msg.get_all("Authentication-Results") or []:
        server, _, rest = str(value).partition(";")
        for method in ("spf", "dkim", "dmarc", "arc"):
            for m in re.finditer(rf"\b{method}=(\w+)([^;]*)", rest, re.I):
                results.append({"server": server.strip(), "method": method.upper(),
                                "result": m.group(1).lower(), "detail": m.group(2).strip()[:200]})
    hops = []
    for value in reversed(msg.get_all("Received") or []):
        text_value = " ".join(str(value).split())
        stamp = text_value.rsplit(";", 1)[-1].strip() if ";" in text_value else ""
        when = iso_date(stamp)
        hops.append({"text": text_value[:300], "date": when})
    prev = None
    for hop in hops:
        if hop["date"] and prev:
            hop["delay_s"] = int((datetime.fromisoformat(hop["date"]) - datetime.fromisoformat(prev)).total_seconds())
        prev = hop["date"] or prev
    dkim = []
    for value in msg.get_all("DKIM-Signature") or []:
        tags = parse_tags(" ".join(str(value).split()))
        dkim.append({"domain": tags.get("d", ""), "selector": tags.get("s", ""), "algorithm": tags.get("a", "")})
    spam = {k: str(msg.get(k)) for k in ("X-Spam", "X-Spam-Status", "X-Spamd-Result", "X-Rspamd-Action",
                                         "X-Spam-Flag", "X-Rspamd-Score") if msg.get(k)}
    from_addr = parseaddr(str(msg.get("From") or ""))[1]
    return {
        "from": str(msg.get("From") or ""), "from_domain": from_addr.rpartition("@")[2].lower(),
        "return_path": str(msg.get("Return-Path") or ""), "subject": str(msg.get("Subject") or ""),
        "message_id": str(msg.get("Message-ID") or ""), "auth_results": results,
        "dkim_signatures": dkim, "hops": hops, "spam": spam,
    }


def rspamd_learn(kind: str, raw: bytes) -> bool:
    """Обучить байесовский фильтр Rspamd: kind = spam | ham. Контроллер доверяет 127.0.0.1."""
    import urllib.request
    try:
        req = urllib.request.Request(f"http://127.0.0.1:11334/learn{kind}", data=raw, method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status in (200, 204, 208)
    except OSError as exc:
        # 208 — уже обучено на этом письме; urllib считает его ошибкой только при 4xx/5xx
        return getattr(exc, "code", 0) == 208


def postqueue_json() -> list[dict]:
    ok, out = run(["postqueue", "-j"], timeout=10)
    if not ok:
        raise MailError(out or "postqueue недоступен")
    items = []
    for line in out.splitlines():
        try:
            items.append(json.loads(line))
        except ValueError:
            continue
    return items
