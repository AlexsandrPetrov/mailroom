"""Консольная утилита Mailroom. Запускается через /usr/local/sbin/mailroom (от root).

  mailroom users                     — пользователи панели
  mailroom passwd ЛОГИН              — задать пароль пользователю панели (все его сессии завершатся)
  mailroom disable-2fa ЛОГИН         — отключить 2FA (если потерян телефон)
  mailroom unban [IP|ЛОГИН|--all]    — снять блокировку входа после ошибок пароля
  mailroom mailbox-passwd АДРЕС      — сгенерировать новый пароль ящика
  mailroom check [--no-send]         — проверить сервер и отправить оповещения
  mailroom backup                    — создать резервную копию
  mailroom restore ФАЙЛ              — восстановить из копии
"""
import getpass
import os
import secrets
import sys

os.environ.setdefault("MAILROOM_SKIP_INIT", "1")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as mr  # noqa: E402


def die(text: str, code: int = 1):
    print(text, file=sys.stderr)
    sys.exit(code)


def user_row(con, login: str):
    row = con.one("SELECT * FROM users WHERE username = %s", (login.lower(),))
    if not row:
        die(f"Пользователь {login} не найден. Список: mailroom users")
    return row


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    cmd, args = argv[0], argv[1:]
    if cmd == "users":
        with mr.db() as con:
            for u in con.all("SELECT username, role, totp_enabled, last_login_at FROM users ORDER BY username"):
                print(f"{u['username']:20} {u['role']:10} 2FA={'да' if u['totp_enabled'] else 'нет':4} вход: {u['last_login_at'] or '—'}")
        return 0
    if cmd == "passwd" and len(args) == 1:
        first = getpass.getpass("Новый пароль (от 14 символов, пусто — сгенерировать): ")
        if first:
            if len(first) < 14:
                die("Пароль короче 14 символов")
            if getpass.getpass("Повторите: ") != first:
                die("Пароли не совпадают")
        password = first or secrets.token_urlsafe(18)
        with mr.db() as con:
            row = user_row(con, args[0])
            con.execute("UPDATE users SET password_hash = %s, session_version = session_version + 1 WHERE id = %s",
                        (mr.password_hash(password), row["id"]))
            con.execute("DELETE FROM login_attempts WHERE username = %s AND NOT success", (row["username"],))
        mr.audit("Пароль панели сменён из консоли", row["username"], "WARN", actor="console")
        if row["username"] == "admin":
            (mr.DATA_DIR / ".bootstrap-admin").unlink(missing_ok=True)
        print(f"Пароль {row['username']} изменён." + ("" if first else f" Новый пароль: {password}"))
        return 0
    if cmd == "disable-2fa" and len(args) == 1:
        with mr.db() as con:
            row = user_row(con, args[0])
            con.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = %s", (row["id"],))
        mr.audit("2FA отключена из консоли", row["username"], "WARN", actor="console")
        print(f"2FA для {row['username']} отключена. Включите её заново в разделе «Безопасность».")
        return 0
    if cmd == "unban":
        with mr.db() as con:
            if not args or args[0] == "--all":
                n = con.execute("DELETE FROM login_attempts WHERE NOT success").rowcount
            else:
                n = con.execute("DELETE FROM login_attempts WHERE NOT success AND (ip = %s OR username = %s OR username = %s)",
                                (args[0], args[0].lower(), f"mail:{args[0].lower()}")).rowcount
        print(f"Снято записей о неудачных входах: {n}")
        return 0
    if cmd == "mailbox-passwd" and len(args) == 1:
        address = args[0].strip().lower()
        if "@" not in address:
            die("Укажите полный адрес ящика")
        local, domain = address.split("@", 1)
        password = secrets.token_urlsafe(15)
        with mr.db() as con:
            row = con.one("SELECT m.id FROM mailboxes m JOIN domains d ON d.id = m.domain_id "
                          "WHERE m.localpart = %s AND d.name = %s", (local, domain))
            if not row:
                die("Ящик не найден")
            con.execute("UPDATE mailboxes SET password_hash = %s, password_changed_at = %s WHERE id = %s",
                        (mr.mailbox_password_hash(password), mr.now_iso(), row["id"]))
            con.execute("DELETE FROM client_sessions WHERE mailbox_id = %s", (row["id"],))
        mr.audit("Пароль ящика сброшен из консоли", address, "WARN", actor="console")
        print(f"Новый пароль {address}: {password}")
        return 0
    if cmd == "check":
        result = mr.run_alerts(send="--no-send" not in args)
        print(f"Проблем: {len(result['problems'])}; новых: {len(result['new'])}; решено: {len(result['resolved'])}")
        for key in result["problems"]:
            print("  -", key.replace("|", ": "))
        for line in result["sent"]:
            print("  отправлено:", line)
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
