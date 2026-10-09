"""Safe Debian/Ubuntu mail-gateway setup planner and executor.

The executor is intentionally opt-in. Without --apply it only reports the
commands that would be run. It refuses to apply on unsupported distributions
and never interpolates user input into a shell command.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
PROFILE_PATH = BASE_DIR / "setup_profile.json"


@dataclass
class Step:
    name: str
    command: list[str]
    destructive: bool = False
    result: str = "planned"
    output: str = ""


def load_profile() -> dict:
    return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))


def os_release() -> dict[str, str]:
    values = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key] = value.strip('"')
    except OSError as exc:
        values["ERROR"] = str(exc)
    return values


def build_steps(profile: dict) -> list[Step]:
    packages = profile["packages"]
    return [
        Step("Проверка ОС", ["cat", "/etc/os-release"]),
        Step("Обновление индекса пакетов", ["apt-get", "update"], True),
        Step("Установка компонентов почты", ["apt-get", "install", "-y", *packages], True),
        Step("Настройка имени узла", ["hostnamectl", "set-hostname", profile["hostname"]], True),
        Step("Проверка Postfix", ["postfix", "check"]),
        Step("Проверка конфигурации Dovecot", ["dovecot", "-n"]),
        Step("Проверка конфигурации Rspamd", ["rspamadm", "configtest"]),
        Step("Включение служб", ["systemctl", "enable", "--now", *profile["services"]], True),
        Step("Проверка слушающих портов", ["ss", "-ltn"]),
        Step("Итоговая проверка Postfix", ["postfix", "check"]),
    ]


def command_available(command: str) -> bool:
    return shutil.which(command) is not None


def run(profile: dict, apply: bool = False) -> dict:
    release = os_release()
    supported = release.get("ID") in profile["platforms"] or release.get("ID_LIKE", "").split() and any(item in release.get("ID_LIKE", "").split() for item in profile["platforms"])
    steps = build_steps(profile)
    if not supported:
        for step in steps:
            step.result = "blocked" if apply else "planned"
            step.output = "Неподдерживаемая ОС: нужен Debian 13 или Ubuntu"
        return {"mode": "apply" if apply else "dry-run", "supported": False, "release": release, "steps": [asdict(item) for item in steps]}
    if apply and os.geteuid() != 0:
        raise PermissionError("Для --apply нужен root. Запустите через sudo на Debian/Ubuntu.")
    for step in steps:
        if not apply:
            step.result = "planned"
            step.output = " ".join(step.command)
            continue
        if not command_available(step.command[0]):
            step.result = "failed"
            step.output = f"Команда не найдена: {step.command[0]}"
            break
        try:
            completed = subprocess.run(step.command, capture_output=True, text=True, timeout=300, check=False)
            step.result = "ok" if completed.returncode == 0 else "failed"
            step.output = (completed.stdout or completed.stderr).strip()[-4000:]
            if step.result == "failed":
                break
        except (OSError, subprocess.TimeoutExpired) as exc:
            step.result = "failed"
            step.output = str(exc)
            break
    return {"mode": "apply" if apply else "dry-run", "supported": True, "release": release, "steps": [asdict(item) for item in steps]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Mailroom Debian/Ubuntu setup runner")
    parser.add_argument("--apply", action="store_true", help="apply changes; requires root on Debian/Ubuntu")
    args = parser.parse_args()
    try:
        report = run(load_profile(), args.apply)
    except PermissionError as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, indent=2))
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if all(item["result"] not in {"failed", "blocked"} for item in report["steps"]) else 1


if __name__ == "__main__":
    sys.exit(main())
