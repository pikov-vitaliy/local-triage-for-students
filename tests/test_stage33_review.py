"""Этап 3.3: замечания второй контрольной проверки версии 0.3.2 (docs/state/review-stage-3.md).

Проверяется поведение:
* шаг обновления базы 6: решения «Согласен с агентом», подтверждённые шагом 4 версии 0.3.1 и затем только
  скопированные или отмеченные внесёнными в Hub, просят подтвердить заново (время подтверждения неизвестно);
* длина промпта по счёту модели сверяется у каждой попытки, в том числе повторной (разбор и «Спросить модель»);
* справочники: сбой большой подмены не оставляет занятым журнал WAL основной базы, следующая загрузка проходит без
  ручной очистки;
* образ ВМ: ключ SSH из guestinfo сверяется с ключом по сети (поддельные vmrun и ssh-keyscan), сборочные SSH-команды
  действительно строгие (ssh -G), файл секрета получает права только владельца ДО записи.
Сценарий доступа к ВМ по сети и состав базы образа – tests/test_stage32_review.py и tests/test_deploy_vm.py.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from app import ask
from app.ask import ask_question
from app.db import Database
from app.llm import OllamaClient
from app.models import ScaAnswer
from fake_ollama import FakeOllama, ask_answer, verdict_answer
from test_db_stage2 import load, sca
from test_stage32_review import COMPONENT, posix
from test_triage import Env, sast

ROOT = Path(__file__).resolve().parents[1]
VM = ROOT / "deploy" / "vm"
# описание шага 4 в журнале schema_version: версия 0.3.1 и версия 0.3.2 и новее
STEP4_031 = "Этап 3.1: в отпечаток ответа агента входят соответствия идентификаторов (AST → CVE)."
STEP5_032 = "Этап 3.2: шаг 4 версии 0.3.1 подтверждал решения «Согласен с агентом»."


# ============================================================================ шаг обновления базы 6

def _agreed_base(path: Path) -> tuple[int, ScaAnswer]:
    """База с решениями «Согласен с агентом» по текущему ответу с соответствиями AST → CVE (отпечаток – текущий)
    и одним решением по ответу без соответствий (другая библиотека)."""
    db = Database(path)
    try:
        pid = db.create_project("Проект")
        load(db, pid, [sca("1", vuln="AST-1"), sca("2", vuln="AST-2"), sca("3", component="other", vuln="AST-3")])
        mapped = ScaAnswer(component=COMPONENT, version="1.4.2", conclusion="update", recommended_version="1.4.9",
                           explanation="e", ids={"AST-1": ["CVE-2099-0001"]}, vulnerabilities=["AST-1", "AST-2"])
        plain = ScaAnswer(component="other", version="1.4.2", conclusion="update", recommended_version="1.4.9",
                          explanation="e", vulnerabilities=["AST-3"])
        db.save_sca_answers(pid, "Агент", [mapped, plain])
        for hub_id, answer in (("1", mapped), ("2", mapped), ("3", plain)):
            db.save_review(pid, hub_id, decision="agree", final_verdict="true_positive", final_comment="c",
                           reviewed=True, answer_sig=answer.signature())
        # после шага 4 человек только скопировал текст и отметил «Внесено в Hub»: updated_at – позже шага
        revision = db.get_review(pid, "2")["revision"]
        db.mark_copied(pid, "2", revision)
        db.mark_entered(pid, "2", revision=revision)
    finally:
        db.close()
    return pid, mapped


def test_new_database_has_no_step_4_and_keeps_decisions(tmp_path: Path):
    path = tmp_path / "triage.db"
    pid, mapped = _agreed_base(path)
    db = Database(path)  # повторное открытие новой базы: шагов нет
    try:
        assert [row["note"] for row in db.schema_log()] == ["новая база", "0002_feeds_and_secrets.sql", "0003_project_mask_display.sql",
                                                          "0004_package_identity.sql"]
        assert db.get_review(pid, "1")["answer_sig"] == mapped.signature()
    finally:
        db.close()


# ============================================================================ длина промпта у каждой попытки

@pytest.fixture
def env(tmp_path: Path, mask_key: bytes):
    fake = FakeOllama()
    environment = Env(tmp_path, fake, mask_key)
    environment.runner.start()
    yield environment
    environment.close()
    fake.close()


def test_triage_rejects_oversized_prompt_on_retry(env: Env):
    """Первый ответ не по формату (промпт в окне), повтор по формату, но по счёту модели промпт повтора длиннее
    окна: вердикт не принимается."""
    env.fake.answers += ["не JSON", ("reply", verdict_answer(), {"prompt_eval_count": 10**6})]
    env.load([sast("A", 15)])
    run = env.run()
    assert run["state"] == "done" and run["failed"] == 1
    item = env.db.recent_items(run["id"])[0]
    assert "не поместился в окно контекста" in item["error"] and "неполные" not in item["error"]
    assert env.db.get_case(env.project_id, "A")["verdict_id"] is None
    assert len(env.fake.chats()) == 2


def test_triage_oversized_first_attempt_is_not_retried(env: Env):
    env.fake.answers += [("reply", "не JSON", {"prompt_eval_count": 10**6})]
    env.load([sast("A", 15)])
    run = env.run()
    assert run["failed"] == 1 and len(env.fake.chats()) == 1  # повтор длиннее – его не отправляют


def test_ask_rejects_oversized_prompt_on_retry(env: Env):
    env.load([sast("A", 15)])
    assert env.run()["state"] == "done"
    env.fake.answers += ["не JSON", ("reply", ask_answer(), {"prompt_eval_count": 10**6})]
    q = ask_question(env.db, env.settings, OllamaClient(env.fake.url), env.runner._mask_key, env.project_id, "A",
                     "Откуда приходит id?", "qwen2.5-coder:14b")
    assert q["state"] == "error" and q["error"] == ask.PROMPT_DOUBT and q["answer"] == ""
    assert q["stats"]["attempts"] == 2 and not ask.busy()


# ============================================================================ образ ВМ: SSH и секреты

def _git_bash() -> str | None:
    if os.name != "nt":
        return shutil.which("bash")
    for candidate in (r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files (x86)\Git\bin\bash.exe"):
        if Path(candidate).is_file():
            return candidate
    return None


def _functions(*names: str) -> str:
    """Текст функций build.sh (однострочных и многострочных) по именам."""
    build = (VM / "build.sh").read_text(encoding="utf-8")
    parts = []
    for name in names:
        start = build.index(f"\n{name}() {{") + 1
        line_end = build.index("\n", start)
        end = line_end + 1 if build[start:line_end].rstrip().endswith("}") else build.index("\n}\n", start) + 3
        parts.append(build[start:end])
    return "".join(parts)


KEY_A = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKeyFromGuestinfoAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
KEY_B = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherMachineKeyBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"


@pytest.mark.parametrize("scanned, ok", [(KEY_A, True), (KEY_B, False), ("", False)])
def test_pin_hostkey_trusts_only_guestinfo_key(tmp_path: Path, scanned: str, ok: bool):
    """Ключ берётся из guestinfo (канал гипервизора); ключ по сети другой или его нет – отказ."""
    bash = _git_bash()
    if bash is None:
        pytest.skip("нет Git Bash")
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "vmrun").write_text(f'#!/bin/bash\n[ "$6" = triage.hostkey ] && echo "{KEY_A}"\nexit 0\n',
                                 encoding="utf-8", newline="\n")
    scan_line = f'echo "192.0.2.5 {scanned}"' if scanned else "true"
    (tools / "ssh-keyscan").write_text(f"#!/bin/bash\n{scan_line}\n", encoding="utf-8", newline="\n")
    known = tmp_path / "known_hosts"
    script = (f'BUILD="{posix(tmp_path)}"\nNAME=local-triage-demo\nVMRUN="{posix(tools / "vmrun")}"\n'
              f'PATH="{posix(tools)}:$PATH"\n'
              'w() { echo "$1"; }\ndie() { echo "ОТКАЗ: $*"; exit 1; }\n'
              + _functions("guestvar", "pin_hostkey")
              + f'pin_hostkey vm.vmx 192.0.2.5 "{posix(known)}" && echo ПРИНЯТ\n')
    r = subprocess.run([bash, "-c", script], capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=60)
    if ok:
        assert r.returncode == 0 and "ПРИНЯТ" in r.stdout, r.stdout + r.stderr
        assert known.read_text(encoding="utf-8").strip() == f"local-triage-demo {KEY_A}"
    else:
        assert r.returncode == 1 and "ОТКАЗ" in r.stdout and "ПРИНЯТ" not in r.stdout, r.stdout + r.stderr


def test_build_ssh_options_are_strict_for_ssh_client(tmp_path: Path):
    """Сборочные SSH-команды: настоящий ssh разбирает параметры ssh_opts как строгую проверку по отдельному
    known_hosts с именем ВМ (ssh -G печатает действующие настройки, не соединяясь)."""
    bash = _git_bash()
    if bash is None or not shutil.which("ssh"):
        pytest.skip("нет Git Bash или ssh")
    known = tmp_path / "known_hosts-build"
    script = ("NAME=local-triage-demo\n" + _functions("ssh_opts")
              + f'ssh -G $(ssh_opts "{posix(known)}") triage@192.0.2.5\n')
    r = subprocess.run([bash, "-c", script], capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=60)
    assert r.returncode == 0, r.stderr
    config = dict(line.split(" ", 1) for line in r.stdout.splitlines() if " " in line)
    assert config["stricthostkeychecking"] in ("true", "yes")
    assert config["userknownhostsfile"].strip() == posix(known)
    assert config["hostkeyalias"] == "local-triage-demo"


@pytest.mark.skipif(os.name != "nt", reason="ACL Windows")
def test_secret_is_restricted_before_it_is_written(tmp_path: Path, monkeypatch):
    """Права ограничиваются, пока файл пуст: в момент ограничения секрета в нём ещё нет."""
    sys.path.insert(0, str(VM))
    try:
        import secret_file
    finally:
        sys.path.remove(str(VM))
    seen = []
    real = secret_file.restrict

    def spy(path: str) -> None:
        # размер, а не содержимое: с этапа 3.4 файл до записи секрета не открывается повторно (совместный доступ
        # запрещён), поэтому прочитать его здесь нельзя
        seen.append(os.path.getsize(path))
        real(path)

    monkeypatch.setattr(secret_file, "restrict", spy)
    path = tmp_path / "triage-password"
    secret_file.write_secret(str(path), "пароль\n")
    assert seen == [0] and path.read_text(encoding="utf-8") == "пароль\n"
    entries = secret_file.acl_entries(str(path))
    assert len(entries) == 1 and secret_file._is_user(entries[0], secret_file._user())


@pytest.mark.skipif(os.name != "nt", reason="ACL Windows")
def test_restrict_removes_explicit_rights_of_others(tmp_path: Path):
    sys.path.insert(0, str(VM))
    try:
        import secret_file
    finally:
        sys.path.remove(str(VM))
    path = tmp_path / "known_hosts-build"
    path.write_text("old\n", encoding="utf-8")
    # явное разрешение другой группе (Пользователи, BUILTIN\Users) у существующего файла
    assert subprocess.run(["icacls", str(path), "/grant", "*S-1-5-32-545:R"], capture_output=True).returncode == 0
    assert len(secret_file.acl_entries(str(path))) > 1
    r = subprocess.run([sys.executable, str(VM / "secret_file.py"), "restrict", str(path)], capture_output=True)
    assert r.returncode == 0
    entries = secret_file.acl_entries(str(path))
    assert len(entries) == 1 and secret_file._is_user(entries[0], secret_file._user())
    assert path.read_text(encoding="utf-8") == "old\n"
