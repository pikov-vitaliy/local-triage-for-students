"""Итоговая проверка 0.10.0: start.ps1 не запускает приложение не на той базе.

Основная база лежит в томе Docker, а следы прежней жизни установки – в папке данных и в копиях рядом с ней. Том можно утратить
(docker compose down -v, сброс данных Docker Desktop): раньше запуск молча создавал пустую базу. Инструменты переноса из SQLite и
возврата удалены в 0.10.0.dev8: база прежней версии рядом с пустой базой – отказ без переноса, список отменённых баз не читается.
Сценарий подключается через «.» – Docker не трогается."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHELLS = [shell for shell in (shutil.which("powershell"), shutil.which("pwsh")) if shell]
MARK = "pgdata-after-rollback.txt"


def in_data(folder: Path, name: str) -> Path:
    (folder / "data").mkdir(exist_ok=True)
    return folder / "data" / name


def blocker(shell: str, state: str, data: Path, new_database: bool = False) -> str:
    # копии – рядом с папкой данных (ADR-0133): data здесь – папка приложения
    (data / "data").mkdir(exist_ok=True)
    command = (f". '{ROOT / 'start.ps1'}'; [Console]::OutputEncoding = [Text.Encoding]::UTF8; "
               f"Write-Output ('ANSWER=' + (Get-StartBlocker '{state}' '{data / 'data'}' ${str(new_database).lower()}))")
    out = subprocess.run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                         capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert out.returncode == 0, out.stderr
    return out.stdout.split("ANSWER=", 1)[1].strip()


@pytest.mark.parametrize("shell", SHELLS)
def test_new_installation_and_working_base_start(shell: str, tmp_path: Path):
    assert blocker(shell, "empty", tmp_path) == "", "новая установка: пустая база и пустая папка данных"
    (tmp_path / "backups").mkdir()
    (tmp_path / "backups" / "triage-20261105-094958.dump").write_bytes(b"x")
    in_data(tmp_path, "triage.db.sqlite-0.9.26").write_bytes(b"x")
    in_data(tmp_path, "triage.db").write_bytes(b"x")
    assert blocker(shell, "ok", tmp_path) == "", "рабочая база: копии и база прежней версии рядом запуску не мешают"
    assert blocker(shell, "migrate", tmp_path) == ""


@pytest.mark.parametrize("shell", SHELLS)
def test_empty_base_beside_old_sqlite_is_refused_without_transfer(shell: str, tmp_path: Path):
    """Сборка базу прежней версии не переносит: отказ называет сборку, выполнявшую перенос, и оба выхода – восстановить копию или
    явно начать с пустой базы."""
    in_data(tmp_path, "triage.db").write_bytes(b"x")
    answer = blocker(shell, "empty", tmp_path).replace("\n", " ")
    assert "базу прежней версии не переносит" in answer and "0.10.0.dev7" in answer
    assert "restore-db.ps1 -Dump <файл из backups> -Confirm" in answer and ".\\start.ps1 -NewDatabase" in answer
    assert "Приложение не запущено" in answer
    assert "сначала перенос" not in answer and "Переход на 0.10.0" not in answer
    assert blocker(shell, "empty", tmp_path, new_database=True) == "", "явное решение начать с пустой базы"


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("trace", ["dump", "sqlite"])
def test_lost_volume_is_not_replaced_by_empty_base(shell: str, tmp_path: Path, trace: str):
    """После перехода база прежней версии переименована, копии лежат в backups: пустая база рядом с ними – утраченный том."""
    if trace == "dump":
        (tmp_path / "backups").mkdir()
        (tmp_path / "backups" / "triage-20261105-094958.dump").write_bytes(b"x")
        (tmp_path / "backups" / "triage-20261105-094958.dump.json").write_text("{}", encoding="utf-8")
    else:
        in_data(tmp_path, "triage.db.sqlite-0.9.26").write_bytes(b"x")
    answer = blocker(shell, "empty", tmp_path)
    assert "том базы утрачен" in answer.replace("\n", " ") and "restore-db.ps1" in answer and "-NewDatabase" in answer
    assert blocker(shell, "empty", tmp_path, new_database=True) == "", "явное решение начать с пустой базы"


@pytest.mark.parametrize("shell", SHELLS)
def test_sidecar_alone_is_not_a_copy(shell: str, tmp_path: Path):
    (tmp_path / "backups").mkdir()
    (tmp_path / "backups" / "triage-20261105-094958.dump.json").write_text("{}", encoding="utf-8")
    (tmp_path / "backups" / "backup-task.log").write_text("x", encoding="utf-8")
    assert blocker(shell, "empty", tmp_path) == ""


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("state", ["ok", "migrate", "empty"])
@pytest.mark.parametrize("place", ["backups", "data"])
def test_list_of_cancelled_bases_left_by_rollback_is_not_read(shell: str, tmp_path: Path, state: str, place: str):
    """0.10.0.dev8: возврата комплектом больше нет. Список отменённых баз, оставшийся от него в backups или в папке данных, запуску
    не мешает и сценарием не меняется."""
    (tmp_path / place).mkdir(exist_ok=True)
    file = tmp_path / place / MARK
    text = "Возврат комплектом backup-before-0.10.0-20261105-093549 начат.\r\nbaseline=0f3a9c1e5b7d2468ace0135792468bdf\r\nbaseline=unknown\r\n"
    file.write_bytes(text.encode("utf-8"))
    assert blocker(shell, state, tmp_path) == ""
    assert file.read_bytes() == text.encode("utf-8")


def test_start_checks_blockers_before_migration():
    start = (ROOT / "start.ps1").read_bytes().decode("utf-8-sig")
    assert start.index("$blocker = Get-StartBlocker") < start.index("Invoke-StorageTool $base @('migrate')")
    assert start.index("$blocker = Get-StartBlocker") < start.index("& docker @compose up -d --no-build"), \
        "утраченную базу не подменяют пустой: проверка – до запуска приложения"
    assert "[switch]$NewDatabase" in start
    assert MARK not in start and "fingerprint" not in start and "Baseline" not in start, "списка отменённых баз и отпечатка базы больше нет"
