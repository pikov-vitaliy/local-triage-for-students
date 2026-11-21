"""Копии основной базы: настоящие сценарии PowerShell и настоящий pg_dump из образа базы, на контейнере тестовой базы (ADR-0128, раздел 9)."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest
from db_support import empty_database

from app.db import Database

ROOT = Path(__file__).resolve().parents[1]
CONTAINER = "triage-test-pg"
SHELLS = [shell for shell in (shutil.which("powershell"), shutil.which("pwsh")) if shell]
pytestmark = [pytest.mark.skipif(not SHELLS or not shutil.which("docker"), reason="нужны PowerShell и Docker"),
              pytest.mark.docker_db]


def run(script: str, *args: str, shell: str = "") -> subprocess.CompletedProcess:
    return subprocess.run([shell or SHELLS[0], "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ROOT / "scripts" / script), *args],
                          capture_output=True, text=True, encoding="utf-8", timeout=180)


def db_name(conninfo: str) -> str:
    return psycopg.conninfo.conninfo_to_dict(conninfo)["dbname"]


def prepared() -> str:
    target = empty_database()
    db = Database(target)
    db.create_project("Проект")
    db.create_project("Второй")
    db.close()
    return target


def check_bases() -> set[str]:
    out = subprocess.run(["docker", "exec", CONTAINER, "psql", "-U", "triage", "-d", "postgres", "-Atc",
                          "SELECT datname FROM pg_database WHERE datname LIKE 'restore_check_%'"],
                         capture_output=True, text=True).stdout
    return set(out.split())


def own_check_bases(pid: int) -> set[str]:
    """Проверочные базы процесса сценария с номером pid: имя базы кончается номером процесса (restore-check.ps1). В общем
    контейнере в этот момент могут идти проверки других прогонов (бэклог 122) – их базы тест не касаются."""
    return {name for name in check_bases() if name.endswith(f"_{pid}")}


def run_with_pid(script: str, *args: str, shell: str = "") -> tuple[subprocess.CompletedProcess, int]:
    """Как run, но возвращает и номер процесса сценария."""
    cmd = [shell or SHELLS[0], "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ROOT / "scripts" / script), *args]
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8") as proc:
        out, err = proc.communicate(timeout=180)
        return subprocess.CompletedProcess(cmd, proc.returncode, out, err), proc.pid


def latest(folder: Path) -> Path:
    return sorted(folder.glob("triage-*.dump"))[-1]


def backup(target: str, folder: Path, shell: str = "") -> Path:
    out = run("backup-db.ps1", "-OutDir", str(folder), "-DbContainer", CONTAINER, "-Database", db_name(target), shell=shell)
    assert out.returncode == 0, out.stdout + out.stderr
    return latest(folder)


@pytest.mark.parametrize("shell", SHELLS)
def test_backup_writes_final_file_and_summary(shell: str, tmp_path: Path):
    target = prepared()
    dump = backup(target, tmp_path, shell)
    assert dump.read_bytes().startswith(b"PGDMP"), "бинарный формат без текстового перенаправления"
    assert not list(tmp_path.glob("*.partial"))
    meta = json.loads(Path(f"{dump}.json").read_text(encoding="utf-8"))
    assert meta["size"] == dump.stat().st_size and meta["tables"]["projects"] >= 2 and meta["schema"]
    assert meta["max_hub_op"] == 0 and meta["max_hub_attempt"] == 0 and meta["postgresql"].startswith("17")
    assert meta["sequences"]["projects_id_seq"] >= 2
    # свой временный файл – по имени своей базы: в общем контейнере могут идти копии других прогонов (бэклог 122)
    left = subprocess.run(["docker", "exec", CONTAINER, "ls", "/tmp"], capture_output=True, text=True).stdout
    assert db_name(target) not in left, "в контейнере не остаётся файлов"


def test_two_backups_started_together_do_not_share_the_container_file(tmp_path: Path):
    """Бэклог 122: две копии разных баз, начатые в одну секунду на одном контейнере (задача по расписанию и ручной
    запуск, параллельные прогоны тестов), пишут каждая свой временный файл: обе завершаются успешно, и каждая копия
    проходит проверку восстановления со своей сводкой (в первой базе два проекта, во второй – три)."""
    first, second = prepared(), prepared()
    db = Database(second)
    db.create_project("Третий")
    db.close()
    for attempt in range(3):  # обе копии должны начаться в одну секунду – иначе тест ничего не проверяет
        folders = [tmp_path / f"a{attempt}", tmp_path / f"b{attempt}"]
        while datetime.now(UTC).microsecond > 300_000:
            time.sleep(0.05)
        procs = [subprocess.Popen([SHELLS[0], "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                                   str(ROOT / "scripts" / "backup-db.ps1"), "-OutDir", str(folder), "-DbContainer",
                                   CONTAINER, "-Database", db_name(target)],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8")
                 for folder, target in zip(folders, (first, second), strict=True)]
        outs = [proc.communicate(timeout=180)[0] for proc in procs]
        assert [proc.returncode for proc in procs] == [0, 0], outs
        dumps = [latest(folder) for folder in folders]
        if dumps[0].name == dumps[1].name:
            break
    else:
        pytest.skip("копии не удалось начать в одну секунду")
    for dump, projects in zip(dumps, (2, 3), strict=True):
        assert json.loads(Path(f"{dump}.json").read_text(encoding="utf-8"))["tables"]["projects"] == projects
        out = run("restore-check.ps1", "-Dump", str(dump), "-DbContainer", CONTAINER)
        assert out.returncode == 0, out.stdout + out.stderr


@pytest.mark.parametrize("shell", SHELLS)
def test_restore_check_passes_and_is_recorded(shell: str, tmp_path: Path):
    dump = backup(prepared(), tmp_path)
    out, pid = run_with_pid("restore-check.ps1", "-Dump", str(dump), "-DbContainer", CONTAINER, shell=shell)
    assert out.returncode == 0, out.stdout + out.stderr
    assert json.loads(Path(f"{dump}.json").read_text(encoding="utf-8"))["restore_check"] == "пройдена"
    assert not own_check_bases(pid), "проверочная база удалена"


def test_restore_check_refuses_changed_summary_and_damaged_file(tmp_path: Path):
    dump = backup(prepared(), tmp_path)
    sidecar = Path(f"{dump}.json")
    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    changed = dict(meta, summary_exact=True, tables=dict(meta["tables"], projects=meta["tables"]["projects"] + 1))
    sidecar.write_text(json.dumps(changed), encoding="utf-8")
    assert run("restore-check.ps1", "-Dump", str(dump), "-DbContainer", CONTAINER).returncode == 1
    assert json.loads(sidecar.read_text(encoding="utf-8"))["restore_check"].startswith("не пройдена")
    sidecar.write_text(json.dumps(meta), encoding="utf-8")
    dump.write_bytes(dump.read_bytes() + b"x")
    assert run("restore-check.ps1", "-Dump", str(dump), "-DbContainer", CONTAINER).returncode == 1


def test_restore_needs_checked_copy_and_confirmation_and_stopped_application(tmp_path: Path):
    target = prepared()
    name = db_name(target)
    dump = backup(target, tmp_path)
    common = ("-Dump", str(dump), "-DbContainer", CONTAINER, "-Database", name, "-NoAfterRestore")
    assert run("restore-db.ps1", *common, "-Confirm").returncode == 1, "копия ещё не проверена"
    assert run("restore-check.ps1", "-Dump", str(dump), "-DbContainer", CONTAINER).returncode == 0
    assert run("restore-db.ps1", *common).returncode == 1, "без подтверждения база не меняется"
    with psycopg.connect(target) as conn:
        assert run("restore-db.ps1", *common, "-Confirm").returncode == 1, "к базе подключено приложение"
        assert conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == 2


def test_restore_returns_data_and_sequences_of_the_copy(tmp_path: Path):
    target = prepared()
    name = db_name(target)
    dump = backup(target, tmp_path)
    assert run("restore-check.ps1", "-Dump", str(dump), "-DbContainer", CONTAINER).returncode == 0
    db = Database(target)
    db.create_project("после копии")
    db.close()
    subprocess.run(["docker", "exec", CONTAINER, "psql", "-U", "triage", "-d", "postgres", "-Atc",
                    f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{name}'"], capture_output=True)
    out = run("restore-db.ps1", "-Dump", str(dump), "-DbContainer", CONTAINER, "-Database", name, "-NoAfterRestore", "-Confirm")
    assert out.returncode == 0, out.stdout + out.stderr
    names = subprocess.run(["docker", "exec", CONTAINER, "psql", "-U", "triage", "-d", "postgres", "-Atc", "SELECT datname FROM pg_database"],
                           capture_output=True, text=True).stdout.split()
    kept = [n for n in names if n.startswith(f"{name}_before_restore_")]
    assert len(kept) == 1, "прежняя база сохранена"
    with psycopg.connect(target.replace(name, kept[0])) as conn:
        assert conn.execute("SELECT COUNT(*) FROM projects WHERE name = 'после копии'").fetchone()[0] == 1
    subprocess.run(["docker", "exec", CONTAINER, "psql", "-U", "triage", "-d", "postgres", "-c", f"DROP DATABASE {kept[0]}"], capture_output=True)
    with psycopg.connect(target) as conn:
        assert conn.execute("SELECT COUNT(*) FROM projects WHERE name = 'после копии'").fetchone()[0] == 0
        before = conn.execute("SELECT MAX(id) FROM projects").fetchone()[0]
        assert conn.execute("SELECT nextval(pg_get_serial_sequence('projects', 'id'))").fetchone()[0] == before + 1


def test_failed_restore_keeps_working_base(tmp_path: Path):
    """Сбой посреди восстановления: копия не разворачивается, рабочая база и её данные на месте, временной базы нет."""
    target = prepared()
    name = db_name(target)
    dump = backup(target, tmp_path)
    assert run("restore-check.ps1", "-Dump", str(dump), "-DbContainer", CONTAINER).returncode == 0
    sidecar = Path(f"{dump}.json")
    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    sidecar.write_text(json.dumps(dict(meta, tables=dict(meta["tables"], projects=99))), encoding="utf-8")
    out = run("restore-db.ps1", "-Dump", str(dump), "-DbContainer", CONTAINER, "-Database", name, "-NoAfterRestore", "-Confirm")
    assert out.returncode == 1
    with psycopg.connect(target) as conn:
        assert conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == 2
    names = subprocess.run(["docker", "exec", CONTAINER, "psql", "-U", "triage", "-d", "postgres", "-Atc", "SELECT datname FROM pg_database"],
                           capture_output=True, text=True).stdout
    assert f"{name}_restore_" not in names and f"{name}_before_restore_" not in names


@pytest.mark.parametrize("name", ["Triage", "tri-age", "a b", "a" * 31])
def test_database_name_is_checked_before_anything(tmp_path: Path, name: str):
    dump = backup(prepared(), tmp_path)
    assert run("restore-check.ps1", "-Dump", str(dump), "-DbContainer", CONTAINER).returncode == 0
    assert run("restore-db.ps1", "-Dump", str(dump), "-DbContainer", CONTAINER, "-Database", name, "-NoAfterRestore", "-Confirm").returncode == 1
    assert run("backup-db.ps1", "-OutDir", str(tmp_path / "x"), "-DbContainer", CONTAINER, "-Database", name).returncode == 1


def test_copy_of_changing_base_takes_summary_from_itself(tmp_path: Path):
    """Приложение работало во время копии: сводка не точна, проверка берёт её из восстановленной копии и не отказывает."""
    dump = backup(prepared(), tmp_path)
    sidecar = Path(f"{dump}.json")
    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    sidecar.write_text(json.dumps(dict(meta, summary_exact=False, tables=dict(meta["tables"], projects=99))), encoding="utf-8")
    assert run("restore-check.ps1", "-Dump", str(dump), "-DbContainer", CONTAINER).returncode == 0
    fixed = json.loads(sidecar.read_text(encoding="utf-8"))
    assert fixed["tables"]["projects"] == 2 and fixed["summary_exact"] is True and fixed["restore_check"] == "пройдена"


def test_sequence_value_comes_from_the_copy(tmp_path: Path):
    """Номер выдан из запаса последовательности: журнал не сдвинулся, а значение уже другое. Исправная копия не отклоняется."""
    dump = backup(prepared(), tmp_path)
    sidecar = Path(f"{dump}.json")
    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    real = meta["sequences"]["projects_id_seq"]
    sidecar.write_text(json.dumps(dict(meta, summary_exact=True, sequences=dict(meta["sequences"], projects_id_seq=real + 7))), encoding="utf-8")
    assert run("restore-check.ps1", "-Dump", str(dump), "-DbContainer", CONTAINER).returncode == 0
    assert json.loads(sidecar.read_text(encoding="utf-8"))["sequences"]["projects_id_seq"] == real


LOST_REPLY = r"""
param([string]$Script, [string]$Dump, [string]$Container, [string]$Name)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
function global:docker {
    $text = $args -join ' '
    if ($text -match 'RENAME TO') {
        if ($env:LOST_REPLY -eq 'applied') { & docker.exe @args | Out-Null }
        cmd /c exit 1
        return 'server closed the connection unexpectedly'
    }
    if ($env:LOST_REPLY -eq 'no-check' -and $text -match 'DROP DATABASE') {
        cmd /c exit 1
        return 'connection refused'
    }
    if ($env:LOST_REPLY -eq 'drop-then-dead' -and $text -match 'datname IN') {
        cmd /c exit 1
        return 'connection refused'
    }
    & docker.exe @args
}
& $Script -Dump $Dump -DbContainer $Container -Database $Name -NoAfterRestore -Confirm
exit $LASTEXITCODE
"""


def restore_with_lost_reply(mode: str, dump: Path, name: str, tmp_path: Path) -> subprocess.CompletedProcess:
    wrapper = tmp_path / "lost-reply.ps1"
    wrapper.write_text(LOST_REPLY, encoding="utf-8-sig")
    return subprocess.run([SHELLS[0], "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(wrapper), str(ROOT / "scripts" / "restore-db.ps1"),
                           str(dump), CONTAINER, name], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180,
                          env={**os.environ, "LOST_REPLY": mode})


def base_names(name: str) -> list[str]:
    out = subprocess.run(["docker", "exec", CONTAINER, "psql", "-U", "triage", "-d", "postgres", "-Atc", f"SELECT datname FROM pg_database WHERE datname LIKE '{name}%'"],
                         capture_output=True, text=True).stdout
    return out.split()


@pytest.mark.parametrize(("mode", "code", "word", "kept"), [("applied", 0, "замена выполнена", "_before_restore_"),
                                                             ("refused", 1, "рабочая база не изменилась", None),
                                                             ("no-check", 1, "неизвестен", "_restore_"),
                                                             ("drop-then-dead", 1, "замены не было, под этим именем прежняя база", None)])
def test_lost_reply_at_switch_reports_real_outcome(tmp_path: Path, mode: str, code: int, word: str, kept: str | None):
    """Ответ сервера при замене имён пропал: исход – по именам баз; проверить нельзя – так и сказано, копия не удаляется."""
    target = prepared()
    name = db_name(target)
    dump = backup(target, tmp_path)
    assert run("restore-check.ps1", "-Dump", str(dump), "-DbContainer", CONTAINER).returncode == 0
    out = restore_with_lost_reply(mode, dump, name, tmp_path)
    assert out.returncode == code, out.stdout + out.stderr
    assert word in out.stdout
    extra = [item for item in base_names(name) if item != name]
    assert name in base_names(name)
    if kept is None:
        assert extra == []
    else:
        assert len(extra) == 1 and kept in extra[0]
    for item in extra:
        subprocess.run(["docker", "exec", CONTAINER, "psql", "-U", "triage", "-d", "postgres", "-qc", f"DROP DATABASE IF EXISTS {item}"], capture_output=True)


def test_switch_outcome_waits_for_unfinished_rename(tmp_path: Path):
    """Сервер ещё завершает замену имён: проверка дожидается её конца и не удаляет копию, уже ставшую рабочей."""
    admin = psycopg.conninfo.make_conninfo(prepared(), dbname="postgres")
    name = f"sw{os.getpid()}"
    fresh, previous = f"{name}_restore", f"{name}_before"
    with psycopg.connect(admin, autocommit=True) as conn:
        for base in (name, fresh):
            conn.execute(f"CREATE DATABASE {base}")
    script = tmp_path / "outcome.ps1"
    common = ROOT / "scripts" / "db-common.ps1"
    script.write_text(f". '{common}'\nGet-DbSwitchOutcome {CONTAINER} triage {name} {fresh} {previous} $true\n", encoding="utf-8-sig")
    conn = psycopg.connect(admin)
    try:
        conn.execute(f"ALTER DATABASE {name} RENAME TO {previous}")
        conn.execute(f"ALTER DATABASE {fresh} RENAME TO {name}")
        check = subprocess.Popen([SHELLS[0], "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)], stdout=subprocess.PIPE, text=True, encoding="utf-8")
        time.sleep(3)
        assert check.poll() is None, "проверка ждёт конца транзакции"
        conn.commit()
        assert check.communicate(timeout=60)[0].strip() == "switched"
    finally:
        conn.close()
        with psycopg.connect(admin, autocommit=True) as cleanup:
            assert cleanup.execute("SELECT COUNT(*) FROM pg_database WHERE datname = %s", (name,)).fetchone()[0] == 1, "копия не удалена"
            for base in (name, previous, fresh):
                cleanup.execute(f"DROP DATABASE IF EXISTS {base}")


def isolated_script(tmp_path: Path, *names: str) -> Path:
    """Копия сценариев в чужой папке: рядом нет docker-compose.yml, поэтому до настоящей установки они не дотянутся."""
    folder = tmp_path / "scripts"
    folder.mkdir()
    for name in names:
        shutil.copy(ROOT / "scripts" / name, folder / name)
    return folder


def test_early_backup_failure_reason_reaches_task_log(tmp_path: Path):
    """Docker или база недоступны при запуске задачи: причина в журнале, а не только код выхода."""
    folder = isolated_script(tmp_path, "backup-db.ps1", "db-common.ps1", "restore-check.ps1")
    log = tmp_path / "task.log"
    out = subprocess.run([SHELLS[0], "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", f"& '{folder / 'backup-db.ps1'}' -Check *>> '{log}'; exit $LASTEXITCODE"],
                         capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    assert out.returncode == 1
    assert log.stat().st_size > 0


# --- отметка о проверенной копии и правило хранения (бэклог 76)

# Копия и её проверка – настоящие, на контейнере тестовой базы; команды Compose подменены: контейнер базы «этой установки» – тестовый,
# запуск образа приложения только записывается. Любая другая команда Compose отклоняется – до настоящей установки сценарий не дотянется.
NOTED = r"""
param([string]$Script, [string]$OutDir, [string]$Database, [string]$Keep = '', [string]$Log = '', [string]$Plain = '')
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
function global:docker {
    $text = $args -join ' '
    if ($args[0] -eq 'compose') {
        if ($text -match ' ps -q db$') { cmd /c exit 0; return $env:NOTED_CONTAINER }
        if ($text -match ' run ') {
            [IO.File]::AppendAllText($env:NOTED_CALLS, $text + "`n")
            if ($env:NOTED_MODE -eq 'note-fails') { cmd /c exit 2; return '{"error": "OperationalError: база приложения недоступна"}' }
            cmd /c exit 0
            return '{"last_checked_backup": {}}'
        }
        cmd /c exit 1
        return 'unexpected compose command'
    }
    if ($env:NOTED_MODE -eq 'check-fails' -and $text -match 'pg_restore') { cmd /c exit 1; return 'pg_restore: error' }
    & docker.exe @args
}
$options = @{ OutDir = $OutDir; Database = $Database }
if (-not $Plain) { $options['Check'] = $true }
if ($Keep) { $options['Keep'] = [int]$Keep }
if ($env:NOTED_MODE -eq 'explicit-container') { $options['DbContainer'] = $env:NOTED_CONTAINER }
if ($Log) { & $Script @options *>> $Log } else { & $Script @options }
exit $LASTEXITCODE
"""


def noted_backup(shell: str, tmp_path: Path, folder: Path, *, mode: str = "", keep: int = 0, log: Path | None = None,
                 plain: bool = False) -> tuple[subprocess.CompletedProcess, list[str]]:
    """backup-db.ps1 без -DbContainer из копии сценариев в чужой папке; возвращает итог и записанные запуски образа приложения."""
    scripts = tmp_path / "scripts"
    if not scripts.exists():
        isolated_script(tmp_path, "backup-db.ps1", "db-common.ps1", "restore-check.ps1")
    wrapper = tmp_path / "noted.ps1"
    wrapper.write_text(NOTED, encoding="utf-8-sig")
    calls = tmp_path / "compose-run.txt"
    calls.write_text("", encoding="utf-8")
    command = [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(wrapper), "-Script", str(scripts / "backup-db.ps1"),
               "-OutDir", str(folder), "-Database", db_name(prepared())]
    command += ["-Keep", str(keep)] if keep else []
    command += ["-Log", str(log)] if log else []
    command += ["-Plain", "1"] if plain else []
    out = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180,
                         env={**os.environ, "NOTED_CONTAINER": CONTAINER, "NOTED_CALLS": str(calls), "NOTED_MODE": mode})
    return out, calls.read_text(encoding="utf-8").splitlines()


@pytest.mark.parametrize("shell", SHELLS)
def test_checked_copy_is_noted_in_application_base(shell: str, tmp_path: Path):
    """После пройденной проверки сценарий сообщает приложению имя и время копии: одной командой backup-note в образе приложения,
    в ту базу, с которой снята копия."""
    folder = tmp_path / "backups"
    out, calls = noted_backup(shell, tmp_path, folder)
    assert out.returncode == 0, out.stdout + out.stderr
    dump = latest(folder)
    assert json.loads(Path(f"{dump}.json").read_text(encoding="utf-8"))["restore_check"] == "пройдена"
    assert len(calls) == 1, calls
    found = re.fullmatch(r"compose -f docker-compose\.yml run --rm --no-deps -T -e PGDATABASE=(\S+) triage python -m app\.storage\.tools "
                         r"backup-note --name (\S+) --checked-at (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)", calls[0])
    assert found, calls[0]
    assert found.group(1).startswith("e") and found.group(2) == dump.name
    noted = datetime.fromisoformat(found.group(3))
    taken = datetime.strptime(dump.name, "triage-%Y%m%d-%H%M%S.dump").replace(tzinfo=UTC)
    assert timedelta(0) <= noted - taken < timedelta(minutes=5), "время отметки – время проверки, UTC"
    assert "Отметка о проверенной копии записана" in out.stdout


@pytest.mark.parametrize("shell", SHELLS)
def test_failed_note_does_not_fail_the_copy_and_reaches_task_log(shell: str, tmp_path: Path):
    """Отметка не записалась: копия остаётся успешной (код 0), предупреждение с причиной – в выводе, а значит и в журнале задачи."""
    folder = tmp_path / "backups"
    log = tmp_path / "task.log"
    out, calls = noted_backup(shell, tmp_path, folder, mode="note-fails", log=log)
    assert out.returncode == 0, out.stdout + out.stderr
    assert len(calls) == 1 and latest(folder).exists()
    raw = log.read_bytes()
    text = raw.decode("utf-16") if raw.startswith(b"\xff\xfe") else raw.decode("utf-8-sig")
    assert "Предупреждение: копия проверена, но отметка о ней в базе приложения не записана" in text
    assert "код" in text and "база приложения недоступна" in text
    assert "Проверка восстановления пройдена" in text


def test_copy_is_not_noted_without_passed_check_or_from_another_container(tmp_path: Path):
    """Отметка – только о проверенной копии базы этой установки: без -Check, при провале проверки и при контейнере, заданном
    параметром, приложению ничего не сообщается; правило хранения при этом тоже не действует."""
    folder = tmp_path / "backups"
    folder.mkdir()
    old = [folder / f"triage-2020010{n}-000000.dump" for n in (1, 2, 3)]
    for dump in old:
        dump.write_bytes(b"x")
        Path(f"{dump}.json").write_text(json.dumps({"restore_check": "пройдена"}), encoding="utf-8")
    out, calls = noted_backup(SHELLS[0], tmp_path, folder, plain=True, keep=1)
    assert out.returncode == 0 and calls == [], out.stdout + out.stderr
    assert "добавьте -Check" in out.stdout
    out, calls = noted_backup(SHELLS[0], tmp_path, folder, mode="check-fails", keep=1)
    assert out.returncode == 1 and calls == [], out.stdout + out.stderr
    out, calls = noted_backup(SHELLS[0], tmp_path, folder, mode="explicit-container")
    assert out.returncode == 0 and calls == [], out.stdout + out.stderr
    assert "отметка о копии в базу приложения не записывается" in out.stdout
    assert all(dump.exists() and Path(f"{dump}.json").exists() for dump in old), "старые копии на месте"


def stored_copy(folder: Path, stamp: str, check: str | None = "пройдена") -> Path:
    """Файл копии с сопроводительным файлом (check – итог проверки; None – файла нет)."""
    dump = folder / f"triage-{stamp}.dump"
    dump.write_bytes(b"x")
    if check is not None:
        Path(f"{dump}.json").write_text(json.dumps({"restore_check": check}, ensure_ascii=False), encoding="utf-8")
    return dump


@pytest.mark.parametrize("shell", SHELLS)
def test_keep_leaves_newest_checked_copies_and_everything_else(shell: str, tmp_path: Path):
    """-Keep 2 после проверенной копии: остаются она и предыдущая проверенная; всё старше удаляется вместе с сопроводительными
    файлами. Непроверенная копия новее оставленной, файлы другого вида и папка before-local-state не трогаются."""
    folder = tmp_path / "backups"
    (folder / "before-local-state").mkdir(parents=True)
    (folder / "before-local-state" / "triage-20200101-000000.dump").write_bytes(b"x")
    stored_copy(folder, "20200101-000000")
    stored_copy(folder, "20200102-000000")
    stored_copy(folder, "20200103-000000", "не пройдена: схема 33 и 34")
    stored_copy(folder, "20200104-000000", None)
    kept = stored_copy(folder, "20200105-000000")
    young = stored_copy(folder, "20200106-000000", None)
    other = ["backup-task.log", "pgdata-after-rollback.txt", "triage-20200101-000000.dump.bak", "triage-2020010-000000.dump",
             "triage-20200101-000000-copy.dump", "other-20200101-000000.dump", "Triage-20200101-000000.dump.txt"]
    for name in other:
        (folder / name).write_bytes(b"x")
    out, calls = noted_backup(shell, tmp_path, folder, keep=2)
    assert out.returncode == 0, out.stdout + out.stderr
    fresh = latest(folder)
    left = sorted(p.name for p in folder.iterdir())
    assert left == sorted([fresh.name, f"{fresh.name}.json", kept.name, f"{kept.name}.json", young.name, "before-local-state", *other]), left
    assert (folder / "before-local-state" / "triage-20200101-000000.dump").exists()
    for stamp in ("20200101-000000", "20200102-000000", "20200103-000000", "20200104-000000"):
        assert f"Удалена старая копия: triage-{stamp}.dump" in out.stdout
    assert kept.name not in out.stdout.split("Удалена старая копия", 1)[1], "оставленная копия среди удалённых не названа"
    assert len(calls) == 1, "отметка записана один раз"


@pytest.mark.parametrize("shell", SHELLS)
def test_keep_rule_removes_nothing_without_enough_checked_copies(shell: str, tmp_path: Path):
    """Само правило: проверенных копий не больше N – ничего не удаляется; N = 0 – правило выключено; копия с нечитаемым
    сопроводительным файлом – непроверенная."""
    folder = tmp_path / "backups"
    folder.mkdir()
    stored_copy(folder, "20200101-000000", None)
    stored_copy(folder, "20200102-000000")
    broken = stored_copy(folder, "20200103-000000")
    Path(f"{broken}.json").write_text("{не JSON", encoding="utf-8")
    stored_copy(folder, "20200104-000000")
    before = sorted(p.name for p in folder.iterdir())
    common = ROOT / "scripts" / "db-common.ps1"

    def rule(keep: int) -> subprocess.CompletedProcess:
        command = f". '{common}'; Remove-OldBackups '{folder}' {keep}; Write-Output 'DONE'"
        return subprocess.run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)

    for keep in (0, 2, 5):
        out = rule(keep)
        assert out.returncode == 0 and "DONE" in out.stdout, out.stdout + out.stderr
        assert sorted(p.name for p in folder.iterdir()) == before, f"-Keep {keep}: ничего не удалено"
    out = rule(1)
    assert out.returncode == 0 and "DONE" in out.stdout, out.stdout + out.stderr
    assert sorted(p.name for p in folder.iterdir()) == ["triage-20200104-000000.dump", "triage-20200104-000000.dump.json"]


def test_negative_keep_is_refused_before_anything(tmp_path: Path):
    out = run("backup-db.ps1", "-OutDir", str(tmp_path / "x"), "-DbContainer", CONTAINER, "-Database", "x", "-Keep", "-1")
    assert out.returncode == 1 and not (tmp_path / "x").exists()


def test_copy_without_database_size_is_refused(tmp_path: Path):
    dump = backup(prepared(), tmp_path)
    sidecar = Path(f"{dump}.json")
    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    del meta["database_bytes"]
    sidecar.write_text(json.dumps(meta), encoding="utf-8")
    assert run("restore-check.ps1", "-Dump", str(dump), "-DbContainer", CONTAINER).returncode == 1


def test_restore_when_working_base_is_gone(tmp_path: Path):
    target = prepared()
    name = db_name(target)
    dump = backup(target, tmp_path)
    assert run("restore-check.ps1", "-Dump", str(dump), "-DbContainer", CONTAINER).returncode == 0
    subprocess.run(["docker", "exec", CONTAINER, "psql", "-U", "triage", "-d", "postgres", "-c", f"DROP DATABASE {name} WITH (FORCE)"], capture_output=True)
    out = run("restore-db.ps1", "-Dump", str(dump), "-DbContainer", CONTAINER, "-Database", name, "-NoAfterRestore", "-Confirm")
    assert out.returncode == 0, out.stdout + out.stderr
    with psycopg.connect(target) as conn:
        assert conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == 2


def test_no_room_is_reported_before_anything_changes(tmp_path: Path):
    target = prepared()
    name = db_name(target)
    dump = backup(target, tmp_path)
    assert run("restore-check.ps1", "-Dump", str(dump), "-DbContainer", CONTAINER).returncode == 0
    sidecar = Path(f"{dump}.json")
    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    sidecar.write_text(json.dumps(dict(meta, database_bytes=10 ** 16)), encoding="utf-8")
    out = run("restore-db.ps1", "-Dump", str(dump), "-DbContainer", CONTAINER, "-Database", name, "-NoAfterRestore", "-Confirm")
    assert out.returncode == 1
    names = subprocess.run(["docker", "exec", CONTAINER, "psql", "-U", "triage", "-d", "postgres", "-Atc", "SELECT datname FROM pg_database"],
                           capture_output=True, text=True).stdout
    assert f"{name}_restore_" not in names


def test_failed_backup_leaves_nothing(tmp_path: Path):
    out = run("backup-db.ps1", "-OutDir", str(tmp_path), "-DbContainer", "нет-такого-контейнера", "-Database", "x")
    assert out.returncode == 1 and list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("shell", SHELLS)
def test_text_file_is_written_through_temporary_file_and_replaces_existing(shell: str, tmp_path: Path):
    """Итоговая проверка 0.10.0: сопроводительный файл копии пишется через временный файл с заменой. Замена существующего файла –
    отдельная ветвь: restore-check.ps1 дописывает итог в уже созданный backup-db.ps1 файл."""
    target = tmp_path / "копия.dump.json"
    command = (f". '{ROOT / 'scripts' / 'db-common.ps1'}'; Write-Utf8File '{target}' 'первый'; "
               f"Write-Utf8File '{target}' 'второй – итог проверки'; Write-Output 'DONE'")
    out = subprocess.run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                         capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert out.returncode == 0 and "DONE" in out.stdout, out.stdout + out.stderr
    assert target.read_bytes() == "второй – итог проверки".encode(), "без BOM, содержимое заменено целиком"
    assert [p.name for p in tmp_path.iterdir()] == [target.name], "временного файла не осталось"


@pytest.mark.parametrize("shell", SHELLS)
def test_every_script_parses(shell: str):
    """Ошибка разбора не даёт сценарию запуститься вообще, а часть из них в обычных тестах не выполняется."""
    command = ("$bad = @(); foreach ($f in Get-ChildItem -LiteralPath '" + str(ROOT / "scripts") + "' -Filter *.ps1) "
               "{ $e = $null; [void][Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$e); "
               "if ($e) { $bad += $f.Name } }; $e = $null; "
               "[void][Management.Automation.Language.Parser]::ParseFile('" + str(ROOT / "start.ps1") + "', [ref]$null, [ref]$e); "
               "if ($e) { $bad += 'start.ps1' }; Write-Output ('BAD=' + ($bad -join ','))")
    out = subprocess.run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command], capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert "BAD=" in out.stdout and out.stdout.split("BAD=")[1].strip() == "", out.stdout + out.stderr


def test_scripts_have_bom_and_task_catches_up():
    for name in ("db-common.ps1", "backup-db.ps1", "restore-check.ps1", "restore-db.ps1", "install-backup-task.ps1", "export-image.ps1",
                 "import-image.ps1"):
        assert (ROOT / "scripts" / name).read_bytes().startswith(b"\xef\xbb\xbf"), f"{name}: без BOM Windows PowerShell 5.1 ломает русский текст"
    task = (ROOT / "scripts" / "install-backup-task.ps1").read_text(encoding="utf-8")
    assert "-StartWhenAvailable" in task, "пропущенный запуск выполняется при следующей возможности"
    assert "Remove-Item" not in task, "старые копии задача не удаляет"
    # сценарий установки в тестах не выполняется (он меняет задачу Планировщика): команда задачи проверяется по тексту
    assert "[int]$Keep = 0" in task, "по умолчанию задача ничего не удаляет"
    assert """$keepArgument = if ($Keep -gt 0) { " -Keep $Keep" } else { '' }""" in task
    assert '''$command = "& '$script' -Check$keepArgument *>> '$log'; exit `$LASTEXITCODE"''' in task, "-Keep передаётся backup-db.ps1"


# --- start.ps1: строка о последней проверенной копии (бэклог 76)

def start_report(shell: str, tmp_path: Path, copies: dict[str, str | None], missing_dump: str = "") -> str:
    """start.ps1 целиком с подменами Docker и сети (test_lan_access.run_flow); copies – {метка времени: итог проверки или None}.
    Возвращает вывод одной строкой: Windows PowerShell 5.1 переносит длинные строки вывода по ширине."""
    from test_lan_access import env_text, run_flow
    folder = tmp_path / "app" / "backups"
    folder.mkdir(parents=True)
    for stamp, check in copies.items():
        stored_copy(folder, stamp, check)
    if missing_dump:
        (folder / f"triage-{missing_dump}.dump").unlink()
    got = run_flow(shell, tmp_path, "-NoBrowser", env_text(tmp_path))
    assert got["exit"] == "0", got["out"] + got["stderr"]
    text = got["out"].replace("\r", "").replace("\n", "")
    assert "Готово: http://127.0.0.1:18765" in text
    return text


def stamp_of(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y%m%d-%H%M%S")


@pytest.mark.parametrize("shell", SHELLS)
def test_start_reports_the_last_checked_copy(shell: str, tmp_path: Path):
    """Итог запуска называет самую новую копию с пройденной проверкой: более новая непроверенная и запись без файла копии не в счёт."""
    now = datetime.now(UTC)
    checked, unchecked, gone = (stamp_of(now - timedelta(hours=5, minutes=30)), stamp_of(now - timedelta(hours=1)),
                                stamp_of(now - timedelta(minutes=30)))
    text = start_report(shell, tmp_path, {stamp_of(now - timedelta(days=9)): "пройдена", checked: "пройдена",
                                          unchecked: "не пройдена: схема 33 и 34", gone: "пройдена"}, missing_dump=gone)
    assert re.search(rf"Последняя проверенная копия базы: triage-{checked}\.dump от [0-9. :]+ \(5 ч назад\)\.", text), text
    assert "больше 48 часов" not in text and "Проверенной копии базы в папке backups нет" not in text


@pytest.mark.parametrize("shell", SHELLS)
def test_start_warns_about_old_or_missing_checked_copy_and_still_starts(shell: str, tmp_path: Path):
    """Проверенная копия старше 48 часов или её нет вовсе – предупреждение; запуск из-за этого не отменяется."""
    old = stamp_of(datetime.now(UTC) - timedelta(hours=50, minutes=10))
    text = start_report(shell, tmp_path / "old", {old: "пройдена", stamp_of(datetime.now(UTC)): None})
    assert re.search(rf"Последняя проверенная копия базы: triage-{old}\.dump от [0-9. :]+ \(50 ч назад\)\. Это больше 48 часов\. "
                     r"Снять и проверить копию: \.\\scripts\\backup-db\.ps1 -Check", text), text
    none = start_report(shell, tmp_path / "none", {stamp_of(datetime.now(UTC)): "не пройдена: сбой"})
    assert "Проверенной копии базы в папке backups нет. Снять и проверить копию: .\\scripts\\backup-db.ps1 -Check" in none
    assert "Последняя проверенная копия базы" not in none
