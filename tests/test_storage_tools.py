"""Команды обслуживания основной базы (ADR-0128, разделы 7–9): status, пауза записи, шаг после восстановления копии. База –
схемы этой сборки, созданная приложением."""

from __future__ import annotations

import json
from pathlib import Path

import psycopg
import pytest
from db_support import empty_database

from app.db import Database
from app.storage import schema as manifest
from app.storage import tools


@pytest.fixture(autouse=True)
def data_dir_without_state_files(monkeypatch, tmp_path: Path):
    """status смотрит в папку данных (файлы состояния прежней сборки, ADR-0133): здесь она пустая и своя у каждого теста."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))


@pytest.fixture
def target() -> str:
    return empty_database()


@pytest.fixture
def base(target: str) -> str:
    """База со схемой этой сборки: её создаёт первое открытие приложением."""
    Database(target).close()
    return target


def tables_of(conn: psycopg.Connection) -> set[str]:
    return {row[0] for row in conn.execute(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'")}


def use_base(monkeypatch, target: str) -> None:
    parts = psycopg.conninfo.conninfo_to_dict(target)
    for key, env in (("host", "PGHOST"), ("port", "PGPORT"), ("user", "PGUSER"), ("password", "PGPASSWORD"), ("dbname", "PGDATABASE")):
        monkeypatch.setenv(env, str(parts[key]))


def run_tools(monkeypatch, target: str, *args: str) -> tuple[int, dict]:
    use_base(monkeypatch, target)
    return tools._run(tools_args(*args))


def tools_args(*args: str):
    captured = {}

    def fake(namespace):
        captured["args"] = namespace
        return 0, {}
    real = tools._run
    tools._run = fake
    try:
        tools.main(list(args))
    finally:
        tools._run = real
    return captured["args"]


def test_tools_commands_on_empty_and_working_base(target: str, monkeypatch, capsys):
    code, answer = run_tools(monkeypatch, target, "status")
    assert code == 0 and answer == {"state": "empty", "schema": None, "expected": manifest.SCHEMA_VERSION, "pending": [],
                                     "local_state_pending": False}
    Database(target).close()
    code, answer = run_tools(monkeypatch, target, "status")
    assert code == 0 and answer == {"state": "ok", "schema": manifest.SCHEMA_VERSION, "expected": manifest.SCHEMA_VERSION, "pending": [],
                                     "local_state_pending": False}
    assert run_tools(monkeypatch, target, "hub-pause")[1] == {"hub_write_paused": True}
    assert run_tools(monkeypatch, target, "hub-resume")[1] == {"hub_write_paused": False}
    assert run_tools(monkeypatch, target, "migrate") == (0, {"applied": []}), "схема этой сборки: применять нечего"


def test_refused_command_answers_with_error_and_code_2(target: str, monkeypatch, capsys):
    use_base(monkeypatch, target)
    capsys.readouterr()
    assert tools.main(["hub-pause"]) == 2
    assert json.loads(capsys.readouterr().out)["error"].startswith("ToolError: База пуста")


@pytest.mark.parametrize("command", ["inspect", "sqlite-to-postgresql", "verify"])
def test_transfer_commands_are_removed(command: str, capsys):
    """0.10.0.dev8: переезд на PostgreSQL выполнен, команд переноса из SQLite и его сверки у сборки нет."""
    with pytest.raises(SystemExit) as stopped:
        tools.main([command, "--sqlite", "copy.db"])
    assert stopped.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_chain_second_step_is_never_queued_after_restore(base: str, monkeypatch):
    """Отметка о прежнем статусе снимается, а второй POST не ставится: ни при запуске, ни после сверки первого шага."""
    from app import hub_effects, hub_entity_versions, hub_status
    with psycopg.connect(base) as conn:
        conn.execute("INSERT INTO projects(id, name, created_at, updated_at) VALUES (1, 'p', 'x', 'x')")
        conn.execute("INSERT INTO hub_ops(id, project_id, purpose, op_key, request_json, targets_json, hub_url, state, created_at, updated_at) VALUES"
                     " (1, 1, 'status', 'k', %s, %s, 'u', %s, 'x', 'x')",
                     (json.dumps({"then": {"status": "x", "reason": "y"}}), json.dumps([{"hub_id": "10", "revision": 1}]), "done"))
    withdrawn = []
    monkeypatch.setattr(hub_status, "status_request", lambda *args, **kwargs: {"method": "POST"})
    monkeypatch.setattr(hub_entity_versions, "confirmable", lambda c, pid, target_row: (None, True, None, None))
    monkeypatch.setattr(hub_effects, "_withdraw_marks_in", lambda c, op, targets: withdrawn.append(targets))
    db = Database(base)
    try:
        assert db.settle_after_restore()["chains"] == 1
        assert hub_effects.chain_replace(db, db.hub_op(1)) is None
        assert db._scalar("SELECT COUNT(*) FROM hub_ops") == 1, "второго шага нет"
        assert withdrawn == [[{"hub_id": "10", "revision": 1}]]
        assert json.loads(db._scalar("SELECT request_json FROM hub_ops WHERE id = 1"))["then"]["chained"] == 0
    finally:
        db.close()


DEFECT_READ = {"status": 200, "body_text": json.dumps({"id": 7, "appId": 5, "summary": "s", "description": "t", "linkedIssues": []})}


def restored_defect(target: str, *, state: str, targets: list, **fields) -> None:
    """В копии: операция чтения №1 выполнена, её ответ сохранён, последствия ещё не применены."""
    with psycopg.connect(target) as conn:
        conn.execute("INSERT INTO projects(id, name, created_at, updated_at) VALUES (1, 'p', 'x', 'x')")
        conn.execute("INSERT INTO hub_ops(id, project_id, app_id, purpose, op_key, request_json, targets_json, hub_url, state, result_json, created_at, updated_at, closed_at)"
                     " VALUES (1, 1, 5, 'defect_read', 'k', '{}', %s, 'u', 'done', %s, 'x', 'x', 'x')", (json.dumps(targets), json.dumps(DEFECT_READ)))
        conn.execute("SELECT setval(pg_get_serial_sequence('hub_ops', 'id'), 1)")
        names = ", ".join(fields)
        marks = ", ".join(["%s"] * len(fields))
        conn.execute(f"INSERT INTO hub_defects(id, project_id, kind, app_id, hub_url, hub_defect_id, targets_json, summary, command_text, state, created_at, updated_at, {names})"
                     f" VALUES (1, 1, 'SAST', 5, 'u', '7', %s, 's', 't', %s, 'x', 'x', {marks})", (json.dumps(targets), state, *fields.values()))


@pytest.mark.parametrize("state", ["blank", "preview", "creating", "created", "linking", "unknown", "unconfirmed"])
def test_unfinished_row_is_cancelled_after_restore(base: str, state: str):
    """Создание и привязка могли уйти в Hub после копии: строка снята, сохранённый ответ ничего не ставит, операции не остаются неизвестными."""
    from app import hub_defects
    restored_defect(base, state=state, targets=[{"hub_id": "10", "issue_type": "SAST"}], read_op_id=1, create_op_id=2)
    with psycopg.connect(base) as conn:
        conn.execute("INSERT INTO hub_ops(id, project_id, app_id, purpose, op_key, request_json, targets_json, hub_url, state, created_at, updated_at)"
                     " VALUES (2, 1, 5, 'defect_create', 'c', '{}', '[]', 'u', 'taken', 'x', 'x')")
    db = Database(base)
    try:
        settled = db.settle_after_restore()
        assert settled["defects"] == 1
        row = hub_defects.sync(db, db.hub_defect(1))
        assert row["state"] == "cancelled" and hub_defects.view(row)["text"] == hub_defects.RESTORED_NOTE
        hub_defects.after_op(db, db.hub_op(1))
        assert db._scalar("SELECT COUNT(*) FROM hub_ops") == 2, "новых операций нет"
        assert db.hub_op(2)["state"] == "cancelled" and db.hub_unknown_writes() == 0
    finally:
        db.close()


@pytest.mark.parametrize("state", ["done", "mismatch", "failed"])
def test_row_with_result_is_kept_after_restore(base: str, state: str):
    from app import hub_defects
    restored_defect(base, state=state, targets=[{"hub_id": "10", "issue_type": "SAST"}], read_op_id=1)
    db = Database(base)
    try:
        assert db.settle_after_restore()["defects"] == 0
        assert db.hub_defect(1)["state"] == state
        assert hub_defects.restart_read(db, db.hub_defect(1)) is None, "итог не перечитывается цепочкой создания"
    finally:
        db.close()


def test_import_row_is_not_touched_after_restore(base: str):
    from app import hub_defects
    restored_defect(base, state="import_reading", targets=[], read_op_id=1, origin="import")
    with psycopg.connect(base) as conn:
        assert conn.execute("SELECT COUNT(*) FROM hub_defects").fetchone()[0] == 1
    db = Database(base)
    try:
        assert db.settle_after_restore()["defects"] == 0
        assert hub_defects.sync(db, db.hub_defect(1))["state"] != "cancelled"
    finally:
        db.close()


@pytest.mark.parametrize("step", ["read1", "read2", "put", "confirm", "verify"])
def test_unfinished_update_is_cancelled_after_restore(base: str, step: str):
    """`PUT` мог уйти в Hub после копии: попытка снята, сохранённый ответ ничего не ставит, синхронизации строка не мешает."""
    from app import hub_defects
    first = json.loads(DEFECT_READ["body_text"])
    restored_defect(base, state="done", targets=[{"defect_update": 1}], update_op_id=1,
                    update_json=json.dumps({"step": step, "phase": "putting" if step == "put" else "preview", "first": first, "generation": 1}))

    def prepare(row):
        pytest.fail("подготовка записи не должна вызываться")

    db = Database(base)
    try:
        assert db.settle_after_restore()["defects"] == 1
        hub_defects.after_op(db, db.hub_op(1), prepare=prepare)
        row = db.hub_defect(1)
        state = json.loads(row["update_json"])
        assert row["update_op_id"] is None and state["phase"] == "cancelled" and state["note"] == hub_defects.RESTORED_PUT_NOTE
        assert state["phase"] in hub_defects.UPDATE_SETTLED and not hub_defects.update_busy(row)
        assert db._scalar("SELECT COUNT(*) FROM hub_ops") == 1, "PUT не поставлен"
    finally:
        db.close()


@pytest.mark.parametrize("command", ["hub-pause", "hub-resume", "after-restore", "migrate"])
def test_commands_refuse_empty_base_and_keep_it_empty(target: str, monkeypatch, command: str):
    with pytest.raises(tools.ToolError, match="База пуста"):
        run_tools(monkeypatch, target, command)
    with psycopg.connect(target) as conn:
        assert tables_of(conn) == set()


def test_pause_is_not_removed_with_unknown_writes(base: str, monkeypatch):
    from app import hub_ops
    run_tools(monkeypatch, base, "hub-pause")
    with psycopg.connect(base) as conn:
        conn.execute("INSERT INTO hub_ops(id, purpose, op_key, request_json, hub_url, state, created_at, updated_at)"
                     " VALUES (1, %s, 'k', '{}', 'u', 'unknown', 'x', 'x')", (sorted(hub_ops.WRITE_PURPOSES)[0],))
    with pytest.raises(tools.ToolError, match="неизвестным исходом"):
        run_tools(monkeypatch, base, "hub-resume")
    assert run_tools(monkeypatch, base, "hub-resume", "--accept-unknown")[1] == {"hub_write_paused": False}, "решение оператора: тупика нет"
    run_tools(monkeypatch, base, "hub-pause")
    with psycopg.connect(base) as conn:
        conn.execute("UPDATE hub_ops SET state = 'done'")
    assert run_tools(monkeypatch, base, "hub-resume")[1] == {"hub_write_paused": False}


def test_after_restore_pauses_and_marks_unfinished_work(base: str, monkeypatch):
    from app import hub_ops
    write = sorted(hub_ops.WRITE_PURPOSES)[0]
    with psycopg.connect(base) as conn:
        for number, (purpose, state) in enumerate([(write, "queued"), (write, "taken"), (write, "unknown"), (write, "done"),
                                                   ("defect_read", "queued")], start=1):
            conn.execute("INSERT INTO hub_ops(id, purpose, op_key, request_json, hub_url, state, created_at, updated_at)"
                         " VALUES (%s, %s, %s, '{}', 'u', %s, 'x', 'x')", (number, purpose, f"k{number}", state))
        conn.execute("INSERT INTO hub_ops(id, purpose, op_key, request_json, hub_url, state, created_at, updated_at) VALUES"
                     " (6, %s, 'k6', '{\"then\": {\"status\": \"x\", \"reason\": \"y\"}}', 'u', 'done', 'x', 'x')", (write,))
    assert not hub_ops.is_write("defect_read")
    code, answer = run_tools(monkeypatch, base, "after-restore")
    assert code == 0 and answer == {"hub_write_paused": True, "failed": 1, "cancelled": 3, "chains": 1, "defects": 0}
    with psycopg.connect(base) as conn:
        states = [row[0] for row in conn.execute("SELECT state FROM hub_ops ORDER BY id")]
        assert states == ["cancelled", "cancelled", "cancelled", "done", "failed", "done"]
        chained = conn.execute("SELECT request_json FROM hub_ops WHERE id = 6").fetchone()[0]
        assert json.loads(chained)["then"]["stop_after_restore"] is True, "второй шаг цепочки не ставится"
        assert conn.execute("SELECT value_json FROM settings WHERE key = 'hub_write_paused'").fetchone()[0] == "true"
    db = Database(base)
    try:
        assert db.hub_write_paused()
        assert db.hub_claim("w", "u", 60) is None, "незавершённая запись не выдаётся повторно"
    finally:
        db.close()
