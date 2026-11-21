"""Возраст последней проверенной копии базы в /healthz (бэклог 76): отметка команды backup-note в settings, поле backup в ответе.

Копии лежат на компьютере вне контейнера, приложение их не видит: отметку пишет scripts/backup-db.ps1 после пройденной проверки
(сам вызов – tests/test_backup_scripts.py). Поле backup – сведение для оператора: status и код ответа от него не зависят."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest
from db_support import conninfo_of, database_for_path
from fastapi.testclient import TestClient

from app.config import Settings
from app.db import BACKUP_NOTE_KEY, Database, DatabaseBusy
from app.main import create_app
from app.routes.api import BACKUP_STALE_HOURS, backup_state
from app.storage import tools

BASE = "http://127.0.0.1:8765"
NAME = "triage-20261104-030000.dump"
NOW = datetime(2026, 11, 6, 12, 0, 0, tzinfo=UTC)
EMPTY = {"checked_at": None, "age_hours": None, "stale": True}


def note(hours: float = 0, seconds: float = 0) -> dict:
    return {"name": NAME, "checked_at": (NOW - timedelta(hours=hours, seconds=seconds)).isoformat(timespec="seconds")}


# --- поле backup

def test_backup_state_counts_whole_hours_and_marks_copies_older_than_two_days():
    assert BACKUP_STALE_HOURS == 48
    assert backup_state(note(), NOW) == {"checked_at": "2026-11-06T12:00:00+00:00", "age_hours": 0, "stale": False}
    assert backup_state(note(hours=5, seconds=3599), NOW)["age_hours"] == 5
    assert backup_state(note(hours=48), NOW) == {"checked_at": "2026-11-04T12:00:00+00:00", "age_hours": 48, "stale": False}
    assert backup_state(note(hours=48, seconds=1), NOW) == {"checked_at": "2026-11-04T11:59:59+00:00", "age_hours": 48, "stale": True}
    assert backup_state(note(hours=24 * 30), NOW)["age_hours"] == 720


def test_backup_state_without_readable_note_is_stale_and_has_no_age():
    for value in (None, {}, {"name": NAME}, {"name": NAME, "checked_at": None}, {"name": NAME, "checked_at": "вчера"},
                  {"name": NAME, "checked_at": 20261104}):
        assert backup_state(value, NOW) == EMPTY, value


def test_backup_state_reads_other_offsets_and_a_clock_behind_the_note():
    assert backup_state({"checked_at": "2026-11-06T13:00:00+03:00"}, NOW)["checked_at"] == "2026-11-06T10:00:00+00:00"
    assert backup_state({"checked_at": "2026-11-06T10:00:00"}, NOW)["age_hours"] == 2, "время без пояса – UTC"
    assert backup_state(note(hours=-3), NOW) == {"checked_at": "2026-11-06T15:00:00+00:00", "age_hours": 0, "stale": False}


# --- команда backup-note

@pytest.fixture
def base(tmp_path: Path, monkeypatch) -> Database:
    """База со схемой; переменные libpq указывают на неё – так команду получает образ приложения."""
    database = Database(tmp_path / "triage.db")
    parts = psycopg.conninfo.conninfo_to_dict(conninfo_of(database_for_path(tmp_path / "triage.db")))
    for key, env in (("host", "PGHOST"), ("port", "PGPORT"), ("user", "PGUSER"), ("password", "PGPASSWORD"), ("dbname", "PGDATABASE")):
        monkeypatch.setenv(env, str(parts[key]))
    yield database
    database.close()


def test_backup_note_command_writes_one_settings_row_and_replaces_it(base: Database, capsys):
    assert base.last_checked_backup() is None
    tables = base._scalar("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema()")
    assert tools.main(["backup-note", "--name", NAME, "--checked-at", "2026-11-04T03:01:15Z"]) == 0
    answer = json.loads(capsys.readouterr().out)
    expected = {"name": NAME, "checked_at": "2026-11-04T03:01:15+00:00"}
    assert answer == {BACKUP_NOTE_KEY: expected} and base.last_checked_backup() == expected
    assert tools.main(["backup-note", "--name", "triage-20261105-030000.dump", "--checked-at", "2026-11-05T06:01:15+03:00"]) == 0
    assert base.last_checked_backup() == {"name": "triage-20261105-030000.dump", "checked_at": "2026-11-05T03:01:15+00:00"}
    rows = base._all("SELECT key, value_json FROM settings WHERE key = ?", (BACKUP_NOTE_KEY,))
    assert len(rows) == 1 and json.loads(rows[0]["value_json"]) == base.last_checked_backup()
    assert base._scalar("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema()") == tables, "схема та же"
    assert BACKUP_NOTE_KEY not in Settings().with_stored(base.get_settings()).__dict__, "настройкой приложения отметка не становится"


@pytest.mark.parametrize(("name", "moment"), [("../triage-20261104-030000.dump", "2026-11-04T03:01:15Z"),
                                              ("triage-20261104-030000.dump.json", "2026-11-04T03:01:15Z"),
                                              ("triage-2026-11-04.dump", "2026-11-04T03:01:15Z"),
                                              (NAME, "04.11.2026 03:01"), (NAME, "")])
def test_backup_note_command_refuses_other_names_and_times(base: Database, capsys, name: str, moment: str):
    assert tools.main(["backup-note", "--name", name, "--checked-at", moment]) == 2
    assert "error" in json.loads(capsys.readouterr().out)
    assert base.last_checked_backup() is None, "в базу ничего не записано"


def test_spoiled_note_reads_as_no_note(base: Database):
    for value in ("не JSON", '"строка"', "[1, 2]"):
        with base._tx() as c:
            c.execute("INSERT INTO settings(key, value_json, updated_at) VALUES (?, ?, '2026-01-01') ON CONFLICT(key) DO UPDATE"
                      " SET value_json = excluded.value_json", (BACKUP_NOTE_KEY, value))
        assert base.last_checked_backup() is None, value


# --- /healthz

def settings_for(tmp_path: Path, maintenance: bool = False) -> Settings:
    return Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "repos", maintenance=maintenance)


def write_note(settings: Settings, moment: datetime) -> None:
    tools.backup_note(NAME, moment.isoformat(timespec="seconds"), conninfo_of(database_for_path(settings.db_path)))


def test_healthz_shows_age_of_the_last_checked_copy(tmp_path: Path):
    (tmp_path / "repos").mkdir()
    settings = settings_for(tmp_path)
    with TestClient(create_app(settings), base_url=BASE) as client:
        first = client.get("/healthz")
        assert first.status_code == 200 and first.json()["status"] == "ok" and first.json()["backup"] == EMPTY
        checked = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=3, minutes=20)
        write_note(settings, checked)
        fresh = client.get("/healthz")
        assert fresh.status_code == 200 and fresh.json()["status"] == "ok"
        assert fresh.json()["backup"] == {"checked_at": checked.isoformat(timespec="seconds"), "age_hours": 3, "stale": False}
        write_note(settings, checked - timedelta(days=3))
        old = client.get("/healthz")
        assert old.status_code == 200 and old.json()["status"] == "ok", "давняя копия готовность не меняет"
        assert old.json()["backup"]["age_hours"] == 75 and old.json()["backup"]["stale"] is True


def test_healthz_keeps_status_of_pause_and_maintenance_beside_backup(tmp_path: Path):
    (tmp_path / "repos").mkdir()
    settings = settings_for(tmp_path)
    with TestClient(create_app(settings), base_url=BASE) as client:
        write_note(settings, datetime.now(UTC) - timedelta(hours=1))
        client.app.state.db.set_hub_write_paused(True)
        paused = client.get("/healthz")
        assert paused.status_code == 200 and paused.json()["status"] == "hub_write_paused"
        assert paused.json()["backup"]["age_hours"] == 1 and paused.json()["backup"]["stale"] is False
        client.app.state.db.set_hub_write_paused(False)
    with TestClient(create_app(settings_for(tmp_path, maintenance=True)), base_url=BASE) as client:
        answer = client.get("/healthz")
        assert answer.status_code == 200 and answer.json()["status"] == "maintenance"
        assert answer.json()["backup"]["stale"] is False


def test_healthz_reports_unavailable_base_when_the_note_cannot_be_read(tmp_path: Path, monkeypatch):
    """База перестала отвечать после проверки готовности: ответ тот же, что у самой проверки, – 503 database_unavailable."""
    (tmp_path / "repos").mkdir()
    with TestClient(create_app(settings_for(tmp_path)), base_url=BASE) as client:
        def busy():
            raise DatabaseBusy("база занята")
        monkeypatch.setattr(client.app.state.db, "last_checked_backup", busy)
        answer = client.get("/healthz")
        assert answer.status_code == 503 and answer.json()["status"] == "database_unavailable"
        assert "backup" not in answer.json()
