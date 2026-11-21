"""Правило ADR-0133: локальные базы данных не используются. В папке данных – только журнал обмена с моделью
и телеметрия, всё остальное в PostgreSQL. Этот файл держит правило и проверяет перенос файлов состояния."""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

import pytest

from app.config import Settings
from app.feeds import FeedStore
from app.main import create_app
from app.storage import local_state
from db_support import conninfo_of, database_for_path
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
SQLITE_ALLOWED = {"app/telemetry.py", "app/storage/local_state.py"}
ALLOWED_IN_DATA = {"telemetry", "telemetry.db", "telemetry.db-wal", "telemetry.db-shm", "model-traffic"}


def app_files() -> list[Path]:
    return sorted((ROOT / "app").rglob("*.py"))


def test_sqlite_only_in_telemetry_and_local_state_import():
    """Появится ещё где-то – сборка не пройдёт. Инструмент переноса основной базы из SQLite удалён в 0.10.0.dev8."""
    used = {p.relative_to(ROOT).as_posix() for p in app_files() if re.search(r"^\s*(import sqlite3|from sqlite3)", p.read_text(encoding="utf-8"), re.M)}
    assert used == SQLITE_ALLOWED


def test_data_dir_is_used_only_for_journal_telemetry_and_local_state_import():
    """Новое хранение состояния в папке данных не заводится (ADR-0133)."""
    allowed = {"app/config.py", "app/main.py", "app/routes/common.py", "app/triage.py", "app/settings_store.py", "app/storage/local_state.py", "app/storage/tools.py", "app/telemetry.py", "app/lockfile.py"}
    used = {p.relative_to(ROOT).as_posix() for p in app_files() if "data_dir" in p.read_text(encoding="utf-8")}
    assert used <= allowed, used - allowed
    main = (ROOT / "app/main.py").read_text(encoding="utf-8")
    joined = re.findall(r"settings\.data_dir\s*/\s*['\"]([^'\"]+)['\"]", main)
    assert set(joined) == {"telemetry"}, joined
    text = "\n".join(p.read_text(encoding="utf-8") for p in app_files() if p.name != "local_state.py")
    for name in ("feeds.db", "mask.key", "hub-worker.key", "instance.lock\""):
        assert f'"{name}' not in text or name == 'instance.lock"', name


def test_backups_are_not_in_git_or_image():
    for name in (".gitignore", ".dockerignore"):
        lines = {line.strip().rstrip("/") for line in (ROOT / name).read_text(encoding="utf-8").splitlines()}
        assert "backups" in lines and "data" in lines, name


@pytest.fixture
def stand(tmp_path: Path):
    """Папка данных с прежними файлами и база новой схемы."""
    data = tmp_path / "data"
    data.mkdir()
    conninfo = conninfo_of(database_for_path(data / "triage.db"))
    return data, conninfo


def write_files(data: Path) -> dict:
    (data / "mask.key").write_bytes(bytes(range(32)))
    (data / "hub-worker.key").write_text("a" * 64, encoding="ascii")
    (data / "providers").mkdir()
    entry = {"version": 1, "key": "k" * 20, "base_url": "http://model.example", "addresses": []}
    (data / "providers" / "7.key").write_text(json.dumps(entry), encoding="ascii")
    con = sqlite3.connect(data / "feeds.db")
    con.executescript("""
        CREATE TABLE feed_meta (kind TEXT PRIMARY KEY, filename TEXT NOT NULL, loaded_at TEXT NOT NULL, records INTEGER NOT NULL,
            version TEXT NOT NULL DEFAULT '', source_date TEXT NOT NULL DEFAULT '', xml_bytes INTEGER NOT NULL DEFAULT 0,
            seconds REAL NOT NULL DEFAULT 0, ref_records INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE bdu (id TEXT PRIMARY KEY, data_json TEXT NOT NULL);
        CREATE TABLE bdu_cve (cve TEXT NOT NULL, bdu_id TEXT NOT NULL, PRIMARY KEY (cve, bdu_id)) WITHOUT ROWID;
        CREATE TABLE cwe (id TEXT PRIMARY KEY, data_json TEXT NOT NULL);
        CREATE TABLE cwe_index (id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL, abstraction TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT '');
    """)
    record = {"id": "BDU:2099-00001", "cves": ["CVE-2099-0001"], "name": "Тест"}
    con.execute("INSERT INTO feed_meta VALUES ('bdu','vulxml.zip','2026-10-18T10:00:00+00:00',1,'','2026-10-01',123,1.5,0)")
    con.execute("INSERT INTO bdu VALUES (?, ?)", (record["id"], json.dumps(record, ensure_ascii=False)))
    con.execute("INSERT INTO bdu_cve VALUES ('CVE-2099-0001', ?)", (record["id"],))
    con.execute("INSERT INTO cwe VALUES ('CWE-79', '{\"id\": \"CWE-79\", \"name\": \"XSS\", \"attack_patterns\": [\"CAPEC-209\"]}')")
    con.execute("INSERT INTO cwe_index VALUES ('CWE-79', 'weakness', 'XSS', 'Base', 'Stable')")
    con.commit()
    con.close()
    return entry


def open_store(conninfo: str):
    from app.db import Database
    db = Database(conninfo)
    return db, FeedStore(db.store)


def test_import_verify_and_work_without_files(stand):
    data, conninfo = stand
    entry = write_files(data)
    report = local_state.import_all(data, conninfo)
    assert report["imported"] and all(item["same"] for item in report["feeds"].values())
    assert report["feeds"]["bdu"] == {"source": 1, "target": 1, "same": True}
    assert "a" * 64 not in json.dumps(report), "значения ключей в ответ не попадают"
    checked = local_state.verify(data, conninfo)
    assert checked["ok"] and checked["keys_with_files"]["mask_key"] == "same" and checked["feeds_compared_with_file"]
    # файлы удалены: всё на месте, ключи те же
    for path in sorted(data.rglob("*"), reverse=True):
        path.rmdir() if path.is_dir() else path.unlink()
    assert local_state.verify(data, conninfo)["ok"]
    db, store = open_store(conninfo)
    try:
        assert db.mask_key() == bytes(range(32))
        assert db.secret(local_state.WORKER_SECRET) == "a" * 64
        from app.provider_keys import load_key
        assert load_key(db, 7) == {"key": entry["key"], "base_url": entry["base_url"], "addresses": []}
        assert store.bdu_by_cve(["CVE-2099-0001"])["CVE-2099-0001"][0]["name"] == "Тест"
        assert store.status()["bdu"]["seconds"] == 1.5 and store.status()["bdu"]["xml_bytes"] == 123
        assert store.cwe_list()[0]["id"] == "CWE-79"
        assert store.capec_for_cwes(["CWE-79"])["CAPEC-209"]["sources"] == ["CWE"], "пары строятся, если их таблицы в файле нет"
    finally:
        store.close()
        db.close()


def test_import_is_not_repeated_and_does_not_touch_files(stand):
    data, conninfo = stand
    write_files(data)
    before = {p.name: p.read_bytes() for p in data.iterdir() if p.is_file()}
    assert local_state.import_all(data, conninfo)["imported"]
    assert local_state.import_all(data, conninfo)["imported"] is False
    assert before == {p.name: p.read_bytes() for p in data.iterdir() if p.is_file()}, "файлы удаляет только владелец"


def test_different_key_stops_import_without_showing_values(stand):
    data, conninfo = stand
    write_files(data)
    db, store = open_store(conninfo)
    try:
        db.put_secret(local_state.MASK_SECRET, "ff" * 32)
    finally:
        store.close()
        db.close()
    with pytest.raises(local_state.LocalStateError) as caught:
        local_state.import_all(data, conninfo)
    assert "mask_key" in str(caught.value) and "ff" * 32 not in str(caught.value) and bytes(range(32)).hex() not in str(caught.value)
    db, store = open_store(conninfo)
    try:
        assert db.secret(local_state.MARKER) is None and store.status() == {}, "база не изменилась"
    finally:
        store.close()
        db.close()


def test_damaged_file_stops_import(stand):
    data, conninfo = stand
    write_files(data)
    (data / "mask.key").write_bytes(b"short")
    with pytest.raises(local_state.LocalStateError, match="повреждён"):
        local_state.import_all(data, conninfo)


def test_verify_notices_changed_row(stand):
    data, conninfo = stand
    write_files(data)
    local_state.import_all(data, conninfo)
    con = sqlite3.connect(data / "feeds.db")
    con.execute("UPDATE cwe_index SET name = 'Другое'")
    con.commit()
    con.close()
    answer = local_state.verify(data, conninfo)
    assert not answer["ok"] and answer["feeds"]["cwe_index"]["same"] is False


def test_nul_in_source_stops_import(stand):
    data, conninfo = stand
    write_files(data)
    con = sqlite3.connect(data / "feeds.db")
    con.execute("UPDATE cwe_index SET name = 'A' || char(0) || 'B'")
    con.commit()
    con.close()
    with pytest.raises(local_state.LocalStateError, match="NUL"):
        local_state.import_all(data, conninfo)
    db, store = open_store(conninfo)
    try:
        assert db.secret(local_state.MARKER) is None and store.status() == {}, "база не изменилась"
    finally:
        store.close()
        db.close()


def test_interrupted_import_is_found_and_continued(stand):
    """Миграция прошла, перенос оборвался: состояние ok, перенос нужен; продолжение штатной командой."""
    data, conninfo = stand
    assert local_state.pending(data, conninfo) is False, "новая установка: файлов нет"
    write_files(data)
    assert local_state.pending(data, conninfo) is True
    local_state.import_all(data, conninfo)
    assert local_state.pending(data, conninfo) is False


def test_import_into_empty_base_after_lost_volume(tmp_path: Path):
    """Том базы утрачен, начинают с пустой базы, файлы состояния ещё лежат: схема создаётся, ключи и справочники переносятся."""
    from db_support import empty_database
    data = tmp_path / "data"
    data.mkdir()
    write_files(data)
    conninfo = empty_database()
    report = local_state.import_all(data, conninfo)
    assert report["imported"] and report["feeds"]["bdu"]["same"]
    assert local_state.verify(data, conninfo)["ok"] and local_state.pending(data, conninfo) is False


def test_start_continues_import_on_current_schema():
    start = (ROOT / "start.ps1").read_bytes().decode("utf-8-sig")
    migrate = start.index("Invoke-StorageTool $base @('migrate')")
    pending = start.index("if ($schema.local_state_pending)")
    assert migrate < pending < start.index("Invoke-StorageTool $base @('local-state-import')") < start.index("Invoke-StorageTool $base @('local-state-verify')") \
        < start.index("& docker @compose up -d --no-build"), "перенос и сверка – после миграции и до запуска, отдельно от неё"
    assert "backup-db.ps1" in start[:migrate] and start.index("backup-db.ps1') -Check") < migrate


def settings_for(data: Path) -> Settings:
    return Settings(data_dir=data, repos_root=data.parent / "repos", ollama_url="http://127.0.0.1:9", osv_url="", team_name="Команда",
                    tmp_root=data.parent / "scratch")


def test_app_refuses_to_start_when_files_are_not_imported(stand):
    data, conninfo = stand
    write_files(data)
    with pytest.raises(RuntimeError, match="local-state-import"):
        with TestClient(create_app(settings_for(data))):
            pass


def test_app_runs_with_only_journal_and_telemetry_in_data(stand):
    """В папке данных только журнал и телеметрия, ключи не меняются от перезапуска, файлы состояния не появляются."""
    data, conninfo = stand
    write_files(data)
    local_state.import_all(data, conninfo)
    for path in sorted(data.rglob("*"), reverse=True):
        path.rmdir() if path.is_dir() else path.unlink()
    keys = []
    for _ in range(2):
        app = create_app(settings_for(data))
        with TestClient(app, base_url="http://127.0.0.1:8765") as client:
            assert client.get("/healthz").status_code == 200
            assert client.get("/feeds").status_code == 200
            keys.append((app.state.hub_worker_key, app.state.db.mask_key()))
        left = {p.name for p in data.iterdir()}
        assert left <= ALLOWED_IN_DATA, left - ALLOWED_IN_DATA
    assert keys[0] == keys[1] == ("a" * 64, bytes(range(32)))


def test_new_installation_creates_keys_once(stand):
    data, conninfo = stand
    db, store = open_store(conninfo)
    try:
        first = db.mask_key()
        assert db.mask_key() == first and len(first) == 32
        assert db.ensure_secret("x", lambda: "1") == db.ensure_secret("x", lambda: "2") == "1"
        db.put_secret("x", "3")
        assert db.secret("x") == "3" and db.drop_secret("x") and not db.drop_secret("x") and db.secret("x") is None
    finally:
        store.close()
        db.close()


def test_damaged_mask_key_is_not_replaced(stand):
    data, conninfo = stand
    db, store = open_store(conninfo)
    try:
        db.put_secret(local_state.MASK_SECRET, "не шестнадцатеричное")
        with pytest.raises(ValueError, match="повреждён"):
            db.mask_key()
        assert db.secret(local_state.MASK_SECRET) == "не шестнадцатеричное"
    finally:
        store.close()
        db.close()
