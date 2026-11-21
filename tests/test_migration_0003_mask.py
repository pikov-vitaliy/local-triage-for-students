"""Настоящая миграция 0003 (схема 34 -> 35, ADR-0141): существующий проект схемы 34 получает показ с масками, данные целы,
запись шага и версии на месте, база открывается сборкой схемы 35 (ревью dev14, круг 1). Данные выдуманные."""

from __future__ import annotations

import shutil
from pathlib import Path

import psycopg
import pytest
from db_support import empty_database

from app.db import SCHEMA_VERSION, Database
from app.storage import migrate


def upto(tmp_path: Path, real: Path, last: int) -> Path:
    """Копия настоящих шагов 0001..last: проверка одного шага не зависит от более поздних миграций (схема 36)."""
    folder = tmp_path / f"migrations-upto-{last:04d}"
    folder.mkdir(exist_ok=True)
    for path in sorted(real.glob("*.sql")):
        if int(path.name[:4]) <= last:
            shutil.copy2(path, folder / path.name)
    return folder


def test_real_step_0003_upgrades_schema_34_project_with_masks(tmp_path: Path, monkeypatch):
    target = empty_database()
    real = migrate.MIGRATIONS_DIR
    old = tmp_path / "migrations-34"
    old.mkdir()
    for name in ("0001_baseline.sql", "0002_feeds_and_secrets.sql"):
        shutil.copy2(real / name, old / name)
    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", old)
    with psycopg.connect(target, autocommit=True) as conn:
        with conn.transaction():  # как новая база у Database._upgrade
            migrate.apply_baseline(conn, mark="%s")
            conn.execute("INSERT INTO meta(key, value) VALUES ('schema_version', %s)", (str(migrate.BASELINE_SCHEMA),))
            conn.execute("INSERT INTO meta(key, value) VALUES ('journal_installation', 'тест')")
            conn.execute("INSERT INTO schema_version(version, applied_at, note) VALUES (%s, %s, 'новая база')",
                         (migrate.BASELINE_SCHEMA, "2026-11-01T00:00:00+00:00"))
        assert migrate.apply_pending(conn) == ["0002_feeds_and_secrets.sql"]
        assert conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0] == "34"
        columns = {r[0] for r in conn.execute("SELECT column_name FROM information_schema.columns "
                                              "WHERE table_schema = current_schema() AND table_name = 'projects'")}
        assert "mask_secrets" not in columns, "схема 34 – без столбца"
        conn.execute("INSERT INTO projects(name, created_at, updated_at, model) VALUES ('Прежний проект', "
                     "'2026-11-01T00:00:00+00:00', '2026-11-01T00:00:00+00:00', 'демо-модель')")

    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", upto(tmp_path, real, 3))
    with psycopg.connect(target, autocommit=True) as conn:
        assert [m.name for m in migrate.pending(conn)] == ["0003_project_mask_display.sql"]
        assert migrate.apply_pending(conn) == ["0003_project_mask_display.sql"]
        assert migrate.apply_pending(conn) == []
        assert conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0] == "35"
        assert conn.execute("SELECT schema_version FROM storage_migrations WHERE number = 3").fetchone()[0] == 35
        assert conn.execute("SELECT note FROM schema_version WHERE version = 35").fetchone()[0] == "0003_project_mask_display.sql"
        row = conn.execute("SELECT name, model, mask_secrets FROM projects").fetchone()
        assert row == ("Прежний проект", "демо-модель", 1), row

    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", real)
    with psycopg.connect(target, autocommit=True) as conn:  # следующие шаги – до текущей схемы
        migrate.apply_pending(conn)
        assert conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0] == str(SCHEMA_VERSION)
    db = Database(target)  # текущая сборка открывает обновлённую базу: структура совпадает
    try:
        pid = int(db._scalar("SELECT MIN(id) FROM projects"))
        assert db.get_project(pid)["mask_secrets"] == 1
        db.update_project(pid, mask_secrets=False)
        assert db.get_project(pid)["mask_secrets"] == 0
    finally:
        db.close()


def test_real_step_0003_failure_after_ddl_rolls_back_and_retries(tmp_path: Path, monkeypatch):
    """Сбой настоящего шага 0003 после выполненного DDL (при записи версии) откатывает и добавленный столбец: схема 34,
    данные и записи шагов прежние; после устранения причины шаг применяется (ревью Codex dev14, круг 2)."""
    target = empty_database()
    real = migrate.MIGRATIONS_DIR
    old = tmp_path / "migrations-34"
    old.mkdir()
    for name in ("0001_baseline.sql", "0002_feeds_and_secrets.sql"):
        shutil.copy2(real / name, old / name)
    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", old)
    with psycopg.connect(target, autocommit=True) as conn:
        with conn.transaction():
            migrate.apply_baseline(conn, mark="%s")
            conn.execute("INSERT INTO meta(key, value) VALUES ('schema_version', %s)", (str(migrate.BASELINE_SCHEMA),))
            conn.execute("INSERT INTO schema_version(version, applied_at, note) VALUES (%s, %s, 'новая база')",
                         (migrate.BASELINE_SCHEMA, "2026-11-01T00:00:00+00:00"))
        migrate.apply_pending(conn)
        conn.execute("INSERT INTO projects(name, created_at, updated_at) VALUES ('Прежний', 'x', 'x')")
        # сбой при записи версии 35 – уже после ALTER TABLE шага
        conn.execute("CREATE FUNCTION test_fail_35() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
                     "IF NEW.version = 35 THEN RAISE EXCEPTION 'тестовый сбой записи версии'; END IF; RETURN NEW; END $$")
        conn.execute("CREATE TRIGGER test_fail_35 BEFORE INSERT ON schema_version FOR EACH ROW EXECUTE FUNCTION test_fail_35()")
    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", upto(tmp_path, real, 3))
    with psycopg.connect(target, autocommit=True) as conn:
        with pytest.raises(psycopg.Error):
            migrate.apply_pending(conn)
        columns = {r[0] for r in conn.execute("SELECT column_name FROM information_schema.columns "
                                              "WHERE table_schema = current_schema() AND table_name = 'projects'")}
        assert "mask_secrets" not in columns, "добавленный столбец откатился вместе с шагом"
        assert conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0] == "34"
        assert conn.execute("SELECT COUNT(*) FROM storage_migrations WHERE number = 3").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM schema_version WHERE version = 35").fetchone()[0] == 0
        assert conn.execute("SELECT name FROM projects").fetchone()[0] == "Прежний"
        conn.execute("DROP TRIGGER test_fail_35 ON schema_version")
        conn.execute("DROP FUNCTION test_fail_35()")
        assert migrate.apply_pending(conn) == ["0003_project_mask_display.sql"]
        assert conn.execute("SELECT mask_secrets FROM projects").fetchone()[0] == 1
