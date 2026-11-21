"""Миграции схемы PostgreSQL (ADR-0128, раздел 7): шаг применяется один раз с записью, упавший шаг откатывается и данные целы,
изменённый файл, пропуск номера и база новее сборки – отказ."""

from __future__ import annotations

from pathlib import Path

import psycopg
import pytest
from db_support import empty_database

from app.db import Database
from app.storage import migrate
from app.storage import schema as manifest


@pytest.fixture
def target() -> str:
    return empty_database()


@pytest.fixture
def steps(tmp_path: Path, monkeypatch) -> Path:
    """Папка миграций с одной базовой схемой, сборка – схемы 33: шаги теста начинаются с 0002 и схемы 34 и не зависят от настоящих
    файлов миграций."""
    folder = tmp_path / "migrations"
    folder.mkdir()
    (folder / migrate.BASELINE.name).write_bytes(migrate.BASELINE.read_bytes())
    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", folder)
    monkeypatch.setattr("app.db.SCHEMA_VERSION", migrate.BASELINE_SCHEMA)
    monkeypatch.setattr(manifest, "SCHEMA_VERSION", migrate.BASELINE_SCHEMA)
    return folder


def migrated_base(target: str) -> None:
    Database(target).close()


def tables_of(conn: psycopg.Connection) -> set[str]:
    return {row[0] for row in conn.execute(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'")}


def test_migration_applies_once_with_record(steps: Path, target: str):
    migrated_base(target)
    (steps / "0002_add.sql").write_text("-- schema: 34\nCREATE TABLE новая (a BIGINT);\nINSERT INTO новая VALUES (1);\n", encoding="utf-8")
    with psycopg.connect(target, autocommit=True) as conn:
        assert [item.name for item in migrate.pending(conn)] == ["0002_add.sql"]
        assert migrate.apply_pending(conn) == ["0002_add.sql"]
        assert migrate.apply_pending(conn) == [], "второй раз нечего применять"
        assert conn.execute("SELECT COUNT(*) FROM новая").fetchone()[0] == 1
        assert conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0] == "34"
        assert conn.execute("SELECT schema_version FROM storage_migrations WHERE number = 2").fetchone()[0] == 34
        assert conn.execute("SELECT note FROM schema_version WHERE version = 34").fetchone()[0] == "0002_add.sql"


def test_failed_migration_rolls_back_and_keeps_data_and_sequences(steps: Path, target: str):
    db = Database(target)
    project = db.create_project("есть")
    db.close()
    (steps / "0002_good.sql").write_text("-- schema: 34\nCREATE TABLE хорошая (a BIGINT);\n", encoding="utf-8")
    (steps / "0003_bad.sql").write_text("-- schema: 35\nCREATE TABLE плохая (a BIGINT);\nDELETE FROM projects;\nSELECT нет_такой_колонки FROM meta;\n", encoding="utf-8")
    with psycopg.connect(target, autocommit=True) as conn:
        with pytest.raises(psycopg.Error):
            migrate.apply_pending(conn)
        tables = tables_of(conn)
        assert "хорошая" in tables and "плохая" not in tables, "откатывается только упавший шаг"
        assert conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0] == "34"
        assert conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == 1
        assert [item.name for item in migrate.pending(conn)] == ["0003_bad.sql"]
    assert project


def test_changed_applied_migration_and_gap_are_refused(steps: Path, target: str):
    migrated_base(target)
    path = steps / "0002_add.sql"
    path.write_text("-- schema: 34\nCREATE TABLE новая (a BIGINT);\n", encoding="utf-8")
    with psycopg.connect(target, autocommit=True) as conn:
        migrate.apply_pending(conn)
        path.write_text("-- schema: 34\nCREATE TABLE новая (b BIGINT);\n", encoding="utf-8")
        with pytest.raises(migrate.MigrationError, match="изменён"):
            migrate.pending(conn)
        path.write_text("-- schema: 34\nCREATE TABLE новая (a BIGINT);\n", encoding="utf-8")
        (steps / "0004_gap.sql").write_text("-- schema: 36\n", encoding="utf-8")
        with pytest.raises(migrate.MigrationError, match="Пропущен"):
            migrate.pending(conn)
        (steps / "0004_gap.sql").unlink()
        (steps / "0003_noline.sql").write_text("CREATE TABLE x (a BIGINT);\n", encoding="utf-8")
        with pytest.raises(migrate.MigrationError, match="Первая строка"):
            migrate.pending(conn)


def test_schema_numbers_must_follow_in_order(steps: Path, target: str):
    migrated_base(target)
    (steps / "0002_add.sql").write_text("-- schema: 35\nCREATE TABLE новая (a BIGINT);\n", encoding="utf-8")
    with psycopg.connect(target, autocommit=True) as conn:
        with pytest.raises(migrate.MigrationError, match="по порядку"):
            migrate.pending(conn)
        assert "новая" not in tables_of(conn)


def test_base_newer_than_files_is_refused(steps: Path, target: str):
    migrated_base(target)
    with psycopg.connect(target, autocommit=True) as conn:
        conn.execute("INSERT INTO storage_migrations(number, schema_version, checksum, applied_at) VALUES (9, 40, 'x', 'x')")
        with pytest.raises(migrate.MigrationError, match="новее"):
            migrate.pending(conn)


def test_new_base_gets_baseline_and_all_migrations_once(steps: Path, target: str, monkeypatch):
    """Новая база не должна получить следующую миграцию второй раз: она записана как применённая."""
    import app.db as db_module
    (steps / "0002_add.sql").write_text("-- schema: 34\nCREATE TABLE новая (a BIGINT);\n", encoding="utf-8")
    monkeypatch.setattr(db_module, "SCHEMA_VERSION", 34)
    db = Database(target)
    db.close()
    with psycopg.connect(target, autocommit=True) as conn:
        assert "новая" in tables_of(conn)
        assert migrate.pending(conn) == []
        assert conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0] == "34"
        assert [r[0] for r in conn.execute("SELECT version FROM schema_version ORDER BY 1")] == [33, 34]


def test_application_refuses_base_before_migration(steps: Path, target: str):
    migrated_base(target)
    with psycopg.connect(target, autocommit=True) as conn:
        conn.execute("UPDATE meta SET value = '32' WHERE key = 'schema_version'")
    with pytest.raises(RuntimeError, match="Схема базы 32"):
        Database(target)
