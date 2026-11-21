"""Настоящая миграция 0004 (схема 35 -> 36, план dev17, п. 4.1): база схемы 35 с данными получает колонки идентичности
пакета, origin_ref исследований заполнен прежним input_ref, данные целы, повтор ничего не меняет, архив удаляется вместе
с проектом; сборка схемы 36 открывает обновлённую базу. Данные выдуманы."""

from __future__ import annotations

from pathlib import Path

import psycopg
from db_support import empty_database
from test_migration_0003_mask import upto

from app.db import SCHEMA_VERSION, Database
from app.storage import migrate


def _base_35(target: str, tmp_path: Path, monkeypatch, real: Path) -> None:
    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", upto(tmp_path, real, 3))
    with psycopg.connect(target, autocommit=True) as conn:
        with conn.transaction():  # как новая база у Database._upgrade
            migrate.apply_baseline(conn, mark="%s")
            conn.execute("INSERT INTO meta(key, value) VALUES ('schema_version', %s)", (str(migrate.BASELINE_SCHEMA),))
            conn.execute("INSERT INTO meta(key, value) VALUES ('journal_installation', 'тест')")
            conn.execute("INSERT INTO schema_version(version, applied_at, note) VALUES (%s, %s, 'новая база')",
                         (migrate.BASELINE_SCHEMA, "2026-11-01T00:00:00+00:00"))
        migrate.apply_pending(conn)
        assert conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0] == "35"
        pid = conn.execute("INSERT INTO projects(name, created_at, updated_at, model) VALUES ('Прежний', "
                           "'2026-11-01T00:00:00+00:00', '2026-11-01T00:00:00+00:00', 'демо') RETURNING id").fetchone()[0]
        imp = conn.execute("INSERT INTO imports(project_id, filename, format, created_at) VALUES "
                           "(%s, 'demo.xlsx', 'hub', '2026-11-01') RETURNING id", (pid,)).fetchone()[0]
        conn.execute("INSERT INTO findings(project_id, hub_id, import_id, pos, kind, data_json) VALUES "
                     "(%s, '73001', %s, 1, 'SCA', %s)",
                     (pid, imp, '{"hub_id": "73001", "kind": "SCA", "component": "spring-core", "build_type": "npm"}'))
        task = conn.execute("INSERT INTO sca2_tasks(project_id, import_id, task_id, contract, answer_contract, "
                            "validator_version, manifest_sha256, created_at, updated_at) VALUES (%s, %s, 't1', 'c', "
                            "'a', 'v', 'm', '2026-11-01', '2026-11-01') RETURNING id", (pid, imp)).fetchone()[0]
        conn.execute("INSERT INTO sca2_research(project_id, task_id, input_ref, revision, answer_sig, imported_at) VALUES "
                     "(%s, %s, 'npm|spring-core|5.3.1', 1, 'a1', '2026-11-01')", (pid, task))
        conn.execute("INSERT INTO sca_set_members(project_id, hub_id, input_ref, set_no, updated_at) VALUES "
                     "(%s, '73001', 'npm|spring-core|5.3.1', 0, '2026-11-01')", (pid,))


def test_real_step_0004_upgrades_schema_35_with_data(tmp_path: Path, monkeypatch):
    target = empty_database()
    real = migrate.MIGRATIONS_DIR
    _base_35(target, tmp_path, monkeypatch, real)
    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", real)
    with psycopg.connect(target, autocommit=True) as conn:
        before = conn.execute("SELECT data_json FROM findings").fetchall()
        assert [m.name for m in migrate.pending(conn)] == ["0004_package_identity.sql"]
        assert migrate.apply_pending(conn) == ["0004_package_identity.sql"]
        assert migrate.apply_pending(conn) == []
        assert conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0] == str(SCHEMA_VERSION)
        assert SCHEMA_VERSION == 36
        assert conn.execute("SELECT schema_version FROM storage_migrations WHERE number = 4").fetchone()[0] == 36
        assert conn.execute("SELECT note FROM schema_version WHERE version = 36").fetchone()[0] == \
            "0004_package_identity.sql"
        row = conn.execute("SELECT pkg_ecosystem, pkg_name, pkg_source, pkg_note, pkg_scope, pkg_rev FROM findings")\
            .fetchone()
        assert row == ("", "", "", "", "", 0), "миграция данных идентичности не заполняет"
        assert conn.execute("SELECT data_json FROM findings").fetchall() == before
        assert conn.execute("SELECT identity_rev FROM projects").fetchone()[0] == 0
        assert conn.execute("SELECT origin_ref, input_ref FROM sca2_research").fetchone() == \
            ("npm|spring-core|5.3.1", "npm|spring-core|5.3.1")
        assert conn.execute("SELECT pending_reason FROM sca_set_members").fetchone()[0] == ""
        assert conn.execute("SELECT COUNT(*) FROM sca_identity_archive").fetchone()[0] == 0
    db = Database(target)  # сборка схемы 36 открывает обновлённую базу: структура совпадает
    try:
        pid = int(db._scalar("SELECT MIN(id) FROM projects"))
        with db._tx() as c:
            c.execute("INSERT INTO sca_identity_archive(project_id, archived_at, source_table, key_json, row_json) "
                      "VALUES (?, '2026-11-09', 'sca_answers', '{}', '{}')", (pid,))
        assert db._scalar("SELECT COUNT(*) FROM sca_identity_archive") == 1
        assert db.delete_project(pid)
        assert db._scalar("SELECT COUNT(*) FROM sca_identity_archive") == 0, "архив удаляется вместе с проектом"
    finally:
        db.close()


def test_new_database_has_schema_36_layout(tmp_path: Path):
    db = Database(empty_database())
    try:
        cols = {r["column_name"] for r in db._all("SELECT column_name FROM information_schema.columns WHERE "
                                                  "table_schema = current_schema() AND table_name = 'findings'")}
        assert {"pkg_ecosystem", "pkg_name", "pkg_source", "pkg_note", "pkg_scope", "pkg_rev"} <= cols
        assert db._scalar("SELECT value FROM meta WHERE key = 'schema_version'") == "36"
    finally:
        db.close()
