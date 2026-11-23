"""Команды обслуживания основной базы (ADR-0128, разделы 7–9): python -m app.storage.tools <команда>.

Адрес базы – переменные libpq, как у приложения. Ответ – JSON в stdout; код выхода 0 – успех, 1 – проверка не пройдена, 2 – ошибка
работы. Копии и восстановление выполняются клиентами образа базы: scripts/backup-db.ps1, restore-db.ps1, restore-check.ps1.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import psycopg

from app import i18n
from app.storage import local_state, migrate
from app.storage import schema as manifest


class ToolError(RuntimeError):
    """Команда не выполнена: база не менялась."""


def status(conninfo: str = "") -> dict:
    """Что с базой: empty – пустая, ok – схема этой сборки, migrate – нужны миграции, newer – база новее сборки, foreign – в базе
    нет версии схемы приложения."""
    with psycopg.connect(conninfo, autocommit=True) as conn:
        tables = {row[0] for row in conn.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'")}
        if not tables:
            # том утрачен, а файлы состояния ещё лежат: ключи и справочники переносятся в новую базу (ADR-0133)
            return {"state": "empty", "schema": None, "expected": manifest.SCHEMA_VERSION, "pending": [],
                    "local_state_pending": bool(local_state.legacy_files(Path(os.environ.get("DATA_DIR") or "/data")))}
        row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone() if "meta" in tables else None
        schema = int(row[0]) if row else None
        pending = [item.name for item in migrate.pending(conn)]
    if schema is None:
        state = "foreign"
    elif schema > manifest.SCHEMA_VERSION:
        state = "newer"
    elif pending or schema < manifest.SCHEMA_VERSION:
        state = "migrate"
    else:
        state = "ok"
    answer = {"state": state, "schema": schema, "expected": manifest.SCHEMA_VERSION, "pending": pending, "local_state_pending": False}
    if state == "ok":
        answer["local_state_pending"] = local_state.pending(Path(os.environ.get("DATA_DIR") or "/data"), conninfo)
    return answer


def _existing_database(conninfo: str):
    """Database создал бы схему в пустой базе: на пустой базе команда отказывает и оставляет её пустой."""
    from app.db import Database
    if status(conninfo)["state"] == "empty":
        raise ToolError(i18n._("База пуста: команда выполняется на существующей базе."))
    return Database(conninfo or None)


def set_pause(paused: bool, conninfo: str = "", *, accept_unknown: bool = False) -> dict:
    from app.db import HubResyncRequired, HubUnknownWrites
    db = _existing_database(conninfo)
    try:
        try:
            db.set_hub_write_paused(paused, accept_unknown=accept_unknown)
        except HubUnknownWrites as e:
            raise ToolError(i18n._("Пауза не снята: операций записи с неизвестным исходом – {count}. Сначала сверьте их "
                                   "с Hub; если сверка показала расхождение и решение принято: hub-resume "
                                   "--accept-unknown.", count=e.args[0])) from e
        except HubResyncRequired as e:
            raise ToolError(i18n._("Пауза не снята: база восстановлена из копии, а «Синхронизировать» и «Принять "
                                   "состояние Hub» не прошли по проектам: {count}. Если это невозможно и решение "
                                   "принято: hub-resume --accept-unknown.", count=e.args[0])) from e
        return {"hub_write_paused": db.hub_write_paused()}
    finally:
        db.close()


def after_restore(conninfo: str = "") -> dict:
    """После восстановления копии: выданные после неё действия в Hub могли выполниться, поэтому незавершённое повторно не выдаётся."""
    db = _existing_database(conninfo)
    try:
        return db.settle_after_restore()
    finally:
        db.close()


def backup_note(name: str, checked_at: str, conninfo: str = "") -> dict:
    """Отметка о последней проверенной копии базы (бэклог 76): её пишет scripts/backup-db.ps1 после пройденной проверки
    восстановления, читает /healthz. Копии лежат вне контейнера, приложение их не видит. Одна строка settings отдельным
    соединением: схема не меняется, работающему приложению команда не мешает."""
    from datetime import UTC, datetime

    from app.db import BACKUP_NOTE_KEY, dumps, now_iso
    if not re.fullmatch(r"triage-[0-9]{8}-[0-9]{6}\.dump", name):
        raise ValueError(i18n._("Имя копии не вида triage-ГГГГММДД-ЧЧММСС.dump: {name}", name=name))
    moment = datetime.fromisoformat(checked_at)  # ValueError – время не в ISO 8601
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    note = {"name": name, "checked_at": moment.astimezone(UTC).isoformat(timespec="seconds")}
    with psycopg.connect(conninfo, autocommit=True) as conn:
        conn.execute("INSERT INTO settings(key, value_json, updated_at) VALUES (%s, %s, %s)"
                     " ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
                     (BACKUP_NOTE_KEY, dumps(note), now_iso()))
    return {BACKUP_NOTE_KEY: note}


# ============================================================================ учебный стенд npm (ADR-0155)

_DB_NAME = re.compile(r"[a-z_][a-z0-9_]{0,62}")


def _same_dir(server: str, expected: str) -> bool:
    """Каталог данных сервера – тот, что ждёт обёртка: абсолютные пути после раскрытия коротких имён и ссылок, на
    Windows без учёта регистра и вида разделителей."""
    def canon(path: str) -> str:
        return os.path.normcase(os.path.realpath(os.path.abspath(path)))
    return bool(server) and canon(server) == canon(expected)


def _service_conn():
    """Соединение со служебной базой postgres: dbname в строке перекрывает PGDATABASE, остальное – из переменных
    libpq окружения (обёртка задаёт их явно)."""
    return psycopg.connect("dbname=postgres", autocommit=True)


def whoami(expect_data_dir: str) -> tuple[int, dict]:
    """Тот ли это сервер: сверка SHOW data_directory с ожидаемым каталогом. Обёртка зовёт перед остановкой сервера и
    перед любой записью, чтобы не тронуть чужой кластер на том же порту."""
    with _service_conn() as conn:
        directory = str(conn.execute("SHOW data_directory").fetchone()[0])
    match = _same_dir(directory, expect_data_dir)
    return (0 if match else 1), {"data_directory": directory, "match": match}


def ensure_database(expect_data_dir: str, create: bool) -> tuple[int, dict]:
    """База из PGDATABASE на сервере с ожидаемым каталогом данных: есть – ничего не меняется; нет – создаётся только
    с create (фазу первой установки знает обёртка: на прежней установке пропавшая база – утрата, а не повод создать
    пустую). Каталог не совпал – отказ до любой записи."""
    from psycopg import sql
    name = (os.environ.get("PGDATABASE") or "").strip()
    if not _DB_NAME.fullmatch(name):
        raise ToolError(i18n._("PGDATABASE: нужно имя базы из латинских строчных букв, цифр и «_»."))
    with _service_conn() as conn:
        directory = str(conn.execute("SHOW data_directory").fetchone()[0])
        answer = {"data_directory": directory, "match": _same_dir(directory, expect_data_dir), "exists": False,
                  "created": False}
        if not answer["match"]:
            return 1, answer
        answer["exists"] = conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,)).fetchone() is not None
        if answer["exists"]:
            return 0, answer
        if not create:
            return 1, answer
        owner = str(conn.execute("SELECT current_user").fetchone()[0])
        conn.execute(sql.SQL("CREATE DATABASE {} OWNER {} ENCODING 'UTF8' TEMPLATE template0").format(
            sql.Identifier(name), sql.Identifier(owner)))
        answer.update(exists=True, created=True)
        return 0, answer


SUMMARY_SCHEMAS = ("feeds", "feeds_imp", "app_state")  # кроме основной схемы: справочники, их загрузка, ключи
# находки по видам и решения по видам и итоговым вердиктам: сверка копии видит и смену значений при прежнем числе строк
SUMMARY_GROUPS = (("findings_kind", "findings", "kind"), ("reviews_decision", "reviews", "decision"),
                  ("reviews_final_verdict", "reviews", "final_verdict"))


def summary(conninfo: str = "") -> dict:
    """Сводка базы для сверки копии с оригиналом (стенд npm, раздел 3.4 плана): число строк каждой таблицы основной
    схемы приложения (имя без схемы) и схем справочников и ключей (имя «схема.таблица»), операции Hub по состояниям.
    Только чтение; содержимое строк не читается."""
    from psycopg import sql
    with psycopg.connect(conninfo, autocommit=True) as conn:
        current = str(conn.execute("SELECT current_schema()").fetchone()[0])
        rows = conn.execute(
            "SELECT table_schema, table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE'"
            " AND (table_schema = %s OR table_schema = ANY(%s)) ORDER BY table_schema, table_name",
            (current, list(SUMMARY_SCHEMAS))).fetchall()
        tables = {(name if schema == current else f"{schema}.{name}"): int(conn.execute(
                      sql.SQL("SELECT count(*) FROM {}.{}").format(sql.Identifier(schema), sql.Identifier(name))
                  ).fetchone()[0]) for schema, name in rows}
        hub = {}
        if "hub_ops" in tables:
            hub = {str(state): int(count) for state, count in conn.execute(
                "SELECT state, count(*) FROM hub_ops GROUP BY state ORDER BY state")}
        groups = {}
        for key, table, column in SUMMARY_GROUPS:
            if table in tables:
                groups[key] = {str(value): int(count) for value, count in conn.execute(sql.SQL(
                    "SELECT {c}, count(*) FROM {t} GROUP BY {c} ORDER BY {c}").format(
                    c=sql.Identifier(column), t=sql.Identifier(table)))}
    return {"tables": tables, "hub_ops": hub, "groups": groups}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.storage.tools", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    stand = commands.add_parser("ensure-database", help=i18n._("учебный стенд npm: база из PGDATABASE на своём сервере"))
    stand.add_argument("--expect-data-dir", required=True, help=i18n._("каталог данных сервера, который ждёт обёртка"))
    stand.add_argument("--create", action="store_true", help=i18n._("создать базу, если её нет (только первая установка)"))
    commands.add_parser("whoami", help=i18n._("учебный стенд npm: тот ли сервер")).add_argument(
        "--expect-data-dir", required=True, help=i18n._("каталог данных сервера, который ждёт обёртка"))
    commands.add_parser("summary", help=i18n._("сводка базы: строки таблиц и операции Hub по состояниям"))
    for name in ("local-state-import", "local-state-verify"):
        commands.add_parser(name).add_argument("--data", type=Path, default=Path(os.environ.get("DATA_DIR") or "/data"),
                                                help=i18n._("папка данных с прежними файлами состояния; читается, не меняется"))
    for name in ("status", "migrate", "hub-pause", "hub-resume", "after-restore"):
        sub = commands.add_parser(name)
        if name == "hub-resume":
            sub.add_argument("--accept-unknown", action="store_true",
                             help=i18n._("снять паузу при неизвестных исходах: они остаются неизвестными и повторно не выдаются"))
    note = commands.add_parser("backup-note")
    note.add_argument("--name", required=True, help=i18n._("имя файла проверенной копии: triage-ГГГГММДД-ЧЧММСС.dump"))
    note.add_argument("--checked-at", required=True, help=i18n._("время пройденной проверки восстановления, ISO 8601, UTC"))
    args = parser.parse_args(argv)
    try:
        code, answer = _run(args)
    except (ToolError, psycopg.Error, RuntimeError, OSError, ValueError) as e:
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}, ensure_ascii=False))
        return 2
    print(json.dumps(answer, ensure_ascii=False, indent=1))
    return code


def _run(args: argparse.Namespace) -> tuple[int, dict]:
    if args.command == "ensure-database":
        return ensure_database(args.expect_data_dir, args.create)
    if args.command == "whoami":
        return whoami(args.expect_data_dir)
    if args.command == "summary":
        return 0, summary()
    if args.command == "local-state-import":
        return 0, local_state.import_all(args.data)
    if args.command == "local-state-verify":
        answer = local_state.verify(args.data)
        return (0 if answer["ok"] else 3), answer
    if args.command == "status":
        answer = status()
        return (0 if answer["state"] in ("ok", "empty") else 1), answer
    if args.command == "migrate":
        if status()["state"] == "empty":
            raise ToolError(i18n._("База пуста: обновлять нечего. Новая база получает схему при запуске."))
        with psycopg.connect("", autocommit=True) as conn:
            return 0, {"applied": migrate.apply_pending(conn)}
    if args.command == "hub-pause":
        return 0, set_pause(True)
    if args.command == "hub-resume":
        return 0, set_pause(False, accept_unknown=args.accept_unknown)
    if args.command == "backup-note":
        return 0, backup_note(args.name, args.checked_at)
    return 0, after_restore()


if __name__ == "__main__":
    sys.exit(main())
