"""Перенос файлов состояния в PostgreSQL (ADR-0133): справочники feeds.db, ключ маскирования, ключ исполнителя, ключи профилей моделей.

Файлы только читаются и не удаляются: их удаляет владелец. Всё пишется одной транзакцией вместе с отметкой о переносе; после отметки
приложение файлы не читает. Значения ключей ни в ответе, ни в журнале не появляются.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

import psycopg

from app import i18n

MARKER = "local_state_imported"
MASK_SECRET = "mask_key"
WORKER_SECRET = "hub_worker_key"
PROVIDER_SECRET = "provider:{}"
MASK_FILE = "mask.key"
WORKER_FILE = "hub-worker.key"
PROVIDERS_DIR = "providers"
FEEDS_FILE = "feeds.db"
TABLES = ("feed_meta", "bdu", "bdu_cve", "cwe_ru", "cwe", "cwe_refs", "cwe_links", "cwe_index", "cwe_capec",
          "capec", "capec_index", "capec_refs", "capec_links", "capec_cwe", "capec_meta")
_DIGEST_SIZE = 2 ** 256
_LOCK = 7133001  # то же, что feeds.IMPORT_LOCK: загрузка справочников и перенос не идут вместе


class LocalStateError(RuntimeError):
    """Перенос остановлен, база не изменилась."""


def legacy_files(data_dir: Path) -> list[str]:
    """Какие файлы состояния лежат в папке данных."""
    root = Path(data_dir)
    found = [name for name in (FEEDS_FILE, MASK_FILE, WORKER_FILE) if (root / name).is_file()]
    return found + [f"{PROVIDERS_DIR}/{p.name}" for p in sorted((root / PROVIDERS_DIR).glob("*.key"))]


def pending(data_dir: Path, conninfo: str = "") -> bool:
    """Перенос нужен: файлы состояния есть, отметки нет. Им же start.ps1 находит прерванный перенос."""
    if not legacy_files(data_dir):
        return False
    with psycopg.connect(conninfo, autocommit=True) as conn:
        return conn.execute("SELECT 1 FROM app_state.secrets WHERE name = %s", (MARKER,)).fetchone() is None


def require_imported(db: Any, data_dir: Path) -> None:
    """Запуск на базе без отметки при файлах состояния в папке данных – отказ: новый ключ маскирования на существующей базе нельзя
    создавать молча. После отметки файлы не читаются совсем."""
    if db.secret(MARKER) is not None:
        return
    files = legacy_files(data_dir)
    if files:
        from app.config import stand_mode
        how = (i18n._("Это служебная папка другой установки: запустите стенд с новой служебной папкой (ключ --home).")
               if stand_mode() == "npm" else
               i18n._("Выполните .\\start.ps1 -Migrate или python -m app.storage.tools local-state-import."))
        raise RuntimeError(i18n._("В папке данных есть файлы состояния, а в базу они не перенесены: {files}.",
                                  files=", ".join(files)) + " " + how)


def _file_keys(data_dir: Path) -> dict[str, str]:
    """Ключи из файлов: {имя в базе: значение}. Повреждённый файл – остановка: заменить его молча нельзя."""
    from app.provider_keys import parse_entry
    root, keys = Path(data_dir), {}
    mask = root / MASK_FILE
    if mask.is_file():
        raw = mask.read_bytes()
        if len(raw) != 32:
            raise LocalStateError(i18n._("Файл {name} повреждён: длина не 32 байта. База не менялась.", name=MASK_FILE))
        keys[MASK_SECRET] = raw.hex()
    worker = root / WORKER_FILE
    if worker.is_file():
        value = worker.read_text(encoding="ascii", errors="replace").strip()
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise LocalStateError(i18n._("Файл {name} повреждён. База не менялась.", name=WORKER_FILE))
        keys[WORKER_SECRET] = value
    for path in sorted((root / PROVIDERS_DIR).glob("*.key")):
        if not path.stem.isdigit():
            raise LocalStateError(i18n._("Неожиданный файл ключа: {name}. База не менялась.", name=path.name))
        entry = parse_entry(path.read_bytes())
        if entry is None:
            raise LocalStateError(i18n._("Файл ключа профиля {name} повреждён. База не менялась.", name=path.name))
        keys[PROVIDER_SECRET.format(int(path.stem))] = json.dumps(entry, ensure_ascii=True, sort_keys=True)
    return keys


def _open_source(data_dir: Path) -> sqlite3.Connection | None:
    path = Path(data_dir) / FEEDS_FILE
    if not path.is_file():
        return None
    wal = Path(f"{path}-wal")
    live = wal.is_file() and wal.stat().st_size > 0
    # журнал пуст – файл открывается как неизменяемый: том Docker Desktop не даёт блокировок SQLite
    return sqlite3.connect(f"file:{quote(path.resolve().as_posix())}?mode=ro" + ("" if live else "&immutable=1"), uri=True)


def _row_hash(row: Any) -> int:
    """Хеш строки без учёта типа драйвера: числа и строки сравниваются по значению."""
    text = json.dumps([repr(v) if isinstance(v, float) else v for v in row], ensure_ascii=False)
    return int.from_bytes(hashlib.sha256(text.encode("utf-8")).digest(), "big")


def _source_columns(source: sqlite3.Connection, table: str) -> list[str]:
    return [row[1] for row in source.execute(f"PRAGMA table_info({table})")]


def _source_digest(source: sqlite3.Connection, table: str, columns: list[str]) -> tuple[int, int]:
    count, total = 0, 0
    for row in source.execute(f"SELECT {', '.join(columns)} FROM {table}"):
        count += 1
        total = (total + _row_hash(row)) % _DIGEST_SIZE
    return count, total


def _target_digest(conn: psycopg.Connection, table: str, columns: list[str]) -> tuple[int, int]:
    count, total = 0, 0
    with conn.cursor(name=f"digest_{table}") as cursor:
        cursor.execute(f"SELECT {', '.join(columns)} FROM feeds.{table}")
        for row in cursor:
            count += 1
            total = (total + _row_hash(row)) % _DIGEST_SIZE
    return count, total


def _copy_feeds(conn: psycopg.Connection, source: sqlite3.Connection) -> dict[str, int]:
    """Строки feeds.db – в схему feeds. Столбец, которого в базе нет, – остановка."""
    copied: dict[str, int] = {}
    for table in TABLES:
        columns = _source_columns(source, table)
        if not columns:  # таблицы нет: каталог этого вида не загружался прежней версией
            copied[table] = 0
            continue
        known = {row[0] for row in conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = 'feeds' AND table_name = %s", (table,))}
        extra = sorted(set(columns) - known)
        if extra:
            raise LocalStateError(i18n._("В {file}, таблица {table}, есть неизвестные столбцы: {columns}. База не менялась.",
                                          file=FEEDS_FILE, table=table, columns=extra))
        count = 0
        with conn.cursor() as cursor, cursor.copy(f"COPY feeds.{table} ({', '.join(columns)}) FROM STDIN") as copy:
            for row in source.execute(f"SELECT {', '.join(columns)} FROM {table}"):
                for column, value in zip(columns, row, strict=True):
                    if isinstance(value, str) and "\x00" in value:  # в PostgreSQL такого значения нет, изменить его молча нельзя
                        raise LocalStateError(i18n._("В {file}, таблица {table}, столбец {column}, есть знак NUL. База не менялась.",
                                                      file=FEEDS_FILE, table=table, column=column))
                copy.write_row(row)
                count += 1
        copied[table] = count
    return copied


def _fill_cwe_capec(conn: psycopg.Connection, source: sqlite3.Connection) -> None:
    """Файл прежней версии без таблицы пар CWE и CAPEC: пары строятся из записей каталога CWE, как делала прежняя версия при открытии."""
    if _source_columns(source, "cwe_capec"):
        return
    from app.capec import identifier
    rows = conn.execute("SELECT id, data_json FROM feeds.cwe").fetchall()
    with conn.cursor() as cursor:
        for ident, raw in rows:
            for value in json.loads(raw).get("attack_patterns", []):
                if identifier(value):
                    cursor.execute("INSERT INTO feeds.cwe_capec(cwe, id) VALUES (%s, %s) ON CONFLICT DO NOTHING", (ident, identifier(value)))


def _compare_feeds(conn: psycopg.Connection, source: sqlite3.Connection) -> dict[str, dict]:
    report: dict[str, dict] = {}
    for table in TABLES:
        columns = _source_columns(source, table)
        if not columns:
            report[table] = {"source": 0, "target": int(conn.execute(f"SELECT COUNT(*) FROM feeds.{table}").fetchone()[0]), "same": True}
            continue
        source_count, source_sum = _source_digest(source, table, columns)
        target_count, target_sum = _target_digest(conn, table, columns)
        report[table] = {"source": source_count, "target": target_count, "same": source_count == target_count and source_sum == target_sum}
    return report


def _key_names(keys: dict[str, str]) -> list[str]:
    """Имена без номеров профилей не нужны: это служебные имена, значений в них нет."""
    return sorted(keys)


def import_all(data_dir: Path, conninfo: str = "") -> dict:
    """Перенос. Повторный запуск после отметки ничего не делает. Разные ключ в файле и в базе, справочники в базе без отметки – остановка."""
    with psycopg.connect(conninfo, autocommit=True) as conn:
        if not conn.execute("SELECT to_regclass('app_state.secrets')").fetchone()[0]:  # пустая база: схема – как при первом запуске
            from app.db import Database
            Database(conninfo or None).close()
        if not conn.execute("SELECT pg_try_advisory_lock(%s)", (_LOCK,)).fetchone()[0]:
            raise LocalStateError(i18n._("Идёт загрузка справочников: остановите приложение и повторите перенос."))
        done = conn.execute("SELECT value FROM app_state.secrets WHERE name = %s", (MARKER,)).fetchone()
        if done:
            return {"imported": False, "already": done[0]}
        keys = _file_keys(data_dir)
        stored = {row[0]: row[1] for row in conn.execute("SELECT name, value FROM app_state.secrets")}
        different = sorted(name for name, value in keys.items() if name in stored and stored[name] != value)
        if different:
            raise LocalStateError(i18n._("Ключи в файлах и в базе различаются: {names}. Значения не показаны. База не менялась.",
                                          names=different))
        source = _open_source(data_dir)
        try:
            if source is not None and conn.execute("SELECT 1 FROM feeds.feed_meta LIMIT 1").fetchone():
                raise LocalStateError(i18n._("В базе уже есть справочники, а отметки переноса нет: перезаписывать их нельзя. База не менялась."))
            now = datetime.now(UTC).isoformat(timespec="seconds")
            report: dict[str, dict] = {}
            with conn.transaction():
                for name, value in keys.items():
                    conn.execute("INSERT INTO app_state.secrets(name, value, updated_at) VALUES (%s, %s, %s) ON CONFLICT (name) DO NOTHING",
                                 (name, value, now))
                if source is not None:
                    _copy_feeds(conn, source)
                    _fill_cwe_capec(conn, source)
                    report = _compare_feeds(conn, source)
                    wrong = sorted(table for table, item in report.items() if not item["same"])
                    if wrong:
                        raise LocalStateError(i18n._("После переноса не совпали таблицы: {tables}. Перенос отменён, база не менялась.",
                                                  tables=wrong))
                conn.execute("INSERT INTO app_state.secrets(name, value, updated_at) VALUES (%s, %s, %s)", (MARKER, now, now))
        finally:
            if source is not None:
                source.close()
    return {"imported": True, "at": now, "keys": _key_names(keys), "feeds": report}


def verify(data_dir: Path, conninfo: str = "") -> dict:
    """Сверка без записи: отметка, ключи и справочники с файлами, какие из них ещё есть. Файлов нет – проверяется наличие в базе."""
    with psycopg.connect(conninfo, autocommit=True) as conn:
        with conn.transaction():
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            stored = {row[0]: row[1] for row in conn.execute("SELECT name, value FROM app_state.secrets")}
            keys = _file_keys(data_dir)
            key_report = {name: ("same" if stored.get(name) == value else "absent" if name not in stored else "different")
                          for name, value in keys.items()}
            source = _open_source(data_dir)
            try:
                feeds = _compare_feeds(conn, source) if source is not None else {
                    table: {"target": int(conn.execute(f"SELECT COUNT(*) FROM feeds.{table}").fetchone()[0])} for table in TABLES}
            finally:
                if source is not None:
                    source.close()
    in_base = sorted(name for name in stored if name != MARKER)
    ok = MARKER in stored and all(value == "same" for value in key_report.values()) and all(item.get("same", True) for item in feeds.values())
    return {"ok": ok, "imported_at": stored.get(MARKER), "keys_in_base": in_base, "keys_with_files": key_report,
            "feeds_compared_with_file": source is not None, "feeds": feeds}
