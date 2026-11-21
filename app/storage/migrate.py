"""Схема PostgreSQL: базовая схема и технические миграции (ADR-0128, раздел 7).

Базовая схема 33 не меняется: новая база – она плюс все миграции, существующая получает миграции командой обслуживания после копии
(start.ps1). Других изменений схемы при открытии базы нет.
Каждый применённый файл – строка в storage_migrations с контрольной суммой; изменённый после применения файл останавливает работу.
Файл миграции: NNNN_имя.sql, первая строка – «-- schema: N»; выполняется одной транзакцией.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations" / "postgresql"
BASELINE = MIGRATIONS_DIR / "0001_baseline.sql"
BASELINE_SCHEMA = 33
_FILE = re.compile(r"^(\d{4})_[^/\\]+\.sql$")
_SCHEMA_LINE = re.compile(r"^--\s*schema:\s*(\d+)\s*$")


class MigrationError(RuntimeError):
    """Файлы миграций и база не согласованы: работа останавливается, база не меняется."""


@dataclass(frozen=True)
class Migration:
    number: int
    path: Path
    schema: int

    @property
    def name(self) -> str:
        return self.path.name


def checksum(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def available() -> list[Migration]:
    """Файлы миграций по порядку, без базовой схемы. Номера идут без пропусков, схема растёт."""
    found = []
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        match = _FILE.match(path.name)
        if not match:
            raise MigrationError(f"Имя файла миграции не по правилу NNNN_имя.sql: {path.name}")
        number = int(match.group(1))
        if number == 1:
            continue
        with path.open(encoding="utf-8") as handle:
            line = _SCHEMA_LINE.match(handle.readline().strip())
        if not line:
            raise MigrationError(f"Первая строка миграции – «-- schema: N»: {path.name}")
        found.append(Migration(number, path, int(line.group(1))))
    for expected, item in enumerate(found, start=2):
        if item.number != expected:
            raise MigrationError(f"Пропущен номер миграции {expected:04d}.")
        if item.schema != BASELINE_SCHEMA + expected - 1:
            raise MigrationError(f"{item.name}: схема {item.schema}, а по порядку должна быть {BASELINE_SCHEMA + expected - 1}.")
    return found


def _applied(conn) -> dict[int, str]:
    return {int(row[0]): row[1] for row in conn.execute("SELECT number, checksum FROM storage_migrations")}


def pending(conn) -> list[Migration]:
    """Ещё не применённые миграции. Применённая и изменённая после этого миграция – отказ."""
    applied = _applied(conn)
    files = available()
    for item in files:
        if item.number in applied and applied[item.number] != checksum(item.path):
            raise MigrationError(f"Файл уже применённой миграции изменён: {item.name}.")
    known = {item.number for item in files} | {1}
    unknown = sorted(set(applied) - known)
    if unknown:
        raise MigrationError(f"База новее этой сборки: применены миграции {unknown}, файлов которых нет.")
    return [item for item in files if item.number not in applied]


def apply_baseline(conn, mark: str = "?") -> None:
    """Базовая схема и запись о ней: внутри открытой транзакции записи вызывающего. mark – маркер параметра его соединения."""
    text = BASELINE.read_text(encoding="utf-8")
    conn.execute(text)  # без параметров: драйвер отправляет весь файл как есть
    conn.execute(f"INSERT INTO storage_migrations(number, schema_version, checksum, applied_at) VALUES ({mark}, {mark}, {mark}, {mark})",
                 (1, BASELINE_SCHEMA, checksum(BASELINE), datetime.now(UTC).isoformat(timespec="microseconds")))


def apply_one(conn, item: Migration, mark: str = "%s") -> None:
    """Миграция, запись о ней и версия схемы – внутри открытой транзакции вызывающего."""
    ts = datetime.now(UTC).isoformat(timespec="seconds")
    conn.execute(item.path.read_text(encoding="utf-8"))
    conn.execute(f"INSERT INTO storage_migrations(number, schema_version, checksum, applied_at) VALUES ({mark}, {mark}, {mark}, {mark})",
                 (item.number, item.schema, checksum(item.path), ts))
    conn.execute(f"UPDATE meta SET value = {mark} WHERE key = 'schema_version'", (str(item.schema),))
    conn.execute(f"INSERT INTO schema_version(version, applied_at, note) VALUES ({mark}, {mark}, {mark})", (item.schema, ts, item.name))


def apply_pending(conn) -> list[str]:
    """Применить миграции: каждая – своя транзакция. Сбой откатывает только эту миграцию. Соединение в режиме autocommit; копию
    перед запуском снимает вызывающий (start.ps1)."""
    done = []
    for item in pending(conn):
        with conn.transaction():
            apply_one(conn, item)
        done.append(item.name)
    return done
