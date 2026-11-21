"""База тестов: сервер PostgreSQL обязателен (scripts/test-db.ps1), запасного варианта нет. Каждый путь
Database(tmp_path / "...") или Settings(data_dir=...).db_path – своя база из общего шаблона; тот же путь – та же база, так
тесты проверяют перезапуск. Базы теста удаляются после него (tests/conftest.py).

connect_db(path) – отдельное соединение с этой базой: заглянуть в строки или подготовить состояние мимо методов Database; те же
«?» и строки результата. Как у обычного соединения: изменения нужно подтвердить (commit), `with connect_db(path) as c:`
подтверждает и закрывает."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import psycopg
import pytest

from app.storage import postgresql

TEST_DSN = os.environ.get("TRIAGE_TEST_DSN", "host=127.0.0.1 port=5433 user=triage password=triage-test")
_db_admin = None
_db_template = ""
_db_by_path: dict[str, str] = {}
_db_serial = 0


def _admin():
    global _db_admin
    if _db_admin is None:
        try:
            _db_admin = psycopg.connect(conninfo_of("postgres"), autocommit=True, connect_timeout=5)
        except psycopg.ProgrammingError:
            pytest.exit(f"Строка TRIAGE_TEST_DSN не разбирается ({dsn_display(TEST_DSN)}).", returncode=3)
        except psycopg.OperationalError as e:
            pytest.exit(f"Тестовая база PostgreSQL недоступна ({dsn_display(TEST_DSN)}): запустите "
                        f"scripts/test-db.ps1. {e}", returncode=3)
    return _db_admin


def libpq_parts() -> dict[str, str]:
    """Части TEST_DSN для переменных libpq; строка не разбирается – выход с сообщением без пароля (Д14)."""
    try:
        return {k: str(v) for k, v in psycopg.conninfo.conninfo_to_dict(TEST_DSN).items() if v is not None}
    except psycopg.ProgrammingError:
        pytest.exit(f"Строка TRIAGE_TEST_DSN не разбирается ({dsn_display(TEST_DSN)}).", returncode=3)


def dsn_display(dsn: str) -> str:
    """Адрес тестовой базы для сообщений без пароля (план стенда, Д14): только узел, порт, пользователь и база – в любой
    записи строки подключения (ключи в любом порядке, адрес postgresql://)."""
    try:
        parts = psycopg.conninfo.conninfo_to_dict(dsn)
    except psycopg.ProgrammingError:
        return "строка TRIAGE_TEST_DSN не разбирается"
    shown = {k: parts[k] for k in ("host", "port", "user", "dbname") if parts.get(k)}
    return " ".join(f"{k}={v}" for k, v in shown.items()) or "адрес по умолчанию libpq"


def _template() -> str:
    """Шаблон с базовой схемой: один на процесс прогона; соединений к нему не остаётся, иначе копия не создастся."""
    global _db_template
    if not _db_template:
        from app.db import Database
        name = f"tpl_{os.getpid()}"
        admin = _admin()
        admin.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        admin.execute(f"CREATE DATABASE {name}")
        Database(conninfo_of(name)).close()
        _db_template = name
    return _db_template


def conninfo_of(name: str) -> str:
    # make_conninfo, а не дописывание строки: адрес вида postgresql://… с паролем иначе не разбирается, и ошибка
    # показала бы строку подключения целиком (Д14)
    return psycopg.conninfo.make_conninfo(TEST_DSN, dbname=name)


def database_for_path(path: Path) -> str:
    """Имя базы теста по пути файла; создаётся при первом обращении."""
    global _db_serial
    key = str(Path(path).resolve())
    if key not in _db_by_path:
        template = _template()
        _db_serial += 1
        name = f"t{os.getpid()}_{_db_serial}"
        _admin().execute(f"CREATE DATABASE {name} TEMPLATE {template}")
        _db_by_path[key] = name
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    return _db_by_path[key]


def empty_database() -> str:
    """Строка подключения к новой пустой базе (без схемы); удаляется вместе с базами теста."""
    global _db_serial
    _template()
    _db_serial += 1
    name = f"e{os.getpid()}_{_db_serial}"
    _admin().execute(f"CREATE DATABASE {name}")
    _db_by_path[f"empty:{name}"] = name
    return conninfo_of(name)


def libpq_env(path: Path) -> dict[str, str]:
    """Переменные подключения для приложения в дочернем процессе (e2e): та же база, что у пути."""
    parts = libpq_parts()
    return {"PGHOST": parts.get("host", ""), "PGPORT": parts.get("port", ""), "PGUSER": parts.get("user", ""),
            "PGPASSWORD": parts.get("password", ""), "PGDATABASE": database_for_path(path)}


def _drop_databases(names: list[str]) -> None:
    wanted = {conninfo_of(n) for n in names}
    for store in list(postgresql.OPEN_STORES):
        if store.conninfo in wanted:
            store.close()
    for name in names:
        _admin().execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")


def install() -> None:
    postgresql.TARGET_RESOLVER = lambda path: conninfo_of(database_for_path(path))


def finish() -> None:
    if _db_admin is None:
        return
    try:
        _drop_databases(list(_db_by_path.values()))
        if _db_template:
            _db_admin.execute(f"DROP DATABASE IF EXISTS {_db_template} WITH (FORCE)")
    finally:
        _db_admin.close()


def known_databases() -> set[str]:
    return set(_db_by_path)


def drop_created_since(before: set[str]) -> None:
    created = [k for k in _db_by_path if k not in before]
    if created:
        _drop_databases([_db_by_path[k] for k in created])
        for key in created:
            del _db_by_path[key]


def connect_db(path: Path | str) -> psycopg.Connection:
    conn = postgresql.Connection.connect(postgresql.conninfo_for(Path(path)), cursor_factory=postgresql.Cursor,
                                         row_factory=postgresql.row_factory)
    postgresql._configure(conn)
    conn.commit()
    return conn


def record_queries(queries: list) -> Callable[[], None]:
    """Все запросы приложения – в список, пока не вызвана возвращённая функция (замер числа запросов страницы)."""
    real = postgresql.Cursor.execute

    def execute(self, query, params=None, **kwargs):
        queries.append(query)
        return real(self, query, params, **kwargs)
    postgresql.Cursor.execute = execute

    def stop() -> None:
        postgresql.Cursor.execute = real
    return stop
