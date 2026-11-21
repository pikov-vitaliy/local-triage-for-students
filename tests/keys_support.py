"""Ключи в памяти для проверок без базы: те же методы, что у Database (ADR-0133)."""

from __future__ import annotations

from pathlib import Path

_BY_PATH: dict[str, MemoryKeys] = {}


class MemoryKeys:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def secret(self, name: str) -> str | None:
        return self.values.get(name)

    def put_secret(self, name: str, value: str) -> None:
        self.values[name] = value

    def drop_secret(self, name: str) -> bool:
        return self.values.pop(name, None) is not None


def keys_for(path: Path) -> MemoryKeys:
    """Одно хранилище на временную папку теста."""
    return _BY_PATH.setdefault(str(path), MemoryKeys())


def worker_key_of(conninfo: str) -> str:
    """Ключ исполнителя в базе: для приложения в другом процессе или до его запуска."""
    import psycopg

    from app.storage.local_state import WORKER_SECRET
    with psycopg.connect(conninfo) as conn:
        row = conn.execute("SELECT value FROM app_state.secrets WHERE name = %s", (WORKER_SECRET,)).fetchone()
    return row[0] if row else ""
