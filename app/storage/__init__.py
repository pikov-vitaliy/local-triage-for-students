"""Хранилище основной базы: PostgreSQL (ADR-0128, редакция 3). app/db.py – прикладной фасад поверх этого слоя."""

from app.storage.postgresql import (
    BUSY_TEXT,
    CommitUnknown,
    DatabaseBusy,
    DatabaseUnavailable,
    IntegrityError,
    PostgresStore,
    Row,
    SerializationFailure,
    conninfo_for,
)

__all__ = ["BUSY_TEXT", "CommitUnknown", "DatabaseBusy", "DatabaseUnavailable", "IntegrityError", "PostgresStore", "Row",
           "SerializationFailure", "conninfo_for"]
