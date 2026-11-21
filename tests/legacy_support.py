"""Опора для проверок миграции: файл базы в состоянии прежней схемы – с настоящими прежними подписями решений, заданными
временами решений и загрузок и полным снимком содержимого для сравнения до и после шага."""

from __future__ import annotations

import gc
import json
import sqlite3
from pathlib import Path

from app.db import SCA_KEYS

EARLY = "2026-01-01T09:00:00+00:00"   # загрузка, записавшая строку находки
DECIDED = "2026-01-01T10:00:00+00:00"  # решение, принятое после этой загрузки
def legacy_signature(data: dict) -> str:
    """Подпись решения SCA до шага 10: поля SCA_KEYS, без экосистемы (так её писали версии 0.3.2–0.3.14)."""
    return json.dumps({"sca": {key: data.get(key) for key in SCA_KEYS}}, ensure_ascii=False, sort_keys=True)


def rewrite_legacy_signatures(path: Path) -> int:
    """Подписи всех решений SCA файла – прежнего формата, вычисленные по данным находки; возвращает число решений."""
    con = sqlite3.connect(path)
    try:
        with con:
            rows = con.execute("SELECT r.project_id, r.hub_id, f.data_json FROM reviews r JOIN findings f"
                               " ON f.project_id = r.project_id AND f.hub_id = r.hub_id WHERE f.kind = 'SCA'").fetchall()
            for project_id, hub_id, data_json in rows:
                con.execute("UPDATE reviews SET finding_sig = ? WHERE project_id = ? AND hub_id = ?",
                            (legacy_signature(json.loads(data_json)), project_id, hub_id))
        return len(rows)
    finally:
        con.close()


def set_times(path: Path, *, import_at: str | None = None, reviewed_at: str | None = None,
              applied_10: str | None = None, hub_ids: tuple[str, ...] | None = None) -> None:
    """Времена в файле: все загрузки (import_at), решения выбранных находок (reviewed_at, updated_at) и запись шага 10
    в журнале (applied_10). None – не менять."""
    con = sqlite3.connect(path)
    try:
        with con:
            if import_at is not None:
                con.execute("UPDATE imports SET created_at = ?", (import_at,))
            if reviewed_at is not None:
                marks = ""
                params: list = [reviewed_at, reviewed_at]
                if hub_ids:
                    marks = f" AND hub_id IN ({','.join('?' * len(hub_ids))})"
                    params += list(hub_ids)
                con.execute(f"UPDATE reviews SET reviewed_at = ?, updated_at = ? WHERE reviewed = 1{marks}", params)
            if applied_10 is not None:
                con.execute("UPDATE schema_version SET applied_at = ? WHERE version = 10", (applied_10,))
    finally:
        con.close()


def dump(path: Path) -> dict:
    """Полное содержимое таблиц, которые трогают шаги обновления: строки целиком, а не отдельные поля; версии журнала
    схем без времени записи."""
    gc.collect()
    con = sqlite3.connect(path)
    try:
        def rows(sql: str) -> list[tuple]:
            return [tuple(r) for r in con.execute(sql)]

        seq = con.execute("SELECT seq FROM sqlite_sequence WHERE name = 'sca_answers'").fetchone()
        return {
            "meta": rows("SELECT key, value FROM meta ORDER BY key"),
            "log": [r[0] for r in con.execute("SELECT version FROM schema_version ORDER BY version")],
            "answers_columns": [r[1] for r in con.execute("PRAGMA table_info(sca_answers)")],
            "answers": rows("SELECT * FROM sca_answers ORDER BY id"),
            "seq": seq[0] if seq else None,
            "reviews": rows("SELECT * FROM reviews ORDER BY project_id, hub_id"),
            "defects": rows("SELECT * FROM defects ORDER BY project_id, defect_key"),
            "findings": rows("SELECT * FROM findings ORDER BY project_id, hub_id"),
        }
    finally:
        con.close()
