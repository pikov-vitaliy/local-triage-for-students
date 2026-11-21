"""Итоговая проверка 0.10.0: ответ не зависит от расположения строк в таблице.

PostgreSQL без ORDER BY отдаёт строки в порядке их расположения или индекса, а UPDATE строки меняет её место. В прежней базе
порядок на деле совпадал с порядком номеров, и код на него опирался: первая подходящая строка попадала в подпись предпросмотра,
в сообщение оператору или определяла очерёдность следующих операций Hub. Каждый тест переставляет строки пустым UPDATE с воспроизводимыми случайными перестановками
и проверяет, что ответ прежний. Адреса выдуманы."""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from app.db import Database, dumps
from app.routes import defect_selected
from test_hub_queue import HUB, status_req, write


@pytest.fixture
def db(tmp_path: Path):
    database = Database(tmp_path / "triage.db")
    yield database
    database.close()


def move_row(db: Database, table: str, row_id: int, seed: int) -> None:
    """Значения прежние, место строки новое: её новая версия ложится после остальных. Статистика собрана, как на рабочей
    базе после автоматического анализа: маленькую таблицу сервер читает подряд, а не по индексу."""
    ids = [r["id"] for r in db._all(f"SELECT id FROM {table} ORDER BY id") if r["id"] != row_id]
    random.Random(seed).shuffle(ids)
    with db._tx() as c:
        for ident in ids:
            c.execute(f"UPDATE {table} SET id = id WHERE id = ?", (ident,))
        c.execute(f"UPDATE {table} SET id = id WHERE id = ?", (row_id,))
        c.execute(f"ANALYZE {table}")
    rows = [r["id"] for r in db._all(f"SELECT id FROM {table}")]
    assert rows[-1] == row_id, "строка не сменила место: тест не проверяет зависимость от порядка"


def defect_row(db: Database, project_id: int, state: str, hub_id: str) -> int:
    targets = dumps([{"hub_id": hub_id, "issue_id": int(hub_id), "issue_type": "SAST"}])
    with db._tx() as c:
        return c.execute("INSERT INTO hub_defects(project_id, kind, state, targets_json, created_at, updated_at)"
                         " VALUES (?, 'SAST', ?, ?, 'x', 'x') RETURNING id", (project_id, state, targets)).fetchone()[0]


@pytest.mark.parametrize("seed", [7, 41, 2026])
def test_busy_reason_names_the_same_defect_after_rows_move(db: Database, seed: int):
    pid = db.create_project("Проект")
    first, second = defect_row(db, pid, "done", "10"), defect_row(db, pid, "done", "10")

    def reason() -> str:
        return db.on_connection(lambda c: defect_selected.busy_reason(db, c, pid, "10", 10))
    before = reason()
    assert f"№{first} " in before and first < second
    move_row(db, "hub_defects", first, seed)
    assert reason() == before


@pytest.mark.parametrize("seed", [7, 41, 2026])
def test_busy_reason_names_the_same_status_operation_after_rows_move(db: Database, seed: int):
    pid = db.create_project("Проект")
    ops = []
    for reason_text in ("первая", "вторая"):  # разные тексты – разные операции одной находки у разных приложений Hub
        ops.append(db.hub_enqueue(purpose="status", request=status_req(10, reason_text), hub_url=HUB, app_id=len(ops) + 7,
                                  project_id=pid, targets=[{"issue_type": "SAST", "issue_id": 10, "revision": 1}],
                                  text=reason_text)["id"])

    def reason() -> str:
        return db.on_connection(lambda c: defect_selected.busy_reason(db, c, pid, "10", 10))
    before = reason()
    assert f"№{ops[0]}:" in before and ops[0] < ops[1]
    move_row(db, "hub_ops", ops[0], seed)
    assert reason() == before


@pytest.mark.parametrize("seed", [7, 41, 2026])
def test_defects_to_sync_come_in_number_order_after_rows_move(db: Database, seed: int):
    pid = db.create_project("Проект")
    ids = [defect_row(db, pid, "creating", str(n)) for n in (10, 11, 12)]
    assert [r["id"] for r in db.hub_defects_to_sync(pid, ["creating"])] == ids
    move_row(db, "hub_defects", ids[0], seed)
    assert [r["id"] for r in db.hub_defects_to_sync(pid, ["creating"])] == ids


@pytest.mark.parametrize("seed", [7, 41, 2026])
def test_lock_refusal_names_the_same_operation_after_rows_move(db: Database, seed: int):
    first, second = write(db, 1)["id"], write(db, 2)["id"]
    both = [{"issue_type": "SAST", "issue_id": n, "revision": 1} for n in (1, 2)]

    def refusal() -> str:
        with pytest.raises(ValueError, match="незакрытая операция") as caught:
            db.hub_enqueue(purpose="status", request=status_req(3, "третья"), hub_url=HUB, app_id=7, targets=both, text="третья")
        return str(caught.value)
    before = refusal()
    assert f"№{first})" in before and first < second
    move_row(db, "hub_ops", first, seed)
    assert refusal() == before
