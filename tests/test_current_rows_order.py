"""«Текущая» строка при двух текущих (бэклог 76): порядок чтения задан явно, а не оставлен плану запроса.

Одну текущую строку держит сама запись (прежняя получает state = 'superseded' в той же транзакции), поэтому две текущие здесь
вставлены напрямую. Тестовая база без статистики читает маленькую таблицу по индексу, рабочая – подряд; строки вставлены так, чтобы
без ORDER BY ошибались оба способа, а где это невозможно – статистика собрана, как в рабочей базе."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.db import Database


@pytest.fixture
def db(tmp_path: Path):
    database = Database(tmp_path / "triage.db")
    yield database
    database.close()


def test_task_row_comes_from_the_latest_current_task(db: Database):
    """Строка действующего задания: при двух текущих заданиях – из последнего, как у current_task (ORDER BY id DESC)."""
    pid = db.create_project("Проект")
    with db._tx() as c:
        for name, version in (("t1", "1.0.0"), ("t2", "2.0.0")):
            task = c.execute("INSERT INTO sca2_tasks(project_id, import_id, task_id, contract, answer_contract, validator_version,"
                             " state, manifest_sha256, created_at, updated_at) VALUES (?, 0, ?, 'c', 'a', 'v', 'current', 'm',"
                             " '2026-01-01', '2026-01-01') RETURNING id", (pid, name)).fetchone()[0]
            c.execute("INSERT INTO sca2_task_rows(task_id, input_ref, ecosystem, name, version) VALUES (?, 'ref', 'npm',"
                      " 'left-pad', ?)", (task, version))
    assert db.current_task(pid)["task_id"] == "t2"
    assert db.task_row(pid, "ref")["version"] == "2.0.0", "строка – того же задания, что current_task"


def test_current_decisions_take_the_highest_revision(db: Database):
    """Словарь действующих решений: при двух текущих по одной строке – решение с большей ревизией, как у decision() и у записи
    следующей ревизии (ORDER BY revision DESC). Старшая ревизия вставлена первой: чтение подряд отдало бы последней младшую."""
    pid = db.create_project("Проект")
    with db._tx() as c:
        for revision, action in ((2, "update"), (1, "accept")):
            c.execute("INSERT INTO sca2_decisions(project_id, input_ref, revision, action, rationale, state, decided_at)"
                      " VALUES (?, 'ref', ?, ?, 'Причина.', 'current', '2026-01-01')", (pid, revision, action))
        c.execute("INSERT INTO sca2_decisions(project_id, input_ref, revision, action, rationale, state, decided_at)"
                  " VALUES (?, 'other', 1, 'accept', 'Причина.', 'current', '2026-01-01')", (pid,))
    with db._tx() as c:
        c.execute("ANALYZE sca2_decisions")  # со статистикой маленькая таблица читается подряд, как рабочая
    decisions = db.decisions(pid)
    assert set(decisions) == {"ref", "other"}
    assert decisions["ref"]["revision"] == 2 and decisions["ref"]["action"] == "update"
    assert db.decision(pid, "ref")["revision"] == 2, "то же решение, что отдаёт чтение одной строки"
