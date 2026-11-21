"""Пояснение номера вычисляется после проверки в транзакции принятия Hub."""

import pytest

from app import hub_defects
from app.db import text_hash
from test_hub_defect_import import accept, answer, defect_body, preview_of, project, sync, tab
from test_web import web  # noqa: F401


@pytest.mark.parametrize("action", ["accept", "apply"])
def test_note_sees_number_taken_before_transaction(web, monkeypatch, action):
    pid = project(web)
    db = web.app.state.db
    row = preview_of(web, pid)
    if action == "apply":
        assert accept(web, pid, row["id"]).status_code == 200
        assert sync(web, pid, row["id"]).status_code == 200
        answer(web, body=defect_body(summary="ID5 - Новое название (SAST)"))
        tab(web, pid)
        row = db.hub_defect(row["id"])
    advance = db.hub_defect_advance
    checked = []
    reads = []
    note = hub_defects.number_note_in

    def interleave(*args, **kwargs):
        # Другая запись заняла номер после подготовки аргументов, до начала транзакции.
        db.set_defect_number(pid, "sast:510003", 5)
        check = kwargs["check"]

        def check_in(c):
            check(c)
            checked.append(c)
        kwargs["check"] = check_in
        return advance(*args, **kwargs)

    def on_connection(c, *args):
        assert checked and c is checked[-1]
        reads.append(c)
        return note(c, *args)

    monkeypatch.setattr(db, "hub_defect_advance", interleave)
    monkeypatch.setattr(hub_defects, "number_note_in", on_connection)
    if action == "accept":
        result = hub_defects.accept_import(db, row, op_id=row["read_op_id"], shown=text_hash(row["import_json"]))
    else:
        result = hub_defects.apply_import_sync(db, row, shown=text_hash(row["sync_json"]))
    assert len(reads) == 1
    assert "номер ID5 уже занят" in result["error"] and "sast:510003" in result["error"]
    assert result["number"] == 5


def test_bad_computed_field_rolls_back_check(web):
    pid = project(web)
    db = web.app.state.db
    row = preview_of(web, pid)

    def check(c):
        c.execute("UPDATE hub_defects SET error = 'промежуточно' WHERE id = ?", (row["id"],))

    with pytest.raises(ValueError, match="неизвестные поля"):
        db.hub_defect_advance(row["id"], expect_state="import_preview", check=check,
                              fields_after_check=lambda c: {"unknown_field": "x"})
    fresh = db.hub_defect(row["id"])
    assert fresh["error"] == row["error"] and fresh["state"] == row["state"]
