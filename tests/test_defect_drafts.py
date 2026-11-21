"""Черновик независим от решений, запись и сборка атомарны."""

import pytest

from app import defect_drafts
from app.db import Database


@pytest.fixture
def draft(tmp_path):
    db = Database(tmp_path / "t.db")
    pid = db.create_project("Демо")
    row = db.hub_defect_insert(pid, kind="SAST", number=5, summary="ID5 - Дефект (SAST)", anchor_hub_id="1",
                               targets=[], number_keys=[], command_text="Исходный текст", hub_url="https://hub.example.org",
                               app_id=1)
    db.hub_defect_update(row["id"], state="done", hub_defect_id="777")
    yield db, db.hub_defect(row["id"])
    db.close()


def test_edit_and_stale_form(draft):
    db, row = draft
    saved = defect_drafts.save(db, row, "1", summary="ID5 - Новый", command="Правка")
    assert saved["draft_revision"] == 2 and saved["summary"] == row["summary"]
    assert saved["command_text"] == "Исходный текст" and saved["draft_command_text"] == "Правка"
    with pytest.raises(ValueError, match="другой вкладке"):
        defect_drafts.save(db, row, "1", summary="устаревший", command="старый")
    assert db.hub_defect(row["id"])["draft_summary"] == "ID5 - Новый"
    assert [x["event"] for x in db._all("SELECT * FROM hub_defect_history ORDER BY id")] == ["create", "edit"]
    assert db._all("SELECT * FROM hub_ops ORDER BY 1, 2") == []


def test_generate_rollback_and_fields_preserved(draft):
    db, row = draft
    db.hub_defect_update(row["id"], draft_fields_json='{"settings":null}')
    before = db.hub_defect(row["id"])
    events = db._all("SELECT * FROM hub_defect_history ORDER BY id")
    with pytest.raises(ValueError, match="генератор"):
        defect_drafts.save(db, row, "1", generate=lambda current: {"refusals": ["ошибка генератора"]})
    assert db.hub_defect(row["id"]) == before
    assert db._all("SELECT * FROM hub_defect_history ORDER BY id") == events
    saved = defect_drafts.save(db, row, "1", generate=lambda current: {"summary": "ID5 - Собран", "command_text": "Текст"})
    assert saved["draft_fields_json"] == '{"settings":null}' and saved["draft_revision"] == 2


@pytest.mark.parametrize("fields", [
    {"state": "unknown"}, {"state": "preview"}, {"update_json": '{"phase":"unconfirmed"}'},
    {"update_json": '{"phase":"preview"}'}, {"conflicts_json": '["конфликт"]'},
    {"sync_op_id": 7}, {"verify_op_id": 8},
])
def test_busy_draft_rejects_edit(draft, fields):
    db, row = draft
    db.hub_defect_update(row["id"], **fields)
    if "conflicts_json" in fields:
        saved = defect_drafts.save(db, row, "1", summary="новый", command="новый")
        assert saved["draft_revision"] == 2 and saved["conflicts_json"] == fields["conflicts_json"]
        assert db._all("SELECT * FROM hub_ops ORDER BY 1, 2") == []
        return
    with pytest.raises(ValueError):
        defect_drafts.save(db, row, "1", summary="новый", command="новый")
    assert db.hub_defect(row["id"])["draft_revision"] == 1
