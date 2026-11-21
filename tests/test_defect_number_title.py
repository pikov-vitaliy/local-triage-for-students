"""Номер дефекта ID (ADR-0138): пропавший из заголовка в Hub номер возвращается при Push. Данные выдуманы, сети нет."""

from __future__ import annotations

import json

from app import defect, hub_defects
from test_hub_defect_import import apply_sync, deliver, sync, take
from test_hub_defect_update import hub_body, phase, put_click, read_job, ready, sent_body, to_preview as update_preview
from test_hub_defects import hello
from test_web import web  # noqa: F401

NO_ID = "SQL injection (SAST)"


def lost(web) -> tuple[int, dict]:
    pid, row = ready(web, build=False)
    hello(web)
    assert sync(web, pid, row["id"]).status_code == 200
    read_job(web, hub_body(summary=NO_ID))
    return pid, web.app.state.db.hub_defect(row["id"])


def test_preview_warns_and_apply_keeps_the_number(web):
    pid, row = lost(web)
    db = web.app.state.db
    page = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    assert "следующий «Push в Hub» вернёт его" in page
    assert apply_sync(web, pid, row["id"]).status_code == 200
    fresh = db.hub_defect(row["id"])
    assert fresh["number"] == row["number"] and fresh["summary"] == NO_ID


def test_push_returns_the_number_to_the_title(web):
    pid, row = lost(web)
    db = web.app.state.db
    assert apply_sync(web, pid, row["id"]).status_code == 200
    update_preview(web, pid, db.hub_defect(row["id"]), hub_body(summary=NO_ID))
    preview = db.hub_defect(row["id"])
    state = hub_defects.update_state(preview)
    assert phase(db, row["id"]) == "preview", state.get("refusals")
    assert state["new"]["summary"] == f"ID{row['number']} - {NO_ID}"
    assert any("возвращает" in w for w in state["warnings"])
    assert put_click(web, pid, preview).status_code == 200
    read_job(web, hub_body(summary=NO_ID))
    put = take(web)
    assert put["body"]["summary"] == f"ID{row['number']} - {NO_ID}"
    deliver(web, put, 204, text="")
    read_job(web, sent_body(db, row["id"]))
    assert phase(db, row["id"]) == "done", hub_defects.update_state(db.hub_defect(row["id"]))
    assert db.defect_number(pid, defect.defect_key_sast("510001")) == row["number"]


def test_title_with_two_numbers_is_still_refused(web):
    pid, row = ready(web, build=True)
    db = web.app.state.db
    update_preview(web, pid, row, hub_body(summary="ID5 и ID6 - x (SAST)"))
    assert phase(db, row["id"]) == "refused"
    assert "неоднозначен" in json.dumps(hub_defects.update_state(db.hub_defect(row["id"])), ensure_ascii=False)


def test_other_defect_holding_the_number_still_refuses(web):
    pid, row = lost(web)
    db = web.app.state.db
    assert apply_sync(web, pid, row["id"]).status_code == 200
    db.set_defect_number(pid, defect.defect_key_sast("510009"), row["number"])
    update_preview(web, pid, db.hub_defect(row["id"]), hub_body(summary=NO_ID))
    assert "занят" in json.dumps(hub_defects.update_state(db.hub_defect(row["id"])), ensure_ascii=False)


def test_ambiguous_title_is_not_a_lost_number(web):
    pid, row = ready(web, build=False)
    db = web.app.state.db
    hello(web)
    assert sync(web, pid, row["id"]).status_code == 200
    read_job(web, hub_body(summary="ID5 и ID6 - x (SAST)"))
    state = json.loads(db.hub_defect(row["id"])["sync_json"])
    assert not any("пропал" in w for w in state["warnings"]) and any("неоднозначен" in w for w in state["warnings"])
    assert apply_sync(web, pid, row["id"]).status_code == 200
    assert db.hub_defect(row["id"])["number"] is None, "номер не берётся"


def test_second_pull_after_lost_number_matches(web):
    pid, row = lost(web)
    db = web.app.state.db
    assert apply_sync(web, pid, row["id"]).status_code == 200
    assert sync(web, pid, row["id"]).status_code == 200
    read_job(web, hub_body(summary=NO_ID))
    assert json.loads(db.hub_defect(row["id"])["sync_json"]).get("matches") is True, "без изменений предпросмотра нет"


def test_empty_draft_title_is_refused(web):
    pid, row = ready(web, build=True)
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET draft_summary = '   ' WHERE id = ?", (row["id"],))
    update_preview(web, pid, db.hub_defect(row["id"]))
    assert "Заголовок черновика пуст" in json.dumps(hub_defects.update_state(db.hub_defect(row["id"])), ensure_ascii=False)
    assert phase(db, row["id"]) == "refused"
