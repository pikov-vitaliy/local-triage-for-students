"""Карточка находки (план dev7, раздел 4): действующий статус Hub с источником и датой, инструкция только без автоматической отправки,
статус «Fixed» без формы и с отказом сервера и массовой отправки. Данные выдуманы, сети нет."""

from __future__ import annotations

import pytest

from app.db import dumps
from app.routes import hub_status_routes as routes
from test_hub_status_routes import HUB, decide, fid, project, run_worker, sast, send, shown_send_fields
from test_web import ORIGIN, web  # noqa: F401


def accept_state(web, pid: int, hub_id: str, status: str, app_id: int = 7) -> None:
    """Принятая сверка: подробное чтение находки и версия из синхронизации."""
    db = web.app.state.db
    with db._tx() as c:
        c.execute("INSERT INTO hub_issue_states(project_id, hub_url, app_id, issue_type, issue_id, confirmed_json, confirmed_presence)"
                  " VALUES (?, ?, ?, 'SAST', ?, ?, 'present')",
                  (pid, routes.hub_ops.hub_base(HUB), app_id, hub_id, dumps({"detail": {"status": status}})))


def card(web, pid: int, hub_id: str) -> str:
    return web.client.get(f"/projects/{pid}/findings/{fid(web, pid, hub_id)}").text


def test_status_from_export_when_nothing_else(web):
    pid = project(web, [sast("101")])
    page = card(web, pid, "101")
    assert 'id="hub-status-now"' in page and "из выгрузки" in page


def test_status_from_accepted_sync(web):
    pid = project(web, [sast("101")])
    accept_state(web, pid, "101", "To verify")
    page = card(web, pid, "101")
    assert "To verify" in page.split('id="hub-status-now"')[1].split("</span></span>")[0] and "принятая сверка" in page


def test_status_from_confirmed_write_with_date(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    assert send(web, pid, "101").status_code == 200
    run_worker(web, body={"id": 1, "status": "False Positive"})
    now = web.app.state.db.on_connection(lambda c: routes.status_now_in(c, pid, "101", "SAST", "Open", HUB, 7))
    assert now["status"] == "False Positive" and now["source"] == "подтверждённая запись" and now["at"], now
    assert "подтверждённая запись" in card(web, pid, "101")


def test_other_hub_target_is_not_trusted(web):
    pid = project(web, [sast("101")])
    accept_state(web, pid, "101", "Fixed", app_id=8)
    now = web.app.state.db.on_connection(lambda c: routes.status_now_in(c, pid, "101", "SAST", "Open", HUB, 7))
    assert now["status"] == "Open" and now["source"] == "из выгрузки" and now["at"], now


def test_manual_instruction_only_without_send(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    page = card(web, pid, "101")
    assert 'id="hub-send-form"' in page and 'id="hub-manual-instr"' not in page and 'id="go-send"' in page


def test_fixed_has_no_form_and_server_refuses(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    fields = shown_send_fields(web, pid, "101")
    accept_state(web, pid, "101", "Fixed")
    page = card(web, pid, "101")
    assert 'id="hub-send-fixed"' in page and "issue was fixed" in page and 'id="hub-send-form"' not in page and 'id="go-send"' not in page
    answer = web.client.post(f"/projects/{pid}/findings/{fid(web, pid, '101')}/hub-status", headers={**ORIGIN, "Accept": "application/json"}, data=fields)
    assert answer.status_code >= 400 and "Fixed" in answer.text, answer.text


def test_fixed_hides_old_refusal_and_keeps_open_operation(web):
    """Проход в браузере 06.11: под «Отправлять нечего» стояло «Hub не принял … Можно отправить ещё раз»."""
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    db = web.app.state.db
    assert send(web, pid, "101").status_code == 200
    run_worker(web, status=400, body={"message": "Unable to change status: issue was fixed"})
    assert "Можно отправить ещё раз" in card(web, pid, "101"), "до сверки отказ виден"
    accept_state(web, pid, "101", "Fixed")
    page = card(web, pid, "101")
    assert 'id="hub-send-fixed"' in page and "Можно отправить ещё раз" not in page
    assert db.hub_last_op(pid, "101", "status")["state"] == "failed", "история операции не меняется"


@pytest.mark.parametrize("status, source_ok, shown", [("False Positive", True, False), ("To verify", True, True), ("False Positive", False, True)])
def test_manual_mark_note_does_not_contradict_confirmed_status(status, source_ok, shown):
    """Проход в браузере 06.11: «статус ею не подтверждён» рядом с «в Hub: False Positive (подтверждённая запись)»."""
    note = "Ручная или прежняя отметка без назначения; статус в текущем Hub ею не подтверждён."
    review = {"entered_scope_note": note, "entered_origin": "manual", "entered_hub": 1, "decision": "disagree", "final_verdict": "false_positive"}
    view = {"status": status, "source": "подтверждённая запись" if source_ok else "из выгрузки"}
    assert routes.entered_scope_note(review, view) == (note if shown else "")


def test_note_of_another_hub_stays(web):
    note = "Прежняя отметка относится к другому Hub."
    review = {"entered_scope_note": note, "entered_origin": "status", "entered_hub": 0, "decision": "disagree", "final_verdict": "false_positive"}
    assert routes.entered_scope_note(review, {"status": "False Positive", "source": "принятая сверка"}) == note
    assert routes.entered_scope_note(None, {}) == ""


def test_fixed_from_export_names_basis_and_way_to_refresh(web):
    pid = project(web, [sast("101")])
    db = web.app.state.db
    with db._tx() as c:
        row = c.execute("SELECT data_json FROM findings WHERE project_id = ? AND hub_id = '101'", (pid,)).fetchone()
        c.execute("UPDATE findings SET data_json = ? WHERE project_id = ? AND hub_id = '101'",
                  (dumps({**routes.loads(row[0], {}), "status": "Fixed"}), pid))
    decide(web, pid, "101")
    page = card(web, pid, "101")
    assert "из выгрузки от" in page and "мог устареть" in page and 'id="hub-send-fixed-sync"' in page and 'id="hub-send-form"' not in page
    accept_state(web, pid, "101", "Open")
    page = card(web, pid, "101")
    assert 'id="hub-send-form"' in page and 'id="hub-send-fixed"' not in page, "сверка показала открытую находку – форма вернулась"


def test_transaction_refuses_when_status_became_fixed(web):
    """Pull принёс «Fixed» между проверкой и постановкой: транзакция не ставит запись."""
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    db = web.app.state.db
    review = db.get_review(pid, "101")
    targets = [{"hub_id": "101", "revision": review["revision"], "sig": db.finding_sig(pid, "101")}]
    check = routes._revisions_check(pid, targets, "False Positive", [], HUB, 7)
    db.on_connection(check)
    accept_state(web, pid, "101", "Fixed")
    with pytest.raises(routes.StaleTarget, match="Fixed"):
        db.on_connection(check)


def test_write_without_version_row_is_recognized(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    assert send(web, pid, "101").status_code == 200
    run_worker(web, body={"id": 1, "status": "False Positive"})
    db = web.app.state.db
    with db._tx() as c:
        c.execute("DELETE FROM hub_entity_versions WHERE project_id = ?", (pid,))
    now = db.on_connection(lambda c: routes.status_now_in(c, pid, "101", "SAST", "Open", HUB, 7))
    assert now["source"] == "подтверждённая запись" and now["status"] == "False Positive"


def test_fixed_neighbor_is_left_out_of_group(web):
    pid = project(web, [sast("101"), sast("102")])
    decide(web, pid, "101")
    decide(web, pid, "102")
    accept_state(web, pid, "102", "Fixed")
    assert send(web, pid, "101").status_code == 200
    job = run_worker(web, body={"id": 1, "status": "False Positive"})
    assert job["body"]["issueId"] == 101, job
    assert web.app.state.db.get_review(pid, "102")["entered_hub"] == 0


def test_bulk_send_excludes_fixed(web):
    pid = project(web, [sast("101"), sast("102", line=3)])
    decide(web, pid, "101")
    decide(web, pid, "102")
    accept_state(web, pid, "102", "Fixed")
    page = web.client.get(f"/projects/{pid}/hub/send-selected", params={"hub_id": ["101", "102"]}).text
    assert "Hub отклонил бы смену статуса" in page, page[:400]
