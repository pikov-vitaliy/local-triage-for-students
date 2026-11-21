"""Ревью кода 0.10.0.dev15, круги 7–8 (оператор нажал «Отправить», Hub ответил «принято» –
процесс закончен): доставленное решение навсегда «отправлено», в том числе когда Hub потом его снял; неотправленные
сохранённые правки не скрываются доставкой текущего решения ни с наблюдением, ни без него; порядок по времени и номерам
операций не нужен."""
import pytest

from app import hub_pull as pull, hub_state, hub_sync_compare as compare
from app.db import loads
from test_hub_status_routes import HUB, decide, project, sast, send
from test_sync_golden_path import LiveHub, drain, synchronize
from test_web import web  # noqa: F401

LOCAL = {"review": {"decision_origin": "operator", "decision": "agree", "final_verdict": "false_positive",
                    "final_comment": "R"},
         "status_intent": {"op_id": 100, "state": "done", "body": {"status": "False Positive", "reason": "R",
                                                                   "expiredAt": "2027-01-26T00:00:00Z"}}}
OPEN = {"detail": {"status": "To verify", "currentBranch": "main"}}


@pytest.mark.parametrize("base", [OPEN, {}])
def test_delivered_decision_never_waits_for_sending(base):
    assert not pull.pending_change("issue", LOCAL, base, OPEN)[0]


def test_delivered_decision_is_sent_when_hub_shows_other():
    diff = {"groups": ["local_only"], "current_pending": False}
    assert compare.delivery_of("issue", "SAST:1", LOCAL, diff, None, {"detail": {"op_id": 101}})["state"] == "sent"
    assert compare.delivery_of("issue", "SAST:1", LOCAL, {"groups": ["matched"]}, None, {})["state"] is None
    st = hub_state._state(1, 5, "issue", "SAST:1", diff, {"state": "sent"})
    assert [b["text"] for b in st["badges"]] == [compare.DELIVERY_LABELS["sent"], compare.LABELS["local_only"]]


@pytest.mark.parametrize("observed", [True, False])
def test_unsent_stored_edit_is_not_hidden_by_delivery_of_the_current_decision(observed):
    """Codex 7 №2 и 8 №3: восстановленная правка A не отправлена, доставлено решение B – «не отправлено», и без
    наблюдения объекта тоже."""
    diff = {"groups": ["pending"] if observed else [], "current_pending": False, "pending_ids": [7],
            "stored_dates": ["2026-11-08T09:00:00+00:00"]}
    found = compare.delivery_of("issue", "SAST:1", LOCAL, diff, None, {}, observed=observed)
    assert found["state"] == "unsent" and found["stored"] == 1, found


def test_decision_accepted_by_hub_follows_hub_when_hub_removes_it(web):
    """Доставить → Hub принял → состояние Hub принято (решение – из Hub) → Hub снял → принять: приложение следует
    за Hub, решение снимается, совпадает, остатка нет (Hub – источник истины). Случай «отправили, а Hub решения так и
    не показал» – тесты aud09: решение оператора остаётся «отправлено» с отличием."""
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    synchronize(db, pid, hub)
    decide(web, pid, "1")
    assert send(web, pid, "1").status_code == 200
    drain(db, hub)
    synchronize(db, pid, hub)
    hub.issues[1]["status"] = "To verify"  # в Hub решение сняли
    hub.issues[1]["issueBranchBriefData"][0]["status"] = "To verify"
    hub.manual.pop(1, None)
    row = synchronize(db, pid, hub)
    result = loads(db._one("SELECT result_json FROM hub_defect_sync_runs WHERE id=?", (row["id"],))["result_json"], {})
    assert result["residue"] == [], result
    diff = loads(db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=? AND entity_key='SAST:1'",
                         (row["id"],))["diff_json"], {})
    assert diff["groups"] == ["matched"], diff
    state = hub_state.project_states(db, db.get_project(pid), HUB)["by_hub_id"]["1"]
    assert not state["unsent"] and not state["differs"], state
