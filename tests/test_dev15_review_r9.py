"""Ревью кода 0.10.0.dev15, круг 9: неизвестный исход отправки виден и тогда, когда прочитанное совпадает с Hub
(принятие ждёт результата операции); обзор проекта называет доставленные решения нейтрально – «отправлено в Hub»;
страница чтения Hub показывает сведения отправки теми же подписями, что списки и карточки."""
from types import SimpleNamespace

import pytest

from app import hub_pull as pull, hub_state, hub_sync_compare as compare
from app.db import loads
from test_hub_status_routes import HUB, decide, project, sast, send
from test_sync_golden_path import LiveHub, synced, synchronize
from test_web import web  # noqa: F401

UNKNOWN = {"review": {"decision_origin": "operator", "decision": "agree", "final_verdict": "false_positive",
                      "final_comment": "R"},
           "status_intent": {"op_id": 7, "state": "unknown", "body": {"status": "False Positive", "reason": "R",
                                                                      "expiredAt": "2027-01-26T00:00:00Z"}}}


@pytest.mark.parametrize("observed", [True, False])
def test_unknown_outcome_is_unconfirmed_even_when_hub_matches(observed):
    diff = {"groups": ["matched"] if observed else [], "current_pending": False}
    found = compare.delivery_of("issue", "SAST:1", UNKNOWN, diff, None, {}, observed=observed)
    assert found["state"] == "unconfirmed", found
    st = hub_state._state(1, 5, "issue", "SAST:1", {"groups": ["matched"]}, found)
    assert st["unsent"] and [b["text"] for b in st["badges"]] == [compare.DELIVERY_LABELS["unconfirmed"]], st


def test_unknown_outcome_names_the_button_when_hub_matches():
    context = SimpleNamespace(last_status={"SAST:1": {"id": 7, "state": "unknown", "created_at": "2026-11-08T10:00:00+00:00",
                                                      "error": ""}})
    diff = {"groups": ["matched"], "current_pending": False, "delivery": {"state": "unconfirmed"}}
    found = compare.causes("issue", "SAST:1", UNKNOWN, diff, context)
    assert any("неизвестен" in c and "«Pull из Hub»" in c for c in found), found


def test_lost_answer_matching_hub_is_shown_and_waits_for_the_outcome(web):
    """Codex 9 №1: Hub выполнил отправку, ответ потерялся (исход неизвестен), чтение показывает то же решение. На
    страницах – «Отправка не подтверждена», а не «всё совпадает»; принятие ждёт результата операции."""
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    synchronize(db, pid, hub)
    decide(web, pid, "1")
    answer = send(web, pid, "1").json()
    got = db.hub_claim("demo", HUB, 120, sync_protocol=2)
    assert got["op"]["id"] == answer["op_id"], got["op"]
    hub.answer(loads(got["op"]["request_json"], {}))  # Hub запись выполнил
    db.hub_result(got["attempt"]["id"], got["attempt"]["lease_token"],
                  {"status": 0, "body_text": "", "error": "timeout", "truncated": False})  # ответ до приложения не дошёл
    assert db.hub_op(answer["op_id"])["state"] == "unknown"
    row = synced(db, pid, hub)
    diff = loads(db._one("SELECT diff_json FROM hub_sync_items WHERE run_id=? AND entity_key='SAST:1'",
                         (row["id"],))["diff_json"], {})
    # Hub и приложение изменились одинаково после принятой базы – для оператора совпадение
    assert set(diff["groups"]) <= {"matched", "coincident"} and diff["delivery"]["state"] == "unconfirmed", diff
    assert any("неизвестен" in c for c in diff["causes"]), diff["causes"]
    states = hub_state.project_states(db, db.get_project(pid), HUB)
    st = states["by_hub_id"]["1"]
    assert st["unsent"] and compare.DELIVERY_LABELS["unconfirmed"] in [b["text"] for b in st["badges"]], st
    assert not states["summary"]["all_match"] and states["summary"]["counts"]["unconfirmed"] == 1, states["summary"]
    page = web.client.get(f"/projects/{pid}/hub-sync/{row['id']}").text
    assert 'class="hub-sync-delivery">Отправка не подтверждена<' in page
    run = db._one("SELECT * FROM hub_defect_sync_runs WHERE id=?", (row["id"],))
    with pytest.raises(ValueError, match="незавершённая операция"):
        pull.apply(db, row["id"], pull.preview(db, run)["token"])
