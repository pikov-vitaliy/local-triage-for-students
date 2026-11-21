"""Ревью кода 0.10.0.dev15, круг 3 (Codex xhigh 0/4/1): регрессии на каждую подтверждённую находку. Данные выдуманные."""
import re
from types import SimpleNamespace

import pytest

from app import hub_sync_compare as compare
from app.db import dumps
from test_dev15_review_r1 import replaced_by_hub, saved_id
from test_hub_status_routes import decide, project, sast, send
from test_sync_golden_path import LiveHub, drain, synced, synchronize
from test_sync_saved_edits import restore_saved
from test_web import web  # noqa: F401


def test_restored_and_sent_edit_without_expiry_is_delivered_after_accept(web):
    """Codex 1: восстановленная правка без срока, отправленная со сроком формы и принятая Hub, – «доставлено», а не
    «заменено Hub» (доказательство доставки – из данных до принятия)."""
    db, pid, hub = replaced_by_hub(web)
    ident = saved_id(db, pid)
    restore_saved(web, pid, ident)
    answer = send(web, pid, "1", extra={"replace": "1", "replace_confirm": "1"})
    assert answer.status_code == 200
    # замена комментария – два шага: «Подтверждено», затем решение с новым основанием; второй ставит опрос карточки
    for _ in range(3):
        drain(db, hub)
        web.client.get(answer.json()["status_url"])
    drain(db, hub)
    assert hub.manual[1]["status"] == "False Positive" and hub.manual[1]["reason"] == "Основание оператора"
    synchronize(db, pid, hub)
    assert db._one("SELECT state FROM hub_sync_pending WHERE id=?", (ident,))["state"] == "delivered"


def test_delivered_body_is_compared_with_accepted_including_expiry():
    """Kimi круг 3: доставленная операция со сроком 26.01 не закрывает правку, если принят срок 01.02."""
    from app import hub_pull as pull
    mine = {"status": "False Positive", "reason": "R"}
    sent = {"status_intent": {"state": "done", "body": {**mine, "expiredAt": "2027-01-26T00:00:00Z"}}}
    assert not pull.history_matches("restored", mine, {**mine, "expiredAt": "2027-02-01T00:00:00Z"}, sent)
    assert pull.history_matches("restored", mine, {**mine, "expiredAt": "2027-01-26T00:00:00Z"}, sent)


@pytest.mark.parametrize("update, state, action", [
    ({"phase": "unknown"}, "unconfirmed", "verify"),
    ({"phase": "confirming", "note": "подтверждающее чтение не прошло"}, "unconfirmed", "reread"),
    ({"phase": "unconfirmed"}, "unconfirmed", "reread"),
])
def test_push_outcome_names_the_available_action(update, state, action):
    """Codex 2, 3: при неизвестном исходе – «Сверить», после сбоя подтверждающего чтения – «Повторить чтение»; без
    операции это не «выполняется»."""
    local = {"owner": {"update_json": dumps(update)}}
    diff = {"groups": ["pending"], "current_pending": True}
    found = compare.delivery_of("defect", "77", local, diff, None)
    assert found["state"] == state and found.get("action") == action, found
    cause = compare.causes("defect", "77", local, {**diff, "delivery": found}, None)[0]
    assert ("«Сверить»" if action == "verify" else "«Повторить чтение»") in cause and "«Pull из Hub»" not in cause


def test_push_with_operation_in_queue_is_running():
    local = {"owner": {"update_json": dumps({"phase": "confirming"}), "update_op_id": 7}}
    found = compare.delivery_of("defect", "77", local, {"groups": ["pending"], "current_pending": True}, None)
    assert found["state"] == "queued"


def test_status_request_not_sent_is_not_a_hub_refusal():
    """Codex 4: исполнитель запрос не отправлял – «не отправлено» с причиной, а не «Hub не принял»."""
    local = {"review": {"decision_origin": "operator"}, "status_intent": {"op_id": 9, "state": "failed"}}
    context = SimpleNamespace(last_status={"SAST:1": {"id": 9, "state": "failed", "created_at": "",
                                                      "error": "запрос в Hub не отправлен: Hub недоступен"}})
    found = compare.delivery_of("issue", "SAST:1", local, {"groups": ["pending"], "current_pending": True}, context)
    assert found["state"] == "unsent" and found["error"].startswith("запрос в Hub не отправлен"), found
    context.last_status["SAST:1"]["error"] = "Bad Request"
    assert compare.delivery_of("issue", "SAST:1", local, {"groups": ["pending"], "current_pending": True},
                               context)["state"] == "refused"


def test_sync_page_search_opens_the_group_of_the_found_object(web):
    """Codex 5: ссылка значка по ключу открывает группу, где объект стоит в сохранённом сравнении."""
    db = web.app.state.db
    hub = LiveHub(2)
    pid = project(web, [sast("1"), sast("2", line=5)])
    synchronize(db, pid, hub)
    row = synced(db, pid, hub)
    decide(web, pid, "1")  # после сравнения: на странице – «не отправлено», в сохранённом сравнении – «совпадает»
    page = web.client.get(f"/projects/{pid}/hub-sync/{row['id']}", params={"q": "SAST:1"}).text
    opened = re.findall(r'<details class="panel" data-sync-group="(\w+)" open>', page)
    assert opened and 'data-sync-item="issue:SAST:1"' in page, opened
