"""Ревью кода 0.10.0.dev15, круг 10: замена комментария в Hub в два шага – одна отправка конечного решения (первый шаг
в очереди – «ждёт исполнителя», неизвестный исход – «не подтверждена», выполненный первый шаг без второго – «не
отправлено»); счётчики обзоров называют не отправленное, ждущее исполнителя и неподтверждённое раздельно."""
import json

from app import hub_state, hub_status
from test_hub_status_replace_dev29 import NEW, entered_once
from test_hub_status_routes import AS_JSON, HUB, decide, project, run_worker, sast, sca, send
from test_web import web  # noqa: F401


def delivery(db, pid, hub_id):
    return hub_state.project_states(db, db.get_project(pid), HUB)["by_hub_id"][hub_id]["delivery"]["state"]


def test_replace_chain_is_one_sending_of_the_final_decision(web):
    db = web.app.state.db
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")
    decide(web, pid, "101", comment=NEW)
    answer = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"}).json()
    assert hub_status.is_reset(db.hub_op(answer["op_id"]))
    assert delivery(db, pid, "101") == "queued"  # первый шаг ждёт исполнителя, а не «не отправлено»
    run_worker(web, status=0, error="timeout")
    assert db.hub_op(answer["op_id"])["state"] == "unknown"
    assert delivery(db, pid, "101") == "unconfirmed"  # как карточка: «Результат первого шага неизвестен»
    r = web.client.post(f"/projects/{pid}/hub/verify", data={"op_id": str(answer["op_id"])}, headers=AS_JSON)
    assert r.status_code == 200, r.text
    run_worker(web, body={"status": hub_status.RESET_STATUS, "reason": hub_status.RESET_REASON,
                          "expiredAt": "2027-01-26T00:00:00Z"})
    assert db.hub_op(answer["op_id"])["state"] == "done"
    assert delivery(db, pid, "101") == "queued"  # второй шаг поставлен и ждёт исполнителя
    run_worker(web)
    assert db.get_review(pid, "101")["entered_hub"] == 1
    assert delivery(db, pid, "101") == "sent"  # конечное решение доставлено; Hub не читался


def test_done_first_step_alone_does_not_deliver_the_final_decision(web):
    db = web.app.state.db
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")
    decide(web, pid, "101", comment=NEW)
    op_id = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"}).json()["op_id"]

    def first_step(chained):
        request = json.loads(db.hub_op(op_id)["request_json"])
        request["then"] = {k: v for k, v in request["then"].items() if k != "chained"}
        if chained is not None:
            request["then"]["chained"] = chained
        with db._tx() as c:
            c.execute("UPDATE hub_ops SET state='done', request_json=? WHERE id=?", (json.dumps(request), op_id))

    first_step(None)  # последствия ответа ещё не доставлены: второй шаг ставится
    assert delivery(db, pid, "101") == "queued"
    first_step(0)  # второй шаг не поставлен (пояснение в первом): конечное решение не отправлено
    assert delivery(db, pid, "101") == "unsent"


def test_counters_keep_unconfirmed_and_queued_apart(web):
    db = web.app.state.db
    pid = project(web, [sast("1"), sast("2", line=5)])  # разные места – не одна групповая отправка
    decide(web, pid, "1")
    decide(web, pid, "2")
    assert send(web, pid, "1").status_code == 200
    with db._tx() as c:  # ответ первой отправки потерялся – исход неизвестен
        c.execute("UPDATE hub_ops SET state='unknown' WHERE project_id=? AND purpose='status'", (pid,))
    overview = web.client.get(f"/projects/{pid}").text
    assert "решений, не отправленных в Hub, – 1, без подтверждения – 1" in overview, overview[overview.find("step-hub-sync-line"):][:400]
    summary = hub_state._summary(pid, None, None, {
        ("defect", "77"): {"kind": "defect", "delivery": {"state": "unconfirmed"}, "differs": False},
        ("defect", "78"): {"kind": "defect", "delivery": {"state": "queued"}, "differs": False}}, True, True)
    assert summary["defects"] == {"unsent": 0, "queued": 1, "unconfirmed": 1, "refused": 0, "differs": 0}, summary


def test_sca_group_counters_name_the_delivery_state(web):
    db = web.app.state.db
    pid = project(web, [sca("201")])
    decide(web, pid, "201", decision="disagree", verdict="false_positive")
    assert send(web, pid, "201", kind="sca/findings").status_code == 200
    page = web.client.get(f"/projects/{pid}/sca").text
    assert "ждёт исполнителя 1" in page and "не отправлено в Hub 1" not in page
    with db._tx() as c:
        c.execute("UPDATE hub_ops SET state='unknown' WHERE project_id=? AND purpose='status'", (pid,))
    page = web.client.get(f"/projects/{pid}/sca").text
    assert "без подтверждения 1" in page and "не отправлено в Hub 1" not in page
