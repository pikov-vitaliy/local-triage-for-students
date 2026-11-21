"""Замена комментария у статуса, который уже стоит в Hub (dev29, ADR-0130): панель «Отправить в Hub»
переходит в режим «Обновить комментарий в Hub», обычная отправка того же статуса отклоняется до запроса, замена идёт
двумя операциями (промежуточный статус «Confirmed», затем прежний статус с новым комментарием) по подтверждению; первый шаг отметок не
ставит; отказ Hub «already has the requested status» переводит панель в тот же режим. Данные выдуманы, сети нет."""

from __future__ import annotations

import json
import re

import pytest

from app import hub_effects, hub_status
from app.db import text_hash
from app.routes import hub_status_routes
from test_hub_status_routes import (  # noqa: F401
    AS_JSON,
    REASON,
    decide,
    fid,
    fixed_today,
    project,
    run_worker,
    sast,
    sca,
    send,
    shown_send_fields,
    worker_headers,
    web,
)

NEW = "Класс лежит в тестовых исходниках и в артефакт сборки не входит: отладочного кода в продукте нет."
ALREADY = {"errorMessage": "Unable to change status for SAST issue #101: issue already has the requested status "
                           "FALSE_POSITIVE", "requestValidationError": None}


def card(web, pid: int, hub_id: str, kind: str = "findings") -> str:
    return web.client.get(f"/projects/{pid}/{kind}/{fid(web, pid, hub_id)}").text


def expires_value(html: str) -> str:
    found = re.search(r'id="hub-send-expires" value="([^"]*)"', html)
    return found.group(1) if found else ""


def entered_once(web, pid: int, hub_id: str, kind: str = "findings", **decision) -> None:
    """Сохранённое решение отправлено и записано в Hub (поддельный исполнитель ответил 200)."""
    decide(web, pid, hub_id, **decision)
    assert send(web, pid, hub_id, kind=kind).status_code == 200
    run_worker(web, body={"id": 1})
    assert web.app.state.db.get_review(pid, hub_id)["entered_hub"] == 1


# ============================================================================ чистые правила


def test_replace_request_and_helpers():
    target = {"hub_id": "101", "issue_id": 101, "issue_type": "SAST", "revision": 2}
    request = hub_status.replace_request(target, "False Positive", " новый ", "2027-01-26T00:00:00Z")
    assert request["path"] == "/issue/status/update"
    assert request["body"] == {"issueId": 101, "issueType": "SAST", "status": hub_status.RESET_STATUS,
                               "reason": hub_status.RESET_REASON, "expiredAt": "2027-01-26T00:00:00Z"}
    # причина – как написана: отступ первой строки остаётся, хвостовые пробелы – нет (ADR-0149 п. 5)
    assert request["then"] == {"status": "False Positive", "reason": " новый", "expiredAt": "2027-01-26T00:00:00Z"}
    op = {"purpose": "status", "state": "queued", "request_json": request}
    assert hub_status.is_reset(op) and hub_status.chain_of(op) == request["then"]
    assert hub_status.sent_status(op) == hub_status.RESET_STATUS
    plain = {"purpose": "status", "state": "failed", "request_json": '{"body": {"status": "False Positive"}}',
             "error": "Hub ответил кодом 400: Unable to change status: issue already has the requested status FALSE_POSITIVE"}
    assert not hub_status.is_reset(plain) and hub_status.chain_of(plain) == {}
    assert hub_status.already_refused(plain) and hub_status.sent_status(plain) == "False Positive"
    assert not hub_status.already_refused({**plain, "state": "done"})
    assert not hub_status.already_refused({**plain, "error": "Hub ответил кодом 400: bad"})
    with pytest.raises(hub_status.StatusRefused):
        hub_status.replace_request(target, "False Positive", " ", "2027-01-26T00:00:00Z")


# ============================================================================ SAST: путь замены


def test_replace_comment_after_entered(web):
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")
    db = web.app.state.db
    before = db.get_review(pid, "101")
    # обычная панель: отправка записана, режима замены нет
    html = card(web, pid, "101")
    assert 'id="hub-send-replace"' not in html and ">Отправить в Hub</button>" in html
    # оператор поправил обоснование: отметка снята, статус в Hub стоит – панель в режиме замены с прежним сроком
    review = decide(web, pid, "101", comment=NEW)
    assert review["entered_hub"] == 0 and review["revision"] == before["revision"] + 1
    html = card(web, pid, "101")
    assert 'id="hub-send-replace" ' in html or 'id="hub-send-replace">' in html
    assert ">Обновить комментарий в Hub</button>" in html
    assert "уже стоит «Ложное срабатывание», а комментарий там прежний" in html
    assert 'id="hub-send-replace-box" required' in html
    assert expires_value(html) == "2027-01-26", "прежний срок – из выполненной записи статуса"
    # обычная отправка того же статуса отклоняется до запроса
    r = send(web, pid, "101")
    assert r.status_code == 400 and "уже стоит статус «Ложное срабатывание»" in r.json()["detail"], r.text
    # замена без подтверждения – отказ
    r = send(web, pid, "101", extra={"replace": "1"})
    assert r.status_code == 400 and "Подтвердите замену" in r.json()["detail"]
    # замена с подтверждением: первый шаг (промежуточный статус) с записанным вторым
    r = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"})
    assert r.status_code == 200, r.text
    answer = r.json()
    assert "сначала «Подтверждено»" in answer["message"] and "Подтверждено" in answer["text"]["hub-send-status"]
    first = db.hub_op(answer["op_id"])
    assert hub_status.is_reset(first) and hub_status.chain_of(first)["reason"] == NEW
    job = run_worker(web, body={"id": 2, "oldStatus": "False Positive", "status": hub_status.RESET_STATUS})
    assert job["path"] == "/issue/status/update"
    assert job["body"] == {"issueId": 101, "issueType": "SAST", "status": hub_status.RESET_STATUS,
                           "reason": hub_status.RESET_REASON, "expiredAt": "2027-01-26T00:00:00Z"}
    first = db.hub_op(answer["op_id"])
    assert first["state"] == "done" and first["error"] == hub_effects.CHAIN_NOTE_QUEUED
    assert db.get_review(pid, "101")["entered_hub"] == 0, "первый шаг отметки не ставит"
    # второй шаг поставлен сам: тот же статус с новым комментарием и сроком; карточка перезагружается на него
    state = web.client.get(answer["status_url"]).json()
    assert state["done"] and state.get("reload")
    second = db.hub_last_op(pid, "101", "status")
    assert second["id"] != first["id"] and second["state"] == "queued" and not hub_status.is_reset(second)
    html = card(web, pid, "101")
    assert "В очереди: ждём исполнителя – «Ложное срабатывание», срок до" in html
    job = run_worker(web, body={"id": 3, "oldStatus": hub_status.RESET_STATUS, "status": "False Positive"})
    assert job["body"] == {"issueId": 101, "issueType": "SAST", "status": "False Positive", "reason": NEW,
                           "expiredAt": "2027-01-26T00:00:00Z"}
    after = db.get_review(pid, "101")
    assert after["entered_hub"] == 1 and after["entered_text_hash"] == text_hash(NEW)
    assert after["revision"] == review["revision"]
    # статус снова стоит в Hub по подтверждённой записи, текст текущий – панель обычная, без режима замены
    html = card(web, pid, "101")
    assert "Записано в Hub" in html and 'id="hub-send-replace"' not in html
    # повторная замена с тем же текстом не нужна: обычная отправка отклоняется как «уже стоит»
    assert send(web, pid, "101").status_code == 400


def test_group_neighbours_are_not_touched_by_replace(web):
    pid = project(web, [sast("101"), sast("102")])
    decide(web, pid, "101")
    decide(web, pid, "102")
    assert send(web, pid, "101").status_code == 200  # группа одним запросом
    run_worker(web)
    db = web.app.state.db
    assert db.get_review(pid, "102")["entered_hub"] == 1
    decide(web, pid, "101", comment=NEW)  # у соседа прежний текст и отметка
    r = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"})
    assert r.status_code == 200, r.text
    job = run_worker(web)
    assert job["path"] == "/issue/status/update" and job["body"]["issueId"] == 101
    job = run_worker(web)
    assert job["body"]["issueId"] == 101 and job["body"]["reason"] == NEW
    assert db.get_review(pid, "102")["entered_hub"] == 1 and db.get_review(pid, "102")["final_comment"] == REASON


def test_hub_refusal_already_has_status_switches_panel(web):
    """Статус поставлен в Hub руками (версии у находки нет): обычная отправка уходит, Hub отвечает 400 «already has
    the requested status» – операция в отказе с пояснением, панель – в режиме замены по слову Hub."""
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    answer = send(web, pid, "101").json()
    run_worker(web, status=400, body=ALREADY)
    op = web.app.state.db.hub_op(answer["op_id"])
    assert op["state"] == "failed" and hub_status.already_refused(op)
    view = hub_status_routes.op_view(op)
    assert view["tone"] == "warn" and "уже стоит, комментарий в Hub прежний" in view["text"]
    html = card(web, pid, "101")
    assert ">Обновить комментарий в Hub</button>" in html and "комментарий в Hub прежний" in html
    assert send(web, pid, "101").status_code == 400
    r = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"})
    assert r.status_code == 200, r.text
    assert run_worker(web)["body"]["status"] == hub_status.RESET_STATUS
    assert run_worker(web)["body"]["status"] == "False Positive"
    assert web.app.state.db.get_review(pid, "101")["entered_hub"] == 1


def test_second_step_is_not_queued_after_a_new_revision(web):
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")
    decide(web, pid, "101", comment=NEW)
    answer = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"}).json()
    decide(web, pid, "101", comment=NEW + " Ещё раз.")  # решение сохранили заново, пока шёл первый шаг
    run_worker(web)
    db = web.app.state.db
    first = db.hub_op(answer["op_id"])
    assert first["state"] == "done" and first["error"] == hub_effects.CHAIN_NOTE_STALE
    assert db.hub_last_op(pid, "101", "status")["id"] == first["id"], "второго шага нет"
    assert db.get_review(pid, "101")["entered_hub"] == 0
    state = web.client.get(answer["status_url"]).json()
    assert state["done"] and "новый комментарий не отправлен" in state["text"]["hub-send-status"]
    # статуса в Hub больше нет (подтверждена запись «Confirmed»): панель обычная, отправка решения – заново
    html = card(web, pid, "101")
    assert 'id="hub-send-replace"' not in html and ">Отправить в Hub</button>" in html
    assert send(web, pid, "101").status_code == 200


def test_replace_refused_when_status_is_not_in_hub(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    r = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"})
    assert r.status_code == 400 and "сейчас нет" in r.json()["detail"]
    assert web.app.state.db.hub_last_op(pid, "101", "status") is None


def test_unknown_first_step_verified_then_chains(web):
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")
    decide(web, pid, "101", comment=NEW)
    answer = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"}).json()
    run_worker(web, status=0, error="timeout")
    state = web.client.get(answer["status_url"]).json()
    assert "Результат первого шага неизвестен" in state["text"]["hub-send-status"] and "hub-verify-form" in state["show"]
    r = web.client.post(f"/projects/{pid}/hub/verify", data={"op_id": str(answer["op_id"])}, headers=AS_JSON)
    assert r.status_code == 200, r.text
    run_worker(web, body={"status": hub_status.RESET_STATUS, "reason": hub_status.RESET_REASON, "expiredAt": "2027-01-26T00:00:00Z"})
    db = web.app.state.db
    assert db.hub_op(answer["op_id"])["state"] == "done"
    second = db.hub_last_op(pid, "101", "status")
    assert second["id"] != answer["op_id"] and second["state"] == "queued"
    assert run_worker(web)["body"]["reason"] == NEW
    assert db.get_review(pid, "101")["entered_hub"] == 1


# ============================================================================ SCA и ответ сохранения


def test_sca_risk_accepted_replace(web):
    pid = project(web, [sca("201")])
    entered_once(web, pid, "201", kind="sca/findings", decision="risk_accepted", verdict="true_positive")
    decide(web, pid, "201", decision="risk_accepted", verdict="true_positive", comment=NEW)
    html = card(web, pid, "201", "sca/findings")
    assert ">Обновить комментарий в Hub</button>" in html and "уже стоит «Риск принят»" in html
    r = send(web, pid, "201", kind="sca/findings", extra={"replace": "1", "replace_confirm": "1"})
    assert r.status_code == 200, r.text
    assert run_worker(web)["body"]["status"] == hub_status.RESET_STATUS
    job = run_worker(web)
    assert job["body"]["status"] == "Accepted risk" and job["body"]["issueType"] == "SCA_S" and NEW in job["body"]["reason"]
    assert web.app.state.db.get_review(pid, "201")["entered_hub"] == 1


def test_save_answer_carries_panel_mode(web):
    """Ответ сохранения (AJAX) несёт режим панели: после правки обоснования у внесённой находки – замена."""
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")
    html = card(web, pid, "101")
    fields = {name: re.search(rf'name="{name}" value="([^"]*)"', html).group(1)
              for name in ("finding_version", "review_revision")}
    verdict = re.search(r'name="verdict_id" value="([^"]*)"', html)
    data = {**fields, "verdict_id": verdict.group(1) if verdict else "", "decision": "false_positive",
            "final_verdict": "", "comment": NEW, "fix": "", "reviewed": "1", "action": "save"}
    r = web.client.post(f"/projects/{pid}/findings/{fid(web, pid, '101')}/review", headers=AS_JSON, data=data)
    assert r.status_code == 200, r.text
    mode = r.json()["hub_replace"]
    assert mode["active"] and "уже стоит «Ложное срабатывание»" in mode["note"] and "две" in mode["check"]
    # вернули прежний текст: отметка не восстанавливается сама (приложение не знает, что в Hub тот же текст) –
    # режим замены остаётся; отметка оператора «внесено» с текущим отпечатком режим снимает
    data.update(comment=REASON, review_revision=str(r.json()["revision"]))
    r = web.client.post(f"/projects/{pid}/findings/{fid(web, pid, '101')}/review", headers=AS_JSON, data=data)
    assert r.status_code == 200, r.text
    assert r.json()["hub_replace"]["active"] is True
    db = web.app.state.db
    db.mark_entered(pid, "101", True, revision=int(r.json()["revision"]), entered_hash=text_hash(REASON))
    html = card(web, pid, "101")
    assert 'id="hub-send-replace"' not in html and ">Отправить в Hub</button>" in html


# ============================================================================ круг 2 ревью: однократность, ключи, свидетельства


def test_redelivery_of_first_step_does_not_requeue_a_failed_second_step(web):
    """Повторная доставка результата первого шага после отказа второго второй шаг заново не ставит."""
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")
    decide(web, pid, "101", comment=NEW)
    answer = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"}).json()
    first_job = None
    job = run_worker(web)  # первый шаг выполнен, второй поставлен
    first_job = job
    db = web.app.state.db
    second = db.hub_last_op(pid, "101", "status")
    assert hub_status.chain_of(db.hub_op(answer["op_id"]))["chained"] == second["id"]
    run_worker(web, status=400, body={"errorMessage": "bad"})  # второй шаг – отказ
    assert db.hub_op(second["id"])["state"] == "failed"
    # повторная доставка того же результата первого шага
    key = web.app.state.hub_worker_key
    r = web.client.post(f"/api/hub/jobs/{first_job['attempt_id']}/result", headers={**AS_JSON, "X-Hub-Worker-Key": key},
                        content='{"lease_token": "%s", "status": 200, "body_text": "{}", "error": ""}' % first_job["lease_token"])
    assert r.status_code == 200 and r.json()["outcome"] == "duplicate", r.text
    assert db.hub_last_op(pid, "101", "status")["id"] == second["id"], "нового второго шага нет"
    assert db.hub_op(second["id"])["state"] == "failed"
    # статуса в Hub нет (версия «Confirmed») – обычная отправка решения
    assert send(web, pid, "101").status_code == 200


def test_return_to_an_earlier_text_is_a_new_chain(web):
    """A отправлен, заменён на B, возвращён A: второй шаг с текстом A – новая операция, не «уже выполнена»."""
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")  # A = REASON
    decide(web, pid, "101", comment=NEW)  # B
    assert send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"}).status_code == 200
    run_worker(web)
    run_worker(web)
    db = web.app.state.db
    assert db.get_review(pid, "101")["entered_text_hash"] == text_hash(NEW)
    decide(web, pid, "101", comment=REASON)  # снова A
    r = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"})
    assert r.status_code == 200, r.text
    assert run_worker(web)["body"]["status"] == hub_status.RESET_STATUS
    job = run_worker(web)
    assert job["body"]["status"] == "False Positive" and job["body"]["reason"] == REASON
    after = db.get_review(pid, "101")
    assert after["entered_hub"] == 1 and after["entered_text_hash"] == text_hash(REASON)


def test_old_refusal_yields_to_an_accepted_version(web):
    """Отказ «already has…» – свидетельство только без принятой версии: принятый Pull с «To verify» его отменяет."""
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    send(web, pid, "101")
    run_worker(web, status=400, body=ALREADY)
    assert ">Обновить комментарий в Hub</button>" in card(web, pid, "101")
    db = web.app.state.db
    from app.db import dumps
    base = "https://hub.example.org"
    with db._tx() as c:  # принятое чтение Hub: статус снят (To verify)
        c.execute("INSERT INTO hub_entity_versions(project_id,hub_url,app_id,entity_kind,entity_key,accepted_epoch,"
                  "accepted_hash,accepted_source_json) VALUES (?,?,?,?,?,1,'x',?)",
                  (pid, base, 7, "issue", "SAST:101", dumps({"origin": "hub_sync"})))
        c.execute("INSERT INTO hub_issue_states(project_id,hub_url,app_id,issue_type,issue_id,finding_id,confirmed_json,"
                  "confirmed_run_id,confirmed_presence,observed_json,observed_run_id,alignment,revision)"
                  " VALUES (?,?,?,?,?,?,?,NULL,'present',?,NULL,'agreed',1)",
                  (pid, base, 7, "SAST", "101", fid(web, pid, "101"), dumps({"detail": {"status": "To verify"}}),
                   dumps({})))
    html = card(web, pid, "101")
    assert 'id="hub-send-replace"' not in html and ">Отправить в Hub</button>" in html
    r = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"})
    assert r.status_code == 400 and "сейчас нет" in r.json()["detail"]
    assert send(web, pid, "101").status_code == 200


def test_first_step_withdraws_the_mark_of_a_bulk_comment(web):
    """Отметка от массовой отправки (общий текст) снимается первым шагом: после «Confirmed» в Hub статуса нет."""
    from test_hub_bulk import fixed_today_bulk, preview, send as bulk_send, targets_of  # noqa: F401
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    r = bulk_send(web, pid, targets_of(preview(web, pid, "101")), comment="Общий комментарий массовой отправки.")
    assert r.status_code == 303, r.text[:200]
    run_worker(web)  # массовая отправка выполнена: отметка с отпечатком общего текста
    db = web.app.state.db
    assert db.get_review(pid, "101")["entered_hub"] == 1
    html = card(web, pid, "101")
    assert ">Обновить комментарий в Hub</button>" in html, "текст карточки отличается от общего – замена доступна"
    r = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"})
    assert r.status_code == 200, r.text
    run_worker(web)  # первый шаг выполнен
    assert db.get_review(pid, "101")["entered_hub"] == 0, "прежний статус снят – отметка снята"
    run_worker(web, status=400, body={"errorMessage": "bad"})  # второй шаг отказ
    html = card(web, pid, "101")
    assert 'id="entered-badge" hidden' in html and ">Отправить в Hub</button>" in html


# ============================================================================ круг 3 ревью: повторная доставка, групповой отказ, восстановление


def worker_key(web) -> str:
    return web.app.state.hub_worker_key


def redeliver(web, job: dict, status: int = 200, body: str = "{}"):
    return web.client.post(f"/api/hub/jobs/{job['attempt_id']}/result",
                           headers={**AS_JSON, "X-Hub-Worker-Key": worker_key(web)},
                           content='{"lease_token": "%s", "status": %d, "body_text": %s, "error": ""}'
                                   % (job["lease_token"], status, __import__("json").dumps(body)))


def test_redelivery_of_first_step_keeps_the_mark_of_the_second(web):
    """Оба шага выполнены, отметка стоит с новым текстом; повторная доставка результата первого её не снимает."""
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")
    decide(web, pid, "101", comment=NEW)
    send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"})
    first = run_worker(web)
    run_worker(web)
    db = web.app.state.db
    assert db.get_review(pid, "101")["entered_hub"] == 1
    assert redeliver(web, first).json()["outcome"] == "duplicate"
    after = db.get_review(pid, "101")
    assert after["entered_hub"] == 1 and after["entered_text_hash"] == text_hash(NEW)
    html = card(web, pid, "101")
    assert 'id="hub-send-replace"' not in html and "Записано в Hub" in html


def test_group_refusal_names_one_finding_only(web):
    """Отказ группового запроса «issue #101 … already has» – свидетельство только для 101; у 102 панель обычная."""
    pid = project(web, [sast("101"), sast("102")])
    decide(web, pid, "101")
    decide(web, pid, "102")
    assert send(web, pid, "101").status_code == 200
    job = run_worker(web, status=400, body=ALREADY)
    assert job["path"] == "/issue/status/change"
    assert ">Обновить комментарий в Hub</button>" in card(web, pid, "101")
    html = card(web, pid, "102")
    assert 'id="hub-send-replace"' not in html and ">Отправить в Hub</button>" in html
    r = send(web, pid, "102")  # у 102 статуса нет – обычная отправка; 101 как «уже в Hub» в группу не входит
    assert r.status_code == 200, r.text
    assert "Уже внесена в Hub и не отправляется: 101" in r.json()["message"]


def test_earlier_text_can_be_resent_after_a_stopped_chain(web):
    """Текст A отправлен; замена на B остановлена после первого шага (новая редакция – снова A): обычная отправка A с
    прежним сроком уходит заново, а не «уже выполнена»."""
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")
    decide(web, pid, "101", comment=NEW)
    answer = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"}).json()
    decide(web, pid, "101", comment=REASON)  # вернули A, пока шёл первый шаг
    run_worker(web)
    db = web.app.state.db
    assert db.hub_op(answer["op_id"])["error"] == hub_effects.CHAIN_NOTE_STALE
    r = send(web, pid, "101")  # тот же запрос, что первая отправка A, но принятая версия другая
    assert r.status_code == 200, r.text
    job = run_worker(web)
    assert job["body"]["status"] == "False Positive" and job["body"]["reason"] == REASON
    assert db.get_review(pid, "101")["entered_hub"] == 1
    assert send(web, pid, "101").status_code == 400, "повтор без смены версии – «уже стоит»"


def test_save_answer_carries_previous_expiry(web):
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")
    html = card(web, pid, "101")
    fields = {name: re.search(rf'name="{name}" value="([^"]*)"', html).group(1)
              for name in ("finding_version", "review_revision")}
    verdict = re.search(r'name="verdict_id" value="([^"]*)"', html)
    data = {**fields, "verdict_id": verdict.group(1) if verdict else "", "decision": "false_positive",
            "final_verdict": "", "comment": NEW, "fix": "", "reviewed": "1", "action": "save"}
    r = web.client.post(f"/projects/{pid}/findings/{fid(web, pid, '101')}/review", headers=AS_JSON, data=data)
    assert r.status_code == 200 and r.json()["hub_replace"]["expires"] == "2027-01-26", r.text


# ============================================================================ круг 4 ревью: две вкладки, порядок свидетельств, соседи, массовая


def test_second_tab_is_refused_in_the_enqueue_transaction(web, monkeypatch):
    """Две вкладки: проверка второй прошла до выполнения первой; в транзакции постановки статус якоря уже стоит."""
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")
    monkeypatch.setattr(hub_status_routes, "status_already", lambda *a, **k: False)  # как будто проверка прошла раньше
    r = send(web, pid, "101")
    assert r.status_code == 400 and "Состав группы изменился" in r.json()["detail"], r.text
    assert web.app.state.db.hub_last_op(pid, "101", "status")["state"] == "done", "второй POST не поставлен"


def test_fresh_refusal_outranks_an_older_accepted_version(web):
    """Принят Pull с «To verify», потом статус поставили в Hub руками: новый отказ «already has…» – свидетельство."""
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    db = web.app.state.db
    from app.db import dumps
    base = "https://hub.example.org"
    with db._tx() as c:
        c.execute("INSERT INTO hub_entity_versions(project_id,hub_url,app_id,entity_kind,entity_key,accepted_epoch,"
                  "accepted_hash,accepted_source_json) VALUES (?,?,?,?,?,1,'x',?)",
                  (pid, base, 7, "issue", "SAST:101", dumps({"origin": "hub_sync"})))
        c.execute("INSERT INTO hub_issue_states(project_id,hub_url,app_id,issue_type,issue_id,finding_id,confirmed_json,"
                  "confirmed_run_id,confirmed_presence,observed_json,observed_run_id,alignment,revision)"
                  " VALUES (?,?,?,?,?,?,?,NULL,'present',?,NULL,'agreed',1)",
                  (pid, base, 7, "SAST", "101", fid(web, pid, "101"), dumps({"detail": {"status": "To verify"}}),
                   dumps({})))
    assert send(web, pid, "101").status_code == 200
    run_worker(web, status=400, body=ALREADY)
    assert ">Обновить комментарий в Hub</button>" in card(web, pid, "101"), "отказ новее принятой версии"
    assert send(web, pid, "101").status_code == 400


def test_group_refusal_card_of_the_unnamed_neighbour(web):
    pid = project(web, [sast("101"), sast("102")])
    decide(web, pid, "101")
    decide(web, pid, "102")
    answer = send(web, pid, "101").json()
    run_worker(web, status=400, body=ALREADY)
    html = card(web, pid, "102")
    assert "Hub не принял групповую отправку: статус «Ложное срабатывание» уже стоит у 101" in html
    assert "Обновить комментарий в Hub" not in html
    html = card(web, pid, "101")
    assert "у находки уже стоит, комментарий в Hub прежний" in html
    state = web.client.get(answer["status_url"]).json()  # опрос – с точки зрения отправившей карточки (101)
    assert "у находки уже стоит" in state["text"]["hub-send-status"]


def test_bulk_preview_excludes_the_named_finding_only(web):
    from test_hub_bulk import fixed_today_bulk, preview, targets_of  # noqa: F401
    pid = project(web, [sast("101"), sast("102")])
    decide(web, pid, "101")
    decide(web, pid, "102")
    send(web, pid, "101")
    run_worker(web, status=400, body=ALREADY)
    html = preview(web, pid, "101", "102")
    assert [t.split("|")[0] for t in targets_of(html)] == ["102"] and "статус уже внесён в Hub" in html


# ============================================================================ круг 5 ревью: отложенные последствия, свидетельство, опрос соседа


def test_delayed_first_step_effects_after_a_later_write_change_nothing(web, monkeypatch):
    """Первый шаг записан как done, но его последствия отложены; тем временем обычная отправка нового текста выполнена
    и отмечена. Отложенные последствия не снимают отметку и не ставят второй POST."""
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")
    decide(web, pid, "101", comment=NEW)
    answer = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"}).json()
    monkeypatch.setattr(hub_effects, "after_result", lambda *a, **k: None)  # последствия первого шага отложены
    run_worker(web)
    monkeypatch.undo()
    db = web.app.state.db
    assert db.hub_op(answer["op_id"])["state"] == "done" and db.hub_last_op(pid, "101", "status")["id"] == answer["op_id"]
    assert send(web, pid, "101").status_code == 200, "статуса в Hub нет – обычная отправка нового текста"
    run_worker(web)
    later = db.hub_last_op(pid, "101", "status")
    assert later["state"] == "done" and db.get_review(pid, "101")["entered_hub"] == 1
    hub_effects.after_result(db, db.hub_op(answer["op_id"]))  # отложенные последствия первого шага
    assert db.hub_last_op(pid, "101", "status")["id"] == later["id"], "второго POST нет"
    assert db.get_review(pid, "101")["entered_hub"] == 1, "новая отметка не снята"
    assert db.hub_op(answer["op_id"])["error"] == hub_effects.CHAIN_NOTE_LATER


def test_failed_first_step_keeps_the_refusal_evidence(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    send(web, pid, "101")
    run_worker(web, status=400, body=ALREADY)
    assert ">Обновить комментарий в Hub</button>" in card(web, pid, "101")
    decide(web, pid, "101", comment=NEW)
    r = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"})
    assert r.status_code == 200, r.text
    job = web.client.get("/api/hub/jobs", params={"worker_id": "w1", "hub_url": "https://hub.example.org", "wait": 0},
                         headers=worker_headers(web)).json()["job"]
    r = web.client.post(f"/api/hub/jobs/{job['attempt_id']}/result", headers=worker_headers(web),
                        content='{"lease_token": "%s", "status": 0, "body_text": "", "error": "Hub недоступен", "not_sent": true}'
                                % job["lease_token"])
    assert r.status_code == 200 and web.app.state.db.hub_last_op(pid, "101", "status")["state"] == "failed"
    html = card(web, pid, "101")
    assert ">Обновить комментарий в Hub</button>" in html, "свидетельство отказа не стёрто"
    assert "Hub не принял снятие прежнего статуса" in html
    assert send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"}).status_code == 200


def test_poll_of_the_neighbour_card_names_the_group_refusal(web):
    pid = project(web, [sast("101"), sast("102")])
    decide(web, pid, "101")
    decide(web, pid, "102")
    answer = send(web, pid, "101").json()
    assert answer["status_url"].endswith("?hub_id=101")
    run_worker(web, status=400, body=ALREADY)
    mine = web.client.get(answer["status_url"]).json()
    assert "у находки уже стоит" in mine["text"]["hub-send-status"] and mine.get("reload") is True
    other = web.client.get(f"/projects/{pid}/hub/ops/{answer['op_id']}?hub_id=102").json()
    assert "групповую отправку" in other["text"]["hub-send-status"] and "уже стоит у 101" in other["text"]["hub-send-status"]
    assert other.get("reload") is True
    assert f'data-poll="/projects/{pid}/hub/ops/' not in card(web, pid, "102") or "?hub_id=102" in card(web, pid, "102")


# ============================================================================ круг 6 ревью: опрос до второго шага, принятый Pull, устаревший отказ


def accept_hub_state(web, pid: int, hub_id: str, confirmed: dict) -> None:
    """Принятое состояние Hub по находке (как после «Pull из Hub»): версия и прочитанное состояние."""
    db = web.app.state.db
    from app.db import dumps
    base = "https://hub.example.org"
    manual = confirmed.get("manual")
    if isinstance(manual, dict):
        # dev15 (план п. 1.1): основание берётся только из своей ручной записи того же статуса – как в настоящем
        # ответе Hub, запись несёт номер, тип и статус находки
        status = (confirmed.get("detail") or {}).get("status")
        confirmed = {**confirmed, "manual": {"issueId": int(hub_id), "issueType": "SAST", "status": status, **manual}}
    with db._tx() as c:
        c.execute("INSERT INTO hub_entity_versions(project_id,hub_url,app_id,entity_kind,entity_key,accepted_epoch,"
                  "accepted_hash,accepted_source_json) VALUES (?,?,?,?,?,1,'x',?)",
                  (pid, base, 7, "issue", f"SAST:{hub_id}", dumps({"origin": "hub_sync"})))
        c.execute("INSERT INTO hub_issue_states(project_id,hub_url,app_id,issue_type,issue_id,finding_id,confirmed_json,"
                  "confirmed_run_id,confirmed_presence,observed_json,observed_run_id,alignment,revision)"
                  " VALUES (?,?,?,?,?,?,?,NULL,'present',?,NULL,'agreed',1)",
                  (pid, base, 7, "SAST", hub_id, fid(web, pid, hub_id), dumps(confirmed), dumps({})))


def test_poll_waits_for_the_second_step(web, monkeypatch):
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")
    decide(web, pid, "101", comment=NEW)
    answer = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"}).json()
    monkeypatch.setattr(hub_effects, "after_result", lambda *a, **k: None)
    run_worker(web)
    monkeypatch.undo()
    db = web.app.state.db
    first = db.hub_op(answer["op_id"])
    # результат записан, последствий нет: карточка (без опроса) показывает, что второй шаг ещё ставится
    view = hub_status_routes.op_view(first)
    assert view["final"] is False and "ставлю второй шаг" in view["text"]
    assert "data-poll=" in card(web, pid, "101"), "карточка продолжает опрос"
    state = web.client.get(answer["status_url"]).json()  # опрос доводит цепочку (круг 10)
    assert state["done"] is True and state.get("reload") is True
    assert db.hub_last_op(pid, "101", "status")["id"] != first["id"]


def test_comment_accepted_from_pull_is_current(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    import html as html_mod
    shown = html_mod.unescape(re.search(r'<pre id="hub-text" class="hub-text">(.*?)</pre>', card(web, pid, "101"), re.S).group(1))
    accept_hub_state(web, pid, "101", {"detail": {"status": "False Positive"},
                                       "manual": {"reason": shown, "expiredAt": "2027-01-26T00:00:00Z"}})
    db = web.app.state.db
    with db._tx() as c:  # отметка принятого Pull: происхождение hub_sync, операция чтения в том же назначении, без отпечатка
        cur = c.execute("INSERT INTO hub_ops(project_id, purpose, op_key, lock_keys, targets_json, request_json, hub_url,"
                        " app_id, text_hash, text_norm, state, created_at, updated_at) VALUES (?, 'read', 'k-pull', '[]',"
                        " '[]', '{}', 'https://hub.example.org', 7, '', '', 'done', '2026-11-02T10:00:00+00:00',"
                        " '2026-11-02T10:00:00+00:00')" " RETURNING id", (pid,))
        c.execute("UPDATE reviews SET entered_hub=1, entered_origin='hub_sync', entered_text_hash='', entered_op_id=?,"
                  " entered_hub_at='2026-11-02T10:00:00+00:00' WHERE project_id=? AND hub_id=?", (cur.fetchone()[0], pid, "101"))
    assert db.get_review(pid, "101")["entered_hub"] == 1
    html = card(web, pid, "101")
    assert 'id="hub-send-replace"' not in html and ">Отправить в Hub</button>" in html, "текст равен принятому"
    decide(web, pid, "101", comment=NEW)  # другой текст – замена
    assert ">Обновить комментарий в Hub</button>" in card(web, pid, "101")


def test_stale_refusal_is_shown_as_history(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    send(web, pid, "101")
    run_worker(web, status=400, body=ALREADY)
    accept_hub_state(web, pid, "101", {"detail": {"status": "To verify"}})
    html = card(web, pid, "101")
    assert "Hub не принял тогда" in html and "это история" in html and "Обновить комментарий в Hub" not in html


# ============================================================================ круг 7 ревью: Pull с тем же статусом гасит отказ


def test_pull_with_the_same_status_retires_the_refusal(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    send(web, pid, "101")
    run_worker(web, status=400, body=ALREADY)
    import html as html_mod
    shown = html_mod.unescape(re.search(r'<pre id="hub-text" class="hub-text">(.*?)</pre>', card(web, pid, "101"), re.S).group(1))
    accept_hub_state(web, pid, "101", {"detail": {"status": "False Positive"},
                                       "manual": {"reason": shown, "expiredAt": "2027-01-26T00:00:00Z"}})
    db = web.app.state.db
    with db._tx() as c:
        cur = c.execute("INSERT INTO hub_ops(project_id, purpose, op_key, lock_keys, targets_json, request_json, hub_url,"
                        " app_id, text_hash, text_norm, state, created_at, updated_at) VALUES (?, 'read', 'k-pull2', '[]',"
                        " '[]', '{}', 'https://hub.example.org', 7, '', '', 'done', '2026-11-02T10:00:00+00:00',"
                        " '2026-11-02T10:00:00+00:00')" " RETURNING id", (pid,))
        c.execute("UPDATE reviews SET entered_hub=1, entered_origin='hub_sync', entered_text_hash='', entered_op_id=?,"
                  " entered_hub_at='2026-11-02T10:00:00+00:00' WHERE project_id=? AND hub_id=?", (cur.fetchone()[0], pid, "101"))
    html = card(web, pid, "101")
    assert 'id="hub-send-replace"' not in html and ">Отправить в Hub</button>" in html
    assert "Hub не принял тогда" in html and "это история" in html and "Заменить комментарий можно" not in html


# ============================================================================ круг 8 ревью: другое решение после отказа


def test_other_outcome_after_a_refusal_is_offered_for_sending(web):
    pid = project(web, [sca("201")])
    decide(web, pid, "201", decision="disagree", verdict="false_positive")
    send(web, pid, "201", kind="sca/findings")
    run_worker(web, status=400, body={"errorMessage": "Unable to change status for SCA_S issue #201: issue already has "
                                                       "the requested status FALSE_POSITIVE", "requestValidationError": None})
    assert ">Обновить комментарий в Hub</button>" in card(web, pid, "201", "sca/findings")
    decide(web, pid, "201", decision="risk_accepted", verdict="true_positive", comment=NEW)
    html = card(web, pid, "201", "sca/findings")
    assert ">Отправить в Hub</button>" in html and 'id="hub-send-replace"' not in html
    assert "Текущее решение другое – отправьте его" in html and "отправлять нечего" not in html
    r = send(web, pid, "201", kind="sca/findings")
    assert r.status_code == 200, r.text
    assert run_worker(web)["body"]["status"] == "Accepted risk"


# ============================================================================ круг 9 ревью: строка отказа после сохранения со скриптом


def test_save_answer_recomputes_the_refusal_line(web):
    pid = project(web, [sca("201")])
    decide(web, pid, "201", decision="disagree", verdict="false_positive")
    send(web, pid, "201", kind="sca/findings")
    run_worker(web, status=400, body={"errorMessage": "Unable to change status for SCA_S issue #201: issue already has "
                                                       "the requested status FALSE_POSITIVE", "requestValidationError": None})
    from test_sca import form_fields
    html = card(web, pid, "201", "sca/findings")
    assert "Заменить комментарий можно" in html
    fields = form_fields(html)
    r = web.client.post(f"/projects/{pid}/sca/findings/{fid(web, pid, '201')}/review", headers=AS_JSON,
                        data={**fields, "decision": "risk_accepted", "final_verdict": "true_positive", "comment": NEW,
                              "kapo_state": "not_actual", "reviewed": "1", "action": "copy", "apply_to": ["201"]})
    assert r.status_code == 200, r.text
    mode = r.json()["hub_replace"]
    assert mode["active"] is False and "Текущее решение другое – отправьте его" in mode["status_text"]
    assert mode["status_tone"] == ""


# ============================================================================ круг 10 ревью: повторная замена после отказа второго шага, восстановление цепочки


def test_replace_again_after_the_second_step_was_refused(web):
    """Первый шаг снял статус; извне вернули «Ложное срабатывание» с другим текстом; второй шаг получил «already».
    Новая подтверждённая замена с теми же текстом и редакцией – новая операция, не «уже выполнена»."""
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")
    decide(web, pid, "101", comment=NEW)
    assert send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"}).status_code == 200
    run_worker(web)  # первый шаг выполнен
    run_worker(web, status=400, body=ALREADY)  # второй шаг: статус уже вернули извне
    assert ">Обновить комментарий в Hub</button>" in card(web, pid, "101")
    r = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"})
    assert r.status_code == 200, r.text
    assert run_worker(web)["body"]["status"] == hub_status.RESET_STATUS
    job = run_worker(web)
    assert job["body"]["status"] == "False Positive" and job["body"]["reason"] == NEW
    assert web.app.state.db.get_review(pid, "101")["entered_hub"] == 1


def test_pending_chain_is_recovered_on_poll_and_at_startup(web, monkeypatch):
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")
    decide(web, pid, "101", comment=NEW)
    answer = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"}).json()
    monkeypatch.setattr(hub_effects, "after_result", lambda *a, **k: None)
    run_worker(web)  # результат записан, последствия не доставлены
    monkeypatch.undo()
    db = web.app.state.db
    first = db.hub_op(answer["op_id"])
    assert hub_effects.chain_pending(first)
    state = web.client.get(answer["status_url"]).json()  # опрос доводит цепочку
    second = db.hub_last_op(pid, "101", "status")
    assert second["id"] != first["id"] and second["state"] == "queued" and state["done"] and state.get("reload")
    assert hub_status.chain_of(db.hub_op(answer["op_id"]))["chained"] == second["id"]
    assert hub_effects.recover_chains(db) == 0, "доведённая цепочка второй раз не ставится"
    run_worker(web)  # второй шаг первой находки выполнен: очередь пуста
    # и при запуске: ещё одна незавершённая цепочка на другой находке
    pid2 = project(web, [sast("102")])
    entered_once(web, pid2, "102")
    decide(web, pid2, "102", comment=NEW)
    sent = send(web, pid2, "102", extra={"replace": "1", "replace_confirm": "1"}).json()
    monkeypatch.setattr(hub_effects, "after_result", lambda *a, **k: None)
    run_worker(web)
    monkeypatch.undo()
    assert hub_effects.recover_chains(db) == 1
    assert db.hub_last_op(pid2, "102", "status")["id"] != sent["op_id"]


# ============================================================================ круг 11 ревью: восстановление без предела, отказ другого статуса


def test_recovery_uses_a_direct_query(web, monkeypatch):
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")
    decide(web, pid, "101", comment=NEW)
    sent = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"}).json()
    monkeypatch.setattr(hub_effects, "after_result", lambda *a, **k: None)
    run_worker(web)
    monkeypatch.undo()
    db = web.app.state.db
    monkeypatch.setattr(db, "hub_ops_list", lambda *a, **k: [])  # общий список с пределом не используется
    assert [o["id"] for o in db.hub_unchained_resets()] == [sent["op_id"]]
    assert hub_effects.recover_chains(db) == 1 and db.hub_unchained_resets() == []


def test_fresh_refusal_of_another_status_overrides_the_confirmed_one(web):
    """Приложение подтвердило «Ложное срабатывание»; извне в Hub поставили «Риск принят», отправка его получила
    «already»; возврат к «Ложному срабатыванию» – обычная отправка, без замены."""
    pid = project(web, [sca("201")])
    entered_once(web, pid, "201", kind="sca/findings", decision="disagree", verdict="false_positive")
    decide(web, pid, "201", decision="risk_accepted", verdict="true_positive", comment=NEW)
    assert send(web, pid, "201", kind="sca/findings").status_code == 200
    run_worker(web, status=400, body={"errorMessage": "Unable to change status for SCA_S issue #201: issue already has "
                                                       "the requested status ACCEPTED_RISK", "requestValidationError": None})
    assert ">Обновить комментарий в Hub</button>" in card(web, pid, "201", "sca/findings")
    decide(web, pid, "201", decision="disagree", verdict="false_positive", comment=REASON)
    html = card(web, pid, "201", "sca/findings")
    assert 'id="hub-send-replace"' not in html and ">Отправить в Hub</button>" in html
    r = send(web, pid, "201", kind="sca/findings")
    assert r.status_code == 200, r.text
    assert run_worker(web)["body"]["status"] == "False Positive"


# ============================================================================ круг 12 ревью: свидетельство не теряется за отказами


def test_refusal_evidence_survives_many_failed_first_steps(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    send(web, pid, "101")
    run_worker(web, status=400, body=ALREADY)
    decide(web, pid, "101", comment=NEW)
    for _ in range(25):
        r = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"})
        assert r.status_code == 200, r.text
        job = web.client.get("/api/hub/jobs", params={"worker_id": "w1", "hub_url": "https://hub.example.org", "wait": 0},
                             headers=worker_headers(web)).json()["job"]
        r = web.client.post(f"/api/hub/jobs/{job['attempt_id']}/result", headers=worker_headers(web),
                            content='{"lease_token": "%s", "status": 0, "body_text": "", "error": "Hub недоступен", "not_sent": true}'
                                    % job["lease_token"])
        assert r.status_code == 200
    html = card(web, pid, "101")
    assert ">Обновить комментарий в Hub</button>" in html, "свидетельство отказа не усечено"
    assert send(web, pid, "101").status_code == 400


# ============================================================================ круг 13 ревью: повтор формы после выполненной замены


def test_replaying_the_same_replace_form_after_success_is_refused(web):
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")
    decide(web, pid, "101", comment=NEW)
    form = {"replace": "1", "replace_confirm": "1"}
    assert send(web, pid, "101", extra=form).status_code == 200
    run_worker(web)
    run_worker(web)
    db = web.app.state.db
    done = db.hub_last_op(pid, "101", "status")
    assert done["state"] == "done" and db.get_review(pid, "101")["entered_hub"] == 1
    r = send(web, pid, "101", extra=form)  # та же форма ещё раз, решение не менялось
    assert r.status_code == 400 and "уже внесён" in r.json()["detail"], r.text
    assert db.hub_last_op(pid, "101", "status")["id"] == done["id"], "новой цепочки нет"


# ============================================================================ круг 14 ревью: повтор формы до отметки, отметка другого Hub


def test_replaying_the_form_before_the_mark_is_delivered_is_refused(web, monkeypatch):
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")
    decide(web, pid, "101", comment=NEW)
    form = {"replace": "1", "replace_confirm": "1"}
    assert send(web, pid, "101", extra=form).status_code == 200
    run_worker(web)
    monkeypatch.setattr(hub_effects, "after_result", lambda *a, **k: None)  # второй шаг записан, отметка не доставлена
    run_worker(web)
    monkeypatch.undo()
    db = web.app.state.db
    second = db.hub_last_op(pid, "101", "status")
    assert second["state"] == "done" and db.get_review(pid, "101")["entered_hub"] == 0
    r = send(web, pid, "101", extra=form)
    assert r.status_code == 400 and "уже внесён" in r.json()["detail"], r.text
    assert db.hub_last_op(pid, "101", "status")["id"] == second["id"]
    hub_effects.after_result(db, second)
    assert db.get_review(pid, "101")["entered_hub"] == 1


def test_mark_of_another_hub_does_not_block_the_replacement(web):
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")  # внесено в Hub A
    db = web.app.state.db
    other = "https://hub-b.example.org"
    db.set_settings({"hub_url": other})
    assert db.get_review(pid, "101")["entered_hub"] == 0, "отметка Hub A в назначении B недействительна"
    assert send(web, pid, "101").status_code == 200  # в B статуса ещё нет – обычная отправка
    job = web.client.get("/api/hub/jobs", params={"worker_id": "w2", "hub_url": other, "wait": 0},
                         headers=worker_headers(web)).json()["job"]
    r = web.client.post(f"/api/hub/jobs/{job['attempt_id']}/result", headers=worker_headers(web), content=__import__("json").dumps(
        {"lease_token": job["lease_token"], "status": 400, "body_text": __import__("json").dumps(ALREADY, ensure_ascii=False), "error": ""}))
    assert r.status_code == 200
    html = card(web, pid, "101")
    assert ">Обновить комментарий в Hub</button>" in html
    r = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"})
    assert r.status_code == 200, r.text


# ============================================================================ круг 15 ревью: сосед с нечисловым номером


def test_neighbour_with_a_non_numeric_id_does_not_block_the_replacement(web):
    pid = project(web, [sast("101"), sast("bad-id")])
    entered_once(web, pid, "101")
    decide(web, pid, "101", comment=NEW)
    decide(web, pid, "bad-id", comment=NEW)  # та же группа, то же обоснование
    r = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"})
    assert r.status_code == 200, r.text
    job = run_worker(web)
    assert job["path"] == "/issue/status/update" and job["body"]["issueId"] == 101
    assert run_worker(web)["body"]["reason"] == NEW


# ============================================================================ круг 16 ревью: локальный номер с ведущими нулями


def test_group_refusal_names_a_leading_zero_local_id(web):
    pid = project(web, [sast("00101"), sast("102")])
    decide(web, pid, "00101")
    decide(web, pid, "102")
    answer = send(web, pid, "00101").json()
    job = run_worker(web, status=400, body=ALREADY)  # Hub: «SAST issue #101 … already has …»
    assert job["path"] == "/issue/status/change" and job["body"]["issues"][0]["issueId"] == 101
    assert hub_status.refused_issue_ids(web.app.state.db.hub_op(answer["op_id"])) == {"00101"}
    assert ">Обновить комментарий в Hub</button>" in card(web, pid, "00101")
    html = card(web, pid, "102")
    assert 'id="hub-send-replace"' not in html and "уже стоит у 00101" in html, "сосед назван своим номером"
    r = send(web, pid, "102")
    assert r.status_code == 200 and "не отправляется: 00101" in r.json()["message"], r.text


# ============================================================================ dev31: Hub не принимает «To verify» – промежуточный статус «Confirmed»


def test_reset_status_is_confirmed_and_old_chains_are_recognized():
    """Hub отвечает 400 «To verify is not available for status change». Промежуточный статус –
    «Confirmed»; первый шаг узнаётся по второму шагу в записи (`then`), поэтому операции до dev31 с «To verify» – тоже
    первые шаги (их отказ карточка показывает как отказ первого шага)."""
    assert hub_status.RESET_STATUS == "Confirmed" and hub_status.RESET_LABEL == "Подтверждено"
    assert "To verify" not in hub_status.RESET_REASON
    old = {"id": 5, "purpose": "status", "state": "failed", "targets_json": "[]",
           "error": "Hub ответил кодом 400: To verify is not available for status change",
           "request_json": json.dumps({"method": "POST", "path": "/issue/status/update",
                                       "body": {"issueId": 101, "issueType": "SAST", "status": "To verify",
                                                "reason": "x", "expiredAt": "2027-01-31T00:00:00Z"},
                                       "then": {"status": "False Positive", "reason": NEW,
                                                "expiredAt": "2027-01-31T00:00:00Z"}})}
    assert hub_status.is_reset(old) and hub_status.sent_status(old) == "To verify"
    view = hub_status_routes.op_view(old)
    assert view["state"] == "failed" and view["final"] and "Hub не принял снятие прежнего статуса" in view["text"]
    assert "To verify is not available" in view["text"] and "можно повторить" in view["text"]
    plain = {"id": 6, "purpose": "status", "state": "done", "targets_json": "[]",
             "request_json": json.dumps({"body": {"status": "Confirmed", "reason": "x"}})}
    assert not hub_status.is_reset(plain), "операция без then – не первый шаг, какой бы статус ни стоял в теле"


def test_refused_first_step_keeps_the_offer_and_the_retry_goes_through_confirmed(web):
    """Отказ Hub на первый шаг: статус и комментарий в Hub прежние, карточка показывает отказ и
    по-прежнему предлагает замену; повтор ставит новую цепочку – «Confirmed», затем прежний статус с новым текстом."""
    pid = project(web, [sast("101")])
    entered_once(web, pid, "101")
    decide(web, pid, "101", comment=NEW)
    r = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"})
    assert r.status_code == 200, r.text
    job = run_worker(web, status=400, body={"errorMessage": "To verify is not available for status change",
                                            "requestValidationError": None})
    assert job["path"] == "/issue/status/update"
    assert job["body"]["status"] == "Confirmed" and job["body"]["reason"] == hub_status.RESET_REASON
    html = card(web, pid, "101")
    assert "Hub не принял снятие прежнего статуса" in html and "To verify is not available" in html
    assert ">Обновить комментарий в Hub</button>" in html and 'id="hub-send-replace"' in html
    r = send(web, pid, "101", extra={"replace": "1", "replace_confirm": "1"})
    assert r.status_code == 200, r.text
    assert run_worker(web, body={"id": 7, "oldStatus": "False Positive", "status": "Confirmed"})["body"]["status"] == "Confirmed"
    second = run_worker(web, body={"id": 8, "oldStatus": "Confirmed", "status": "False Positive"})
    assert second["body"]["status"] == "False Positive" and second["body"]["reason"] == NEW
    assert web.app.state.db.get_review(pid, "101")["entered_hub"] == 1
    assert ">Отправить в Hub</button>" in card(web, pid, "101")
