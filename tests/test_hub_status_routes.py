"""Статус находки в Hub из карточки (этап 2, ADR-0115): постановка «Ложное срабатывание» SAST для находки и её
группы, «Ложное срабатывание» и «Риск принят» SCA; отказы (нет адреса Hub, номера приложения, срока, решения, другая
редакция, итог не тот); выполнение поддельным исполнителем ставит отметку «Внесено в Hub» только при неизменной
редакции; «результат неизвестен» сверяется чтением статуса. Данные и адреса выдуманы."""

from __future__ import annotations

import json
import re
from datetime import date
from urllib.parse import parse_qs, urlsplit

import pytest

from app import hub_ops
from app.db import text_hash
from app.models import Finding
from app.routes import hub_status_routes
from app.triage import order_findings
from test_web import ORIGIN, web  # noqa: F401

HUB = "https://hub.example.org"
AS_JSON = {**ORIGIN, "Accept": "application/json"}
REASON = "Имя таблицы задано константой, внешний ввод в запрос не попадает."


@pytest.fixture(autouse=True)
def fixed_today(monkeypatch):
    monkeypatch.setattr(hub_status_routes, "today", lambda: date(2026, 10, 28))


def sast(hub_id: str, line: int = 2) -> Finding:
    return Finding(hub_id=hub_id, kind="SAST", rule="Внедрение SQL", cwe=["CWE-89"], codebase="demo", file="demo.py",
                   line=line, snippet="query = 'SELECT ' + value", severity="high")


def sca(hub_id: str) -> Finding:
    return Finding(hub_id=hub_id, kind="SCA", rule="CVSS > 7", cve=["CVE-2099-0001"], component="org.example:lib",
                   version="1.2.3", cvss=8.1, severity="")


def project(web, findings, hub_app_id: int | None = 7, hub_url: str = HUB) -> int:
    db = web.app.state.db
    pid = db.create_project("p")
    db.save_import(pid, "x.xlsx", "xlsx", [], {}, [], order_findings(findings))
    if hub_app_id:
        db.update_project(pid, hub_app_id=hub_app_id)
    db.set_settings({"hub_url": hub_url})
    return pid


def fid(web, pid: int, hub_id: str) -> int:
    return int(web.app.state.db._one("SELECT id FROM findings WHERE project_id = ? AND hub_id = ?", (pid, hub_id))["id"])


def decide(web, pid: int, hub_id: str, verdict: str = "false_positive", decision: str = "agree",
           comment: str = REASON) -> dict:
    return web.app.state.db.save_review(pid, hub_id, decision=decision, final_verdict=verdict, final_comment=comment,
                                        reviewed=True)


def shown_text_hash(web, pid: int, hub_id: str, kind: str = "findings") -> str:
    """Отпечаток текста из формы «Отправить в Hub» – как его отдаёт карточка браузеру."""
    return shown_send_fields(web, pid, hub_id, kind)["text_hash"]


def send_fields_of(html: str) -> dict:
    """Поля формы «Отправить в Hub» из разметки карточки: отпечаток текста и назначение – основа адреса Hub и номер
    приложения, которые карточка показала (KIMI-12)."""
    out = {}
    for name, field_id in (("text_hash", "hub-send-text-hash"), ("hub_base", "hub-send-hub-base"),
                           ("hub_app_id", "hub-send-app-id")):
        found = re.search(rf'id="{field_id}" value="([^"]*)"', html)
        out[name] = found.group(1) if found else ""
    return out


def shown_send_fields(web, pid: int, hub_id: str, kind: str = "findings") -> dict:
    """send_fields_of карточки находки – как их отдаёт браузеру карточка, открытая сейчас."""
    return send_fields_of(web.client.get(f"/projects/{pid}/{kind}/{fid(web, pid, hub_id)}").text)


def send(web, pid: int, hub_id: str, revision: int | None = None, expires: str = "2027-01-26", kind: str = "findings",
         extra: dict | None = None):
    review = web.app.state.db.get_review(pid, hub_id)
    data = {"expires": expires, "review_revision": str(review["revision"] if revision is None else revision),
            "finding_sig": web.app.state.db.finding_sig(pid, hub_id),
            **shown_send_fields(web, pid, hub_id, kind), **(extra or {})}
    return web.client.post(f"/projects/{pid}/{kind}/{fid(web, pid, hub_id)}/hub-status", data=data, headers=AS_JSON)


def worker_headers(web) -> dict:
    key = web.app.state.hub_worker_key
    return {**ORIGIN, "Accept": "application/json", hub_ops.WORKER_KEY_HEADER: key}


def verify(web, pid: int, op_id: int):
    return web.client.post(f"/projects/{pid}/hub/verify", data={"op_id": str(op_id)}, headers=AS_JSON)


def run_worker(web, status: int = 200, body: dict | None = None, error: str = "", identify: bool = True) -> dict:
    """Исполнитель берёт задание и отдаёт ответ. На адресное чтение статуса (`GET /issue/status?issueId=…`) Hub
    отвечает записью той же находки: номер и тип из запроса подставляются в тело, если тест не задал свои
    (identify=False – тело как есть, для ответов без номера и типа)."""
    job = web.client.get("/api/hub/jobs", params={"worker_id": "w1", "hub_url": HUB, "wait": 0},
                         headers=worker_headers(web)).json()["job"]
    assert job is not None
    if identify and body and job["method"] == "GET" and job["path"].startswith("/issue/status?"):
        asked = parse_qs(urlsplit(job["path"]).query)
        body = {"issueId": int(asked["issueId"][0]), "issueType": asked["issueType"][0], **body}
    r = web.client.post(f"/api/hub/jobs/{job['attempt_id']}/result", headers=worker_headers(web), content=json.dumps(
        {"lease_token": job["lease_token"], "status": status, "body_text": json.dumps(body or {}, ensure_ascii=False),
         "error": error}))
    assert r.status_code == 200, r.text
    return job


# ============================================================================ SAST


def test_sast_false_positive_single(web):
    pid = project(web, [sast("101")])
    review = decide(web, pid, "101")
    r = send(web, pid, "101")
    assert r.status_code == 200, r.text
    answer = r.json()
    assert not answer["done"] and "В очереди" in answer["text"]["hub-send-status"]
    job = run_worker(web, body={"id": 1, "status": "False Positive"})
    assert job["method"] == "POST" and job["path"] == "/issue/status/update"
    assert job["body"] == {"issueId": 101, "issueType": "SAST", "status": "False Positive", "reason": REASON,
                           "expiredAt": "2027-01-26T00:00:00Z"}
    after = web.app.state.db.get_review(pid, "101")
    assert after["entered_hub"] == 1 and after["entered_text_hash"] == text_hash(REASON)
    assert after["revision"] == review["revision"], "отметка не меняет редакцию решения"
    state = web.client.get(answer["status_url"]).json()
    assert state["done"] and state.get("reload") and "Записано в Hub" in state["text"]["hub-send-status"]


def test_sast_group_goes_in_one_request(web):
    pid = project(web, [sast("101"), sast("102"), sast("103")])
    decide(web, pid, "101")
    decide(web, pid, "102")
    decide(web, pid, "103", comment="Другое обоснование.")
    assert send(web, pid, "101").status_code == 200
    job = run_worker(web)
    assert job["path"] == "/issue/status/change"
    assert job["body"]["issues"] == [{"issueId": 101, "issueType": "SAST"}, {"issueId": 102, "issueType": "SAST"}]
    db = web.app.state.db
    assert db.get_review(pid, "101")["entered_hub"] == 1 and db.get_review(pid, "102")["entered_hub"] == 1
    assert db.get_review(pid, "103")["entered_hub"] == 0, "другое обоснование – не в группе отправки"


def test_changed_revision_after_send_gets_no_mark(web):
    pid = project(web, [sast("101"), sast("102")])
    decide(web, pid, "101")
    decide(web, pid, "102")
    send(web, pid, "101")
    decide(web, pid, "102", comment=REASON + " Уточнено.")  # решение соседа сохранили заново после отправки
    run_worker(web)
    db = web.app.state.db
    assert db.get_review(pid, "101")["entered_hub"] == 1 and db.get_review(pid, "102")["entered_hub"] == 0


@pytest.mark.parametrize("case,needle,status", [
    ("no_hub", "Адрес Hub не задан", 400),
    ("no_app", "Номер приложения в Hub не задан", 400),
    ("no_expiry", "Укажите срок", 400),
    ("past_expiry", "позже сегодняшней", 400),
    ("stale", "в другой вкладке", 400),
    ("true_positive", "только для «Ложное срабатывание»", 400),
    ("no_decision", "Сначала сохраните решение", 400),
])
def test_sast_refusals(web, case, needle, status):
    pid = project(web, [sast("101")], hub_app_id=None if case == "no_app" else 7, hub_url="" if case == "no_hub" else HUB)
    if case != "no_decision":
        decide(web, pid, "101", verdict="true_positive" if case == "true_positive" else "false_positive")
    else:
        web.app.state.db.save_review(pid, "101", decision="", final_verdict="", final_comment="", reviewed=False)
    kwargs = {"expires": "" if case == "no_expiry" else ("2026-10-01" if case == "past_expiry" else "2027-01-26")}
    if case == "stale":
        kwargs["revision"] = 999
    r = send(web, pid, "101", **kwargs)
    assert r.status_code == status and needle in r.json()["detail"], r.text
    assert web.app.state.db.hub_ops_list() == []


def test_open_operation_refuses_second_send(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    assert send(web, pid, "101").status_code == 200
    r = send(web, pid, "101", expires="2027-03-01")
    assert r.status_code == 409 and "незакрытая" in r.json()["detail"]


def test_failed_send_can_be_repeated(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    send(web, pid, "101")
    run_worker(web, status=400, body={"error": "bad"})
    assert web.app.state.db.get_review(pid, "101")["entered_hub"] == 0
    assert send(web, pid, "101").status_code == 200


# ============================================================================ SCA


@pytest.mark.parametrize("decision,verdict,status", [("agree", "false_positive", "False Positive"),
                                                      ("risk_accepted", "true_positive", "Accepted risk")])
def test_sca_status(web, decision, verdict, status):
    pid = project(web, [sca("50001")])
    decide(web, pid, "50001", verdict=verdict, decision=decision)
    r = send(web, pid, "50001", kind="sca/findings")
    assert r.status_code == 200, r.text
    job = run_worker(web)
    assert job["path"] == "/issue/status/update" and job["body"]["issueType"] == "SCA_S"
    assert job["body"]["status"] == status and job["body"]["issueId"] == 50001
    assert REASON.rstrip(".") in job["body"]["reason"]
    assert web.app.state.db.get_review(pid, "50001")["entered_hub"] == 1


def test_sca_endpoint_refuses_sast_finding(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    assert send(web, pid, "101", kind="sca/findings").status_code == 404


# ============================================================================ результат неизвестен и сверка


def test_unknown_then_verify_matches(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    answer = send(web, pid, "101").json()
    run_worker(web, status=0, error="timeout")
    state = web.client.get(answer["status_url"]).json()
    assert "Результат неизвестен" in state["text"]["hub-send-status"]
    assert web.app.state.db.get_review(pid, "101")["entered_hub"] == 0
    r = verify(web, pid, answer["op_id"])
    assert r.status_code == 200 and "Сверка поставлена" in r.json()["message"]
    assert r.json()["done"] is False  # пока чтение не выполнено, карточка опрашивает состояние
    state = web.client.get(answer["status_url"]).json()
    assert state["done"] is False and "Сверяем с Hub" in state["text"]["hub-send-status"]
    again = verify(web, pid, answer["op_id"]).json()
    assert "Сверка уже идёт" in again["message"]
    job = run_worker(web, body={"status": "False Positive", "reason": REASON, "expiredAt": "2027-01-26T00:00:00Z"})
    assert job["method"] == "GET" and job["path"] == "/issue/status?issueId=101&issueType=SAST"
    assert web.app.state.db.hub_op(answer["op_id"])["state"] == "done"
    assert web.app.state.db.get_review(pid, "101")["entered_hub"] == 1
    state = web.client.get(answer["status_url"]).json()
    assert state["done"] is True and state["reload"] is True


def test_verify_mismatch_stays_unknown(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    answer = send(web, pid, "101").json()
    run_worker(web, status=502)
    verify(web, pid, answer["op_id"])
    run_worker(web, body={})  # статус в Hub не менялся
    op = web.app.state.db.hub_op(answer["op_id"])
    assert op["state"] == "unknown" and "сверка" in op["error"]
    assert web.app.state.db.get_review(pid, "101")["entered_hub"] == 0
    state = web.client.get(answer["status_url"]).json()  # сверка закончилась – снова «Сверить»
    assert state["done"] is True and "Результат неизвестен" in state["text"]["hub-send-status"]


def test_verify_only_for_unknown(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    answer = send(web, pid, "101").json()
    r = verify(web, pid, answer["op_id"])
    assert r.status_code == 400


def test_state_of_other_project_is_404(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    answer = send(web, pid, "101").json()
    other = web.app.state.db.create_project("q")
    assert web.client.get(f"/projects/{other}/hub/ops/{answer['op_id']}").status_code == 404


# ============================================================================ блок «Отправить в Hub» в карточке


def card_html(web, pid: int, hub_id: str, kind: str = "findings") -> str:
    r = web.client.get(f"/projects/{pid}/{kind}/{fid(web, pid, hub_id)}")
    assert r.status_code == 200, r.text
    return r.text


def test_card_panel_blocker_without_hub_url(web):
    pid = project(web, [sast("101")], hub_url="")
    decide(web, pid, "101")
    html = card_html(web, pid, "101")
    assert 'id="hub-send-blocker"' in html and "Адрес Hub не задан" in html
    assert 'id="hub-send-form"' not in html


def test_card_panel_blocker_without_app_id(web):
    pid = project(web, [sast("101")], hub_app_id=None)
    decide(web, pid, "101")
    html = card_html(web, pid, "101")
    assert "Номер приложения в Hub не задан" in html and 'id="hub-send-form"' not in html


def test_card_panel_form_and_presets(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    html = card_html(web, pid, "101")
    assert 'id="hub-send-form"' in html and f'action="/projects/{pid}/findings/{fid(web, pid, "101")}/hub-status"' in html
    # срок обязателен, без умолчания; быстрые сроки считает сервер от сегодняшней даты
    assert 'id="hub-send-expires" min="2026-10-29" max="2031-11-01" required' in html
    assert 'data-date-value="2026-11-27"' in html and 'data-date-value="2027-01-26"' in html
    assert 'data-date-value="2027-04-26"' in html
    assert 'id="hub-send-expires" value=' not in html
    assert 'data-poll="/projects/' not in html  # операций ещё нет
    assert 'data-busy="Ставлю сверку…" hidden>' in html  # «Сверить» скрыта, пока не нужна
    assert 'id="hub-send-confirm-label" hidden' in html  # «Текст проверен» – только при тексте к другому итогу


def test_card_panel_shows_queued_and_polls(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    answer = send(web, pid, "101").json()
    html = card_html(web, pid, "101")
    assert "В очереди: ждём исполнителя" in html and f'data-poll="{answer["status_url"]}"' in html
    run_worker(web)
    html = card_html(web, pid, "101")
    assert "Записано в Hub" in html and 'data-poll="/projects/' not in html


def test_card_panel_unknown_offers_verify(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    answer = send(web, pid, "101").json()
    run_worker(web, status=503)
    html = card_html(web, pid, "101")
    assert "Результат неизвестен" in html
    assert f'action="/projects/{pid}/hub/verify" id="hub-verify-form" class="actions" data-ajax data-busy="Ставлю сверку…">' in html
    assert f'id="hub-verify-op" value="{answer["op_id"]}"' in html


def test_sca_card_panel(web):
    pid = project(web, [sca("201")])
    decide(web, pid, "201", verdict="true_positive", decision="risk_accepted")
    html = card_html(web, pid, "201", kind="sca/findings")
    assert 'id="hub-send-form"' in html and f'/projects/{pid}/sca/findings/{fid(web, pid, "201")}/hub-status' in html


# ============================================================================ по ревью Codex, круг 1


def test_group_sibling_saved_again_before_enqueue_is_refused(web, monkeypatch):
    """Другая вкладка сохраняет решение соседа между сборкой запроса и постановкой: редакции целей сверяются в
    транзакции постановки – операция не ставится, ложность не уходит в Hub."""
    pid = project(web, [sast("101"), sast("102")])
    decide(web, pid, "101")
    decide(web, pid, "102")
    db = web.app.state.db
    real = db.hub_enqueue

    def racing(**kwargs):
        decide(web, pid, "102", verdict="true_positive", decision="disagree")  # тот же комментарий, другой итог
        return real(**kwargs)

    monkeypatch.setattr(db, "hub_enqueue", racing)
    r = send(web, pid, "101")
    assert r.status_code == 400 and "102" in r.json()["detail"] and "изменились" in r.json()["detail"], r.text
    assert db.hub_ops_list() == []


def test_group_sibling_with_other_outcome_is_not_sent(web):
    pid = project(web, [sast("101"), sast("102")])
    decide(web, pid, "101")
    decide(web, pid, "102", verdict="true_positive", decision="disagree")  # тот же комментарий, другой итог
    assert send(web, pid, "101").status_code == 200
    job = run_worker(web)
    assert job["path"] == "/issue/status/update" and job["body"]["issueId"] == 101
    assert web.app.state.db.get_review(pid, "102")["entered_hub"] == 0


MATCH = {"status": "False Positive", "reason": REASON, "expiredAt": "2027-01-26T00:00:00Z"}
OTHER = {"status": "False Positive", "reason": "другое", "expiredAt": "2027-01-26T00:00:00Z"}


def group_unknown(web) -> tuple[int, dict]:
    pid = project(web, [sast("101"), sast("102")])
    decide(web, pid, "101")
    decide(web, pid, "102")
    answer = send(web, pid, "101").json()
    run_worker(web, status=504)
    assert web.app.state.db.hub_op(answer["op_id"])["state"] == "unknown"
    return pid, answer


def test_verify_round_needs_all_reads_of_the_same_round(web):
    """Ответы разных кругов сверки не смешиваются: совпавшее чтение прежнего круга не закрывает операцию вместе с
    чтением нового."""
    pid, answer = group_unknown(web)
    db = web.app.state.db
    assert verify(web, pid, answer["op_id"]).json()["message"].endswith("чтений – 2.")
    first = run_worker(web, body=OTHER)   # круг 1: первая находка не совпала
    second = run_worker(web, body=MATCH)  # круг 1: вторая совпала
    assert {first["path"], second["path"]} == {"/issue/status?issueId=101&issueType=SAST",
                                               "/issue/status?issueId=102&issueType=SAST"}
    op = db.hub_op(answer["op_id"])
    assert op["state"] == "unknown" and "сверка" in op["error"]
    # круг 2: пока закрыто одно чтение – итога нет; второе не совпало – операция остаётся неизвестной
    assert verify(web, pid, answer["op_id"]).json()["message"].endswith("чтений – 2.")
    run_worker(web, body=MATCH)
    assert db.hub_op(answer["op_id"])["state"] == "unknown"
    state = web.client.get(answer["status_url"]).json()
    assert state["done"] is False and "Сверяем с Hub" in state["text"]["hub-send-status"]
    run_worker(web, body=OTHER)
    assert db.hub_op(answer["op_id"])["state"] == "unknown"
    assert db.get_review(pid, "101")["entered_hub"] == 0 and db.get_review(pid, "102")["entered_hub"] == 0
    # круг 3: обе совпали – выполнено, отметки у обеих
    verify(web, pid, answer["op_id"])
    run_worker(web, body=MATCH)
    run_worker(web, body=MATCH)
    assert db.hub_op(answer["op_id"])["state"] == "done"
    assert db.get_review(pid, "101")["entered_hub"] == 1 and db.get_review(pid, "102")["entered_hub"] == 1


def test_verify_round_is_enqueued_whole_or_not_at_all(web):
    pid, answer = group_unknown(web)
    db = web.app.state.db
    # чтение второй находки уже открыто (например, поставлено вручную): круг целиком не ставится
    db.hub_enqueue(purpose="read", request={"method": "GET", "path": "/issue/status?issueId=102&issueType=SAST",
                                            "body": None},
                   hub_url=HUB, app_id=7, project_id=pid, targets=[{"issue_id": 102, "issue_type": "SAST"}])
    before = len(db.hub_ops_list())
    r = verify(web, pid, answer["op_id"]).json()
    assert "Сверка уже идёт" in r["message"] and len(db.hub_ops_list()) == before


def test_verify_while_checking_does_not_start_a_new_round(web):
    pid, answer = group_unknown(web)
    verify(web, pid, answer["op_id"])
    again = verify(web, pid, answer["op_id"]).json()
    assert "Сверка уже идёт" in again["message"] and again["done"] is False


def test_poll_shows_verify_button_after_unknown(web):
    """Карточка, открытая до отправки: опрос после «результат неизвестен» показывает «Сверить» и номер операции."""
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    answer = send(web, pid, "101").json()
    assert "hub-verify-form" in answer["hide"] and answer["value"]["hub-verify-op"] == str(answer["op_id"])
    run_worker(web, status=503)
    state = web.client.get(answer["status_url"]).json()
    assert state["done"] is True and "hub-verify-form" in state["show"]
    assert state["value"]["hub-verify-op"] == str(answer["op_id"])
    checking = verify(web, pid, answer["op_id"]).json()
    assert "hub-verify-form" in checking["hide"] and checking["done"] is False


def test_redelivery_after_failure_completes_the_marks(web, monkeypatch):
    """Сбой после записи результата (отметка не поставилась): исполнитель доставляет тот же результат ещё раз –
    отметки доводятся до конца; уже поставленная отметка не перезаписывается."""
    pid = project(web, [sast("101"), sast("102")])
    decide(web, pid, "101")
    decide(web, pid, "102")
    send(web, pid, "101")
    db = web.app.state.db
    job = web.client.get("/api/hub/jobs", params={"worker_id": "w1", "hub_url": HUB, "wait": 0},
                         headers=worker_headers(web)).json()["job"]
    payload = json.dumps({"lease_token": job["lease_token"], "status": 200, "body_text": "{}"})
    real = db.mark_entered
    calls = []

    def flaky(project_id, hub_id, *args, **kwargs):
        calls.append(hub_id)
        if hub_id == "102" and calls.count("102") == 1:
            raise RuntimeError("сбой записи")
        return real(project_id, hub_id, *args, **kwargs)

    monkeypatch.setattr(db, "mark_entered", flaky)
    r = web.client.post(f"/api/hub/jobs/{job['attempt_id']}/result", headers=worker_headers(web), content=payload)
    assert r.status_code == 500  # исполнитель не получил подтверждения – доставит ещё раз
    assert db.hub_op(job["op_id"])["state"] == "done"
    first = db.get_review(pid, "101")
    assert first["entered_hub"] == 1 and db.get_review(pid, "102")["entered_hub"] == 0
    r = web.client.post(f"/api/hub/jobs/{job['attempt_id']}/result", headers=worker_headers(web), content=payload)
    assert r.status_code == 200 and r.json()["outcome"] == "duplicate"
    assert db.get_review(pid, "102")["entered_hub"] == 1
    assert db.get_review(pid, "101")["entered_hub_at"] == first["entered_hub_at"], "отметка не перезаписана"


def test_model_comment_for_other_outcome_needs_confirm(web, monkeypatch):
    """Комментарий модели к другому итогу: без «Текст проверен» – отказ с reason comment (карточка покажет флажок),
    с флажком той же редакции – отправка."""
    from app.routes import findings as card
    monkeypatch.setattr(card, "comment_origin", lambda *args, **kwargs: "true_positive")
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    r = send(web, pid, "101")
    assert r.status_code == 409 and r.json()["reason"] == "comment" and "Текст проверен" in r.json()["detail"]
    assert web.app.state.db.hub_ops_list() == []
    r = send(web, pid, "101", extra={"comment_confirmed": "1"})
    assert r.status_code == 200, r.text


def test_stale_card_shows_confirm_in_form(web, monkeypatch):
    from app.routes import findings as card
    monkeypatch.setattr(card, "comment_origin", lambda *args, **kwargs: "true_positive")
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    html = card_html(web, pid, "101")
    assert 'id="hub-send-confirm-label">' in html and 'id="hub-send-comment-confirm"' in html


# ============================================================================ по ревью Codex, круг 2


def test_resolve_refused_when_a_newer_round_appeared(web, monkeypatch):
    """Пока считался итог круга 1, другая вкладка поставила круг 2: круг 1 операцию не закрывает."""
    pid, answer = group_unknown(web)
    db = web.app.state.db
    verify(web, pid, answer["op_id"])
    run_worker(web, body=MATCH)
    real = db.hub_resolve

    def racing(op_id, state, note="", check=None):
        db.hub_enqueue(purpose="read", request={"method": "GET", "path": "/issue/status?issueId=101&issueType=SAST",
                                                "body": None},
                       hub_url=HUB, app_id=7, project_id=pid,
                       targets=[{"verify_of": op_id, "round": 2, "issue_id": 101, "issue_type": "SAST"}])
        return real(op_id, state, note, check=check)

    monkeypatch.setattr(db, "hub_resolve", racing)
    run_worker(web, body=MATCH)  # последнее чтение круга 1 совпало
    assert db.hub_op(answer["op_id"])["state"] == "unknown"
    assert db.get_review(pid, "101")["entered_hub"] == 0


def test_new_round_refused_when_operation_got_resolved(web, monkeypatch):
    """Пока ставился круг 2, операцию закрыла сверка круга 1: новый круг не ставится."""
    pid, answer = group_unknown(web)
    db = web.app.state.db
    real = db.hub_enqueue_many

    def racing(items, check=None):
        with db._tx() as c:
            c.execute("UPDATE hub_ops SET state = 'done' WHERE id = ?", (answer["op_id"],))
        return real(items, check=check)

    monkeypatch.setattr(db, "hub_enqueue_many", racing)
    before = len(db.hub_ops_list())
    r = verify(web, pid, answer["op_id"])
    assert r.status_code == 400 and "уже сверена" in r.json()["detail"]
    assert len(db.hub_ops_list()) == before


def reimport_changed(web, pid: int, hub_id: str) -> None:
    """Повторная выгрузка изменила данные находки (как save_import при другой версии или строке)."""
    db = web.app.state.db
    with db._tx() as c:
        row = c.execute("SELECT data_json FROM findings WHERE project_id = ? AND hub_id = ?", (pid, hub_id)).fetchone()
        data = json.loads(row["data_json"])
        data["line"] = int(data.get("line") or 0) + 7
        c.execute("UPDATE findings SET data_json = ? WHERE project_id = ? AND hub_id = ?",
                  (json.dumps(data, ensure_ascii=False), pid, hub_id))


def test_card_opened_before_reimport_is_refused(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    shown = web.app.state.db.finding_sig(pid, "101")
    assert f'name="finding_sig" value="{shown}"' in card_html(web, pid, "101")
    reimport_changed(web, pid, "101")
    r = send(web, pid, "101", extra={"finding_sig": shown})
    assert r.status_code == 400 and "Выгрузка обновилась" in r.json()["detail"]
    r = send(web, pid, "101", extra={"finding_sig": ""})
    assert r.status_code == 400 and "Выгрузка обновилась" in r.json()["detail"]
    assert web.app.state.db.hub_ops_list() == []


def test_reimport_between_build_and_enqueue_is_refused(web, monkeypatch):
    pid = project(web, [sast("101"), sast("102")])
    decide(web, pid, "101")
    decide(web, pid, "102")
    db = web.app.state.db
    real = db.hub_enqueue

    def racing(**kwargs):
        reimport_changed(web, pid, "102")
        return real(**kwargs)

    monkeypatch.setattr(db, "hub_enqueue", racing)
    r = send(web, pid, "101")
    assert r.status_code == 400 and "102" in r.json()["detail"]
    assert db.hub_ops_list() == []


def test_unreviewed_decision_is_not_sent(web):
    """После обновления выгрузки решение снято с «Проверено»: сначала проверить и сохранить."""
    pid = project(web, [sast("101")])
    web.app.state.db.save_review(pid, "101", decision="agree", final_verdict="false_positive", final_comment=REASON,
                                 reviewed=False)
    r = send(web, pid, "101")
    assert r.status_code == 400 and "Проверено" in r.json()["detail"]


def test_without_script_form_has_own_revision_and_redirects(web):
    """Без скрипта: у формы своё поле редакции, успех – возврат в карточку с сообщением, отказ – страница ошибки."""
    pid = project(web, [sast("101")])
    review = decide(web, pid, "101")
    html = card_html(web, pid, "101")
    assert f'<input type="hidden" name="review_revision" value="{review["revision"]}">' in html
    url = f"/projects/{pid}/findings/{fid(web, pid, '101')}/hub-status"
    data = {"expires": "2027-01-26", "review_revision": str(review["revision"]),
            "finding_sig": web.app.state.db.finding_sig(pid, "101"), **send_fields_of(html)}
    assert data["hub_base"] == HUB and data["hub_app_id"] == "7", "назначение – в форме и без скрипта (KIMI-12)"
    as_page = {**ORIGIN, "Accept": "text/html,application/xhtml+xml"}  # как у браузера без скрипта
    r = web.client.post(url, data={**data, "expires": ""}, headers=as_page, follow_redirects=False)
    assert r.status_code == 400 and "Укажите срок" in r.text and "text/html" in r.headers["content-type"]
    r = web.client.post(url, data=data, headers=as_page, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].endswith("ok=hub_queued#hub-send")
    page = web.client.get(r.headers["location"].split("#")[0]).text
    assert "Поставлено в очередь исполнителю" in page and "В очереди: ждём исполнителя" in page


def test_card_keeps_polling_until_marks_are_set(web, monkeypatch):
    """Ответ записан, отметка упала: опрос не останавливается и не перезагружает карточку, пока повторная доставка
    не поставит отметку."""
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    answer = send(web, pid, "101").json()
    db = web.app.state.db
    job = web.client.get("/api/hub/jobs", params={"worker_id": "w1", "hub_url": HUB, "wait": 0},
                         headers=worker_headers(web)).json()["job"]
    payload = json.dumps({"lease_token": job["lease_token"], "status": 200, "body_text": "{}"})
    real = db.mark_entered
    failed = []

    def flaky(*args, **kwargs):
        if not failed:
            failed.append(1)
            raise RuntimeError("сбой записи")
        return real(*args, **kwargs)

    monkeypatch.setattr(db, "mark_entered", flaky)
    assert web.client.post(f"/api/hub/jobs/{job['attempt_id']}/result", headers=worker_headers(web),
                           content=payload).status_code == 500
    state = web.client.get(answer["status_url"]).json()
    assert state["done"] is False and not state.get("reload") and "Ставлю отметку" in state["text"]["hub-send-status"]
    assert f'data-poll="{answer["status_url"]}"' in card_html(web, pid, "101")
    web.client.post(f"/api/hub/jobs/{job['attempt_id']}/result", headers=worker_headers(web), content=payload)
    state = web.client.get(answer["status_url"]).json()
    assert state["done"] is True and state["reload"] is True


def test_pending_marks_wait_is_bounded(web, monkeypatch):
    """Отметку сняли вручную после выполнения: опрос не ждёт её вечно – только окно повторной доставки."""
    from datetime import timedelta

    from app import hub_effects
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    answer = send(web, pid, "101").json()
    run_worker(web)
    db = web.app.state.db
    db.mark_entered(pid, "101", False)
    op = db.hub_op(answer["op_id"])
    assert hub_effects.effects_pending(db, op) is True
    monkeypatch.setattr(hub_effects, "EFFECTS_WAIT", timedelta(seconds=-1))
    assert hub_effects.effects_pending(db, op) is False


def test_concurrent_redelivery_keeps_the_mark_date(web):
    """Отметка той же редакции тем же текстом уже стоит: повторная запись её дату не меняет (проверка в транзакции)."""
    from app import hub_effects
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    answer = send(web, pid, "101").json()
    run_worker(web)
    db = web.app.state.db
    first = db.get_review(pid, "101")["entered_hub_at"]
    with db._tx() as c:  # дата отметки «из прошлого» – видно, перезапишется ли она
        c.execute("UPDATE reviews SET entered_hub_at = '2000-01-01T00:00:00+00:00' WHERE project_id = ? AND hub_id = ?",
                  (pid, "101"))
    assert first
    assert hub_effects.mark_targets(db, db.hub_op(answer["op_id"])) == 0
    assert db.get_review(pid, "101")["entered_hub_at"] == "2000-01-01T00:00:00+00:00"


def test_unknown_note_has_hub_message():
    from app import hub_ops
    state, note = hub_ops.outcome_state("status", {"status": 503, "body_text": '{"message": "maintenance"}'})
    assert state == "unknown" and note == "результат неизвестен: Hub ответил кодом 503: maintenance"


# ============================================================================ по ревью Codex, круг 3


def test_text_changed_after_card_was_shown_is_refused(web, monkeypatch):
    """Текст для Hub изменился после показа (соответствие номеров, новый ответ агента, подписи статусов) при той же
    редакции и тех же данных: отпечаток показанного текста не совпал – отправки нет. Любая зависимость текста
    ловится одной проверкой."""
    from app.routes import sca as sca_card
    pid = project(web, [sca("201")])
    decide(web, pid, "201")
    shown = shown_text_hash(web, pid, "201", kind="sca/findings")
    assert shown
    real = sca_card.saved_hub_text
    monkeypatch.setattr(sca_card, "saved_hub_text",
                        lambda *args, **kwargs: real(*args, **kwargs) + " Также CVE-2099-0002.")
    r = send(web, pid, "201", kind="sca/findings", extra={"text_hash": shown})
    assert r.status_code == 400 and "Текст для Hub изменился" in r.json()["detail"], r.text
    r = send(web, pid, "201", kind="sca/findings", extra={"text_hash": ""})
    assert r.status_code == 400 and "Карточка не показала текст для Hub" in r.json()["detail"]
    assert web.app.state.db.hub_ops_list() == []


def test_sast_text_changed_after_card_was_shown_is_refused(web, monkeypatch):
    from app.routes import findings as card
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    shown = shown_text_hash(web, pid, "101")
    real = card.saved_hub_text
    monkeypatch.setattr(card, "saved_hub_text", lambda *args, **kwargs: real(*args, **kwargs) + " (новая подпись)")
    r = send(web, pid, "101", extra={"text_hash": shown})
    assert r.status_code == 400 and "Текст для Hub изменился" in r.json()["detail"]


def test_sibling_unreviewed_is_left_out_of_the_group(web):
    """Выгрузка сняла «Проверено» с соседа: он не блокирует отправку группы, а уходит своей карточкой после проверки."""
    pid = project(web, [sast("101"), sast("102")])
    decide(web, pid, "101")
    web.app.state.db.save_review(pid, "102", decision="agree", final_verdict="false_positive", final_comment=REASON,
                                 reviewed=False)
    assert send(web, pid, "101").status_code == 200
    job = run_worker(web)
    assert job["path"] == "/issue/status/update" and job["body"]["issueId"] == 101
    assert web.app.state.db.get_review(pid, "102")["entered_hub"] == 0


def test_verify_without_script_returns_to_the_card(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    answer = send(web, pid, "101").json()
    run_worker(web, status=503)
    as_page = {**ORIGIN, "Accept": "text/html,application/xhtml+xml",
               "Referer": f"http://testserver/projects/{pid}/findings/{fid(web, pid, '101')}?ok=hub_queued"}
    r = web.client.post(f"/projects/{pid}/hub/verify", data={"op_id": str(answer["op_id"])}, headers=as_page,
                        follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == f"/projects/{pid}/findings/{fid(web, pid, '101')}?ok=hub_verify_queued#hub-send"
    r = web.client.post(f"/projects/{pid}/hub/verify", data={"op_id": ""}, headers=as_page, follow_redirects=False)
    assert r.status_code == 404 and "text/html" in r.headers["content-type"] and "Операция не найдена" in r.text


def test_truncated_refusal_keeps_code_and_message():
    from app import hub_ops
    state, note = hub_ops.outcome_state("status", {"status": 503, "body_text": '{"message": "maintenance"}',
                                                   "error": "ответ Hub прочитан не полностью: 25 из 100 байт"})
    assert state == "unknown"
    assert note == ("результат неизвестен: Hub ответил кодом 503: maintenance; "
                    "ответ Hub прочитан не полностью: 25 из 100 байт")
    assert hub_ops.outcome_state("status", {"status": 0, "error": "timeout"})[1] == "результат неизвестен: timeout"


# ============================================================================ по ревью Codex, круг 4

AS_PAGE = {**ORIGIN, "Accept": "text/html,application/xhtml+xml"}  # браузер без скрипта


def form_value(html: str, name: str) -> str:
    found = re.search(rf'name="{name}" value="([^"]*)"', html)
    return found.group(1) if found else ""


def card_value(html: str, element_id: str) -> str:
    tag = re.search(rf'<input[^>]* id="{element_id}"[^>]*>', html)
    assert tag, element_id
    return re.search(r'value="([^"]*)"', tag.group(0)).group(1)


def stale_draft_page(web, pid: int, hub_id: str, kind: str, data: dict) -> str:
    """Карточка открыта, в другой вкладке решение сохранили заново, эта сохраняет устаревшую форму без скрипта: ответ
    409 – карточка-черновик с введённым, а не сохранённым решением."""
    url = f"/projects/{pid}/{kind}/{fid(web, pid, hub_id)}"
    card = web.client.get(url).text
    shown = {"finding_version": form_value(card, "finding_version"), "verdict_id": form_value(card, "verdict_id"),
             "review_revision": card_value(card, "review-revision")}
    decide(web, pid, hub_id, decision=data.get("decision") if kind != "findings" else "agree",
           comment=REASON + " Уточнено во второй вкладке.")
    r = web.client.post(f"{url}/review", headers=AS_PAGE, data={**shown, **data, "reviewed": "1", "action": "save"})
    assert r.status_code == 409 and "подставлен в форму" in r.text, r.text[:400]
    return r.text


def test_draft_card_gives_no_send_hash_sast(web):
    """Черновик (ответ 409 на устаревшую форму) показывает введённое, а не сохранённое решение: отпечатка текста для
    Hub в форме нет, отправка из него отказывает – не уходит текст, которого карточка не показала."""
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    page = stale_draft_page(web, pid, "101", "findings",
                            {"decision": "false_positive", "comment": "Черновик оператора из первой вкладки."})
    assert card_value(page, "hub-send-text-hash") == ""
    assert hub_status_routes.DRAFT_NOTE in page
    r = send(web, pid, "101", extra={"text_hash": card_value(page, "hub-send-text-hash")})
    assert r.status_code == 400 and r.json()["detail"] == hub_status_routes.TEXT_NOT_SHOWN
    assert web.app.state.db.hub_ops_list() == []
    # обычная карточка того же решения – отпечаток есть, отправка проходит
    assert shown_text_hash(web, pid, "101") and send(web, pid, "101").status_code == 200


def test_draft_card_gives_no_send_hash_sca(web):
    pid = project(web, [sca("201")])
    decide(web, pid, "201", decision="disagree")
    page = stale_draft_page(web, pid, "201", "sca/findings",
                            {"decision": "disagree", "final_verdict": "false_positive",
                             "comment": "Черновик оператора из первой вкладки."})
    assert card_value(page, "hub-send-text-hash") == ""
    assert hub_status_routes.DRAFT_NOTE in page
    r = send(web, pid, "201", kind="sca/findings", extra={"text_hash": ""})
    assert r.status_code == 400 and r.json()["detail"] == hub_status_routes.TEXT_NOT_SHOWN
    assert web.app.state.db.hub_ops_list() == []


def test_sca_preview_and_send_hash_come_from_one_read(web, monkeypatch):
    """Предпросмотр и отпечаток отправки SCA – одна строка: текст для Hub читается один раз на сборку карточки, и
    отпечаток в форме – от того текста, что показан в предпросмотре."""
    import html as html_lib

    from app.routes import sca as sca_card
    pid = project(web, [sca("201")])
    decide(web, pid, "201", decision="disagree")
    calls = []
    real = sca_card.saved_hub_text

    def counted(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs) + f" (чтение {len(calls)})"
    monkeypatch.setattr(sca_card, "saved_hub_text", counted)
    page = web.client.get(f"/projects/{pid}/sca/findings/{fid(web, pid, '201')}").text
    shown = card_value(page, "hub-send-text-hash")
    db = web.app.state.db
    base = real(db, web.app.state.settings, pid, Finding.from_dict(db.case_input(pid, "201")["data"]),
                db.get_review(pid, "201"))
    in_preview = [n for n in range(1, len(calls) + 1) if f"{base} (чтение {n})" in html_lib.unescape(page)]
    assert in_preview, "предпросмотр показывает текст для Hub"
    assert shown == text_hash(f"{base} (чтение {in_preview[-1]})")


def test_unsettled_sca_card_refuses_to_send(web, monkeypatch):
    """Пакет менялся на всех трёх попытках сборки карточки: отпечатка текста для Hub нет, отправка отказывает."""
    pid = project(web, [sca("201")])
    decide(web, pid, "201", decision="disagree")
    db = web.app.state.db
    real = db.sca_defect_fingerprint
    ticks = iter(range(10_000))
    monkeypatch.setattr(db, "sca_defect_fingerprint", lambda *a, **k: f"{real(*a, **k)}-{next(ticks)}")
    page = web.client.get(f"/projects/{pid}/sca/findings/{fid(web, pid, '201')}").text
    assert "Данные этой версии компонента меняются" in page
    assert card_value(page, "hub-send-text-hash") == "" and hub_status_routes.UNSETTLED_NOTE in page
    monkeypatch.undo()
    r = send(web, pid, "201", kind="sca/findings", extra={"text_hash": ""})
    assert r.status_code == 400 and r.json()["detail"] == hub_status_routes.TEXT_NOT_SHOWN


def test_missing_project_refusal_is_built_in_threadpool(web, monkeypatch):
    """«Проект не найден» у отправки и «Сверить» без скрипта – страница из пула потоков, а не общий обработчик в цикле
    событий; со скриптом и у опроса состояния – JSON."""
    import asyncio
    seen = []
    real = hub_status_routes.error_response

    def recorded(*args, **kwargs):
        try:
            asyncio.get_running_loop()
            seen.append("loop")
        except RuntimeError:
            seen.append("thread")
        return real(*args, **kwargs)
    monkeypatch.setattr(hub_status_routes, "error_response", recorded)
    r = web.client.post("/projects/9999/findings/1/hub-status", headers=AS_PAGE, data={"expires": "2027-01-26"})
    assert r.status_code == 404 and "text/html" in r.headers["content-type"] and "Проект не найден" in r.text
    r = web.client.post("/projects/9999/hub/verify", headers=AS_PAGE, data={"op_id": "1"})
    assert r.status_code == 404 and "Проект не найден" in r.text
    assert seen == ["thread", "thread"]
    r = web.client.post("/projects/9999/sca/findings/1/hub-status", headers=AS_JSON, data={"expires": "2027-01-26"})
    assert r.status_code == 404 and r.json()["detail"] == "Проект не найден."
    r = web.client.get("/projects/9999/hub/ops/1", headers=AS_JSON)
    assert r.status_code == 404 and r.json()["detail"] == "Проект не найден."


def test_truncated_4xx_keeps_hub_message():
    state, note = hub_ops.outcome_state("status", {"status": 403, "body_text": '{"message": "maintenance"}',
                                                   "error": "ответ Hub прочитан не полностью: 25 из 100 байт"})
    assert state == "failed"
    assert note == "Hub ответил кодом 403: maintenance; ответ Hub прочитан не полностью: 25 из 100 байт"
    assert hub_ops.outcome_state("status", {"status": 403, "body_text": '{"message": "maintenance"}'})[1] == \
        "Hub ответил кодом 403: maintenance"


# ============================================================================ срок – как его покажет Hub


def test_until_moment_is_the_end_of_the_day_in_utc():
    """Hub хранит срок как конец выбранного дня по UTC: карточка показывает тот же момент."""
    assert hub_status_routes.until_moment("2027-01-26T00:00:00Z") == "2027-01-26T23:59:59Z"
    assert hub_status_routes.until_moment("2027-01-26") == "2027-01-26T23:59:59Z"
    assert hub_status_routes.until_moment("") == "" and hub_status_routes.until_moment(None) == ""
    assert hub_status_routes.until_moment("2027-13-40T00:00:00Z") == "" and hub_status_routes.until_moment("мусор") == ""


def test_status_line_carries_the_until_moment(web):
    """Состояние со сроком: текст без скрипта – момент по UTC, со скриптом – элемент времени (пояс браузера, как в
    интерфейсе Hub); в разметке карточки – тот же элемент; состояние без срока – без него."""
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    answer = send(web, pid, "101").json()
    queued = answer["text"]["hub-send-status"]
    assert queued == "В очереди: ждём исполнителя – «Ложное срабатывание», срок до 26.01.2027, 23:59 UTC."
    assert answer["times"]["hub-send-status"] == {
        "prefix": "В очереди: ждём исполнителя – «Ложное срабатывание», срок до ",
        "datetime": "2027-01-26T23:59:59Z", "suffix": "."}
    run_worker(web)
    state = web.client.get(answer["status_url"], headers=AS_JSON).json()
    assert state["text"]["hub-send-status"] == "Записано в Hub: «Ложное срабатывание», срок до 26.01.2027, 23:59 UTC."
    assert state["times"]["hub-send-status"]["datetime"] == "2027-01-26T23:59:59Z"
    html = web.client.get(f"/projects/{pid}/findings/{fid(web, pid, '101')}").text
    status = re.search(r'id="hub-send-status"[^>]*>(.*?)</p>', html, re.S).group(1)
    assert status == ('Записано в Hub: «Ложное срабатывание», срок до '
                      '<time datetime="2027-01-26T23:59:59Z">26.01.2027, 23:59 UTC</time>.')
    assert 'id="hub-send-until-preview"' in html


def test_status_line_without_until_has_no_time(web):
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    answer = send(web, pid, "101").json()
    run_worker(web, status=503)
    state = web.client.get(answer["status_url"], headers=AS_JSON).json()
    assert "Результат неизвестен" in state["text"]["hub-send-status"] and "times" not in state


# ============================================================================ сосед уже внесён в Hub (ADR-0116)


def test_sibling_already_entered_in_hub_is_left_out_of_the_group(web):
    """Сосед уже внесён в Hub тем же статусом: Hub отклонил бы весь групповой запрос («issue already has the requested
    status») – сосед в группу не входит, ответ называет его; уходит одна находка – update, а не change."""
    pid = project(web, [sast("101"), sast("102")])
    decide(web, pid, "101")
    send(web, pid, "101")
    run_worker(web)
    assert web.app.state.db.get_review(pid, "101")["entered_hub"] == 1
    decide(web, pid, "102")
    answer = send(web, pid, "102").json()
    assert answer["ok"] and "Уже внесена в Hub и не отправляется: 101." in answer["message"], answer
    job = run_worker(web)
    assert job["path"] == "/issue/status/update" and job["body"]["issueId"] == 102


def test_sibling_with_done_operation_is_left_out_even_without_the_mark(web):
    """Ответ Hub 2xx записан, а отметка не встала (или её сняли): статус в Hub уже стоит – по выполненной операции
    с тем же статусом сосед всё равно не входит в группу."""
    pid = project(web, [sast("101"), sast("102")])
    db = web.app.state.db
    decide(web, pid, "101")
    send(web, pid, "101")
    run_worker(web)
    db.mark_entered(pid, "101", False, db.get_review(pid, "101")["revision"], "")
    assert db.get_review(pid, "101")["entered_hub"] == 0
    decide(web, pid, "102")
    answer = send(web, pid, "102").json()
    assert "Уже внесена в Hub и не отправляется: 101." in answer["message"]
    assert run_worker(web)["path"] == "/issue/status/update"


def test_manual_mark_does_not_exclude_the_sibling_without_a_scoped_operation(web):
    """AUD-02: ручная отметка без назначения не доказывает фактический статус соседа."""
    pid = project(web, [sast("101"), sast("102")])
    db = web.app.state.db
    decide(web, pid, "101")
    decide(web, pid, "102")
    db.mark_entered(pid, "101", True, db.get_review(pid, "101")["revision"], "x")
    answer = send(web, pid, "102").json()
    assert answer["ok"] and "Уже внесен" not in answer["message"]
    job = run_worker(web)
    assert job["path"] == "/issue/status/change"
    assert sorted(i["issueId"] for i in job["body"]["issues"]) == [101, 102]


def test_group_composition_is_checked_in_the_enqueue_transaction(web, monkeypatch):
    """Ответ операции соседа приходит между сборкой и постановкой: состав проверяется в транзакции."""
    pid = project(web, [sast("101"), sast("102")])
    db = web.app.state.db
    decide(web, pid, "101")
    assert send(web, pid, "101").status_code == 200
    decide(web, pid, "102")
    original = db.hub_enqueue

    def completed_meanwhile(*args, **kwargs):
        run_worker(web)
        return original(*args, **kwargs)

    monkeypatch.setattr(db, "hub_enqueue", completed_meanwhile)
    r = send(web, pid, "102")
    assert r.status_code == 400 and "Состав группы изменился" in r.json()["detail"], r.text
    assert len(db.hub_ops_list()) == 1 and db.hub_ops_list()[0]["state"] == "done"


def test_skipped_siblings_are_reported_without_script(web):
    pid = project(web, [sast("101"), sast("102")])
    db = web.app.state.db
    decide(web, pid, "101")
    send(web, pid, "101")
    run_worker(web)
    decide(web, pid, "102")
    review = db.get_review(pid, "102")
    data = {"expires": "2027-01-26", "review_revision": str(review["revision"]), "finding_sig": db.finding_sig(pid, "102"),
            **shown_send_fields(web, pid, "102")}
    r = web.client.post(f"/projects/{pid}/findings/{fid(web, pid, '102')}/hub-status", data=data,
                        headers={**ORIGIN, "Accept": "text/html,application/xhtml+xml"}, follow_redirects=False)
    assert r.status_code == 303 and "ok=hub_queued_skipped" in r.headers["location"], r.headers.get("location")
    page = web.client.get(r.headers["location"]).text
    assert "уже внесён в Hub, не отправляются" in page


def test_hub_error_dto_reason_is_shown():
    """Отказ Hub по его схеме HubErrorDto: errorMessage и ошибки полей – в пояснении."""
    body = ('{"errorMessage":"Unable to change status for SAST issue #4242: issue already has the requested status '
            'FALSE_POSITIVE","requestValidationError":null}')
    state, note = hub_ops.outcome_state("status", {"status": 400, "body_text": body})
    assert state == "failed"
    assert note == ("Hub ответил кодом 400: Unable to change status for SAST issue #4242: issue already has the "
                    "requested status FALSE_POSITIVE")
    fields = '{"errorMessage":"Validation failed","requestValidationError":{"expiredAt":{"code":"x","message":"bad date"}}}'
    assert hub_ops.hub_message(fields) == "Validation failed; expiredAt: bad date"
    assert hub_ops.hub_message('{"message": "maintenance"}') == "maintenance"
    assert hub_ops.hub_message("<html>") == "" and hub_ops.hub_message('{"requestValidationError": {"a": 1}}') == ""


def test_done_operation_of_another_hub_does_not_leave_the_sibling_out(web):
    """Выполненная операция другого адреса Hub не доказывает статус в текущем Hub: сосед входит в группу."""
    pid = project(web, [sast("101"), sast("102")])
    db = web.app.state.db
    decide(web, pid, "101")
    send(web, pid, "101")
    run_worker(web)
    db.mark_entered(pid, "101", False, db.get_review(pid, "101")["revision"], "")
    db.set_settings({"hub_url": "https://hub2.example.org"})
    decide(web, pid, "102")
    answer = send(web, pid, "102").json()
    assert answer["ok"] and "Уже внесен" not in answer["message"], answer
    op = db.hub_op(answer["op_id"])
    assert json.loads(op["request_json"])["path"] == "/issue/status/change"
    assert op["hub_url"] == "https://hub2.example.org"
