"""Правила операций в Hub через исполнителя (ADR-0114, app/hub_ops.py): белый список запросов, ключи операции и
блокировки, исход операции по результату, усечение результата, итог проверки связи. Без сети; адреса выдуманы."""

from __future__ import annotations

import json

import pytest

from app import hub_ops

HUB = "https://hub.example.org"


# ============================================================================ белый список


@pytest.mark.parametrize("method,path", [
    ("GET", "/auth/user"),
    ("GET", "/defects/blank?appId=1&issueIds=10,11&type=SAST"),
    ("POST", "/defects"),
    ("GET", "/defects?appId=1&pageIndex=0&pageSize=50"),
    ("GET", "/defects/9001"),
    ("POST", "/defects/9001/link"),
    ("POST", "/issue/status/update"),
    ("POST", "/issue/status/change"),
    ("GET", "/issue/status?issueId=12&issueType=SAST"),
    ("GET", "/issue/sast/12"),
    ("GET", "/issue/sca/security/12"),
    ("GET", "/issue/SCA_S/12/comment"),
    ("GET", "/defects/serviceInfo"),
    ("PUT", "/defects/9001"),  # заголовок и описание существующего дефекта (ADR-0125)
    ("get", "/auth/user"),  # регистр метода не важен
])
def test_allowed_requests_pass(method, path):
    hub_ops.check_request(method, path)


@pytest.mark.parametrize("method,path,why", [
    ("DELETE", "/defects/1", "метод"),
    ("PATCH", "/defects/1", "метод"),
    # PUT – только `PUT /defects/{id}` без параметров (ADR-0125): отвязка, пересборка описания, статус – отказ
    ("PUT", "/defects/1/link", "PUT вне списка"),
    ("PUT", "/defects/1/unlink", "отвязка"),
    ("PUT", "/defects", "PUT без номера"),
    ("PUT", "/defects/blank?appId=1&issueIds=1&type=SAST", "пересборка описания"),
    ("PUT", "/defects/1?appId=1", "параметр у PUT"),
    ("PUT", "/issue/status/update", "статус находки"),
    ("PUT", "/issue/sast/12", "находка"),
    ("POST", "/defects/1/unlink", "отвязка"),
    ("GET", "/defects/1/unlink", "отвязка"),
    ("", "/auth/user", "метод"),
    ("GET", "/auth/logout", "путь вне списка"),
    ("POST", "/auth/login", "вход – дело исполнителя, не очереди"),
    ("GET", "/defects/abc", "не число"),
    ("GET", "/defects/1/../2", ".."),
    ("GET", "/defects/1#x", "#"),
    ("GET", "//defects/1", "//"),
    ("GET", "defects/1", "без /"),
    ("GET", "/defects/1 ", "пробел"),
    ("GET", "/issue/OTHER/12/comment", "тип находки"),
    ("GET", "/auth/user?x=1", "лишний параметр"),
    ("GET", "/defects?appId=1&appId=2", "повтор параметра"),
    ("GET", "/defects?appId=1;drop", "значение параметра"),
    ("GET", "/defects/blank?appId=1&issueIds=1&type=SAST&format=x", "лишний параметр"),
    ("POST", "/defects?appId=1", "параметр у POST"),
])
def test_rejected_requests(method, path, why):
    with pytest.raises(hub_ops.HubRequestRejected):
        hub_ops.check_request(method, path)


def test_allowed_list_has_no_delete_and_one_put():
    """С 0.9.23.dev4 (ADR-0125) в белом списке ровно одна пара PUT – `PUT /defects/{id}` (заголовок и описание
    существующего дефекта); DELETE и прочие PUT – нет. Назначение записи defect_update – запись: повторно не уходит."""
    assert {m for m, _, _ in hub_ops.ALLOWED} == {"GET", "POST", "PUT"} == set(hub_ops.METHODS)
    assert [(m, p, q) for m, p, q in hub_ops.ALLOWED if m == "PUT"] == [("PUT", "/defects/{id}", frozenset())]
    assert "defect_update" in hub_ops.WRITE_PURPOSES and hub_ops.is_write("defect_update")
    assert not any("unlink" in p for _, p, _ in hub_ops.ALLOWED)


# ============================================================================ ключи

TARGETS = [{"issue_type": "SAST", "issue_id": 1, "revision": 3}, {"issue_type": "SAST", "issue_id": 2, "revision": 1}]
REQ = {"method": "POST", "path": "/issue/status/change",
       "body": {"issues": [{"issueId": 1, "issueType": "SAST"}], "status": "False Positive", "reason": "x"}}


def test_op_key_is_stable_to_target_order_and_hub_tail():
    a = hub_ops.op_key(HUB, 1, "status", TARGETS, "текст", REQ)
    b = hub_ops.op_key(HUB + "/", 1, "status", list(reversed(TARGETS)), "текст", REQ)
    assert a == b and len(a) == 40


@pytest.mark.parametrize("change", [
    {"hub_url": "https://other.example.org"},
    {"app_id": 2},
    {"purpose": "defect_link"},
    {"text": "другой текст"},
    {"request": {**REQ, "body": {**REQ["body"], "expiredAt": "2027-01-01T00:00:00Z"}}},
    {"request": {**REQ, "path": "/issue/status/update"}},
    {"targets": TARGETS[:1]},
])
def test_op_key_changes_with_every_identity_part(change):
    base = {"hub_url": HUB, "app_id": 1, "purpose": "status", "targets": TARGETS, "text": "текст", "request": REQ}
    assert hub_ops.op_key(**base) != hub_ops.op_key(**{**base, **change})


def test_op_key_text_is_normalized():
    assert hub_ops.op_key(HUB, 1, "status", TARGETS, "a  b\n c", REQ) == hub_ops.op_key(HUB, 1, "status", TARGETS,
                                                                                       " a b c ", REQ)


def test_lock_keys_one_per_target_and_order_free():
    keys = hub_ops.lock_keys(HUB, 1, "status", TARGETS)
    assert keys == hub_ops.lock_keys(HUB, 1, "status", list(reversed(TARGETS))) and len(keys) == 2
    assert hub_ops.lock_keys(HUB, 1, "status", []) == []
    assert not set(keys) & set(hub_ops.lock_keys(HUB, 1, "defect_create", TARGETS)), "своё назначение – свои замки"


# ============================================================================ исход операции


@pytest.mark.parametrize("result,state", [
    ({"status": 200}, "done"),
    ({"status": 201}, "done"),
    ({"status": 200, "truncated": True}, "unknown"),
    ({"status": 200, "error": "обрыв при чтении тела"}, "unknown"),
    ({"status": 302}, "unknown"),
    ({"status": 500}, "unknown"),
    ({"status": 502}, "unknown"),
    ({"status": 0, "error": "timeout"}, "unknown"),
    ({"status": 0}, "unknown"),
    ({"status": 400}, "failed"),
    ({"status": 401}, "failed"),
    ({"status": 409}, "failed"),
])
def test_write_outcome_everything_but_4xx_is_unknown(result, state):
    assert hub_ops.outcome_state("status", result)[0] == state
    assert hub_ops.outcome_state("defect_create", result)[0] == state


@pytest.mark.parametrize("result,state", [
    ({"status": 200}, "done"),
    ({"status": 200, "truncated": True}, "failed"),
    ({"status": 302}, "failed"),
    ({"status": 502}, "failed"),
    ({"status": 0}, "failed"),
    ({"status": 404}, "failed"),
])
def test_read_outcome_is_done_or_failed(result, state):
    assert hub_ops.outcome_state("probe", result)[0] == state
    assert hub_ops.outcome_state("read", result)[0] == state


def test_not_sent_is_failed_even_for_write():
    """Исполнитель не отправлял запрос (белый список, Hub недоступен до отправки): записи не было – failed, ключ
    освобождается; без признака статус 0 у записи – unknown."""
    state, error = hub_ops.outcome_state("status", {"status": 0, "not_sent": True, "error": "путь вне списка"})
    assert state == "failed" and "не отправлен" in error and "путь вне списка" in error
    assert hub_ops.outcome_state("status", {"status": 0})[0] == "unknown"


def test_outcome_error_text():
    assert "502" in hub_ops.outcome_state("status", {"status": 502})[1]
    assert "усечён" in hub_ops.outcome_state("status", {"status": 200, "truncated": True})[1]
    assert "ответа от Hub нет" in hub_ops.outcome_state("status", {"status": 0})[1]
    assert hub_ops.outcome_state("status", {"status": 200}) == ("done", "")


# ============================================================================ результат и проверка связи


def test_clip_result_truncates_and_keeps_known_fields():
    big = "я" * (hub_ops.RESULT_MAX // 2 + 10)  # кириллица – по 2 байта
    out = hub_ops.clip_result({"status": "200", "body_text": big, "took_ms": "15",
                               "headers": {"Location": "/defects/9", "Set-Cookie": "JSESSIONID=x",
                                           "Content-Type": "application/json"}, "extra": 1})
    assert out["truncated"] and len(out["body_text"].encode("utf-8")) <= hub_ops.RESULT_MAX
    assert out["headers"] == {"location": "/defects/9", "content-type": "application/json"}
    assert out["status"] == 200 and out["took_ms"] == 15 and set(out) == {"status", "headers", "body_text",
                                                                        "truncated", "error", "took_ms", "not_sent"}


def test_clip_result_survives_garbage():
    out = hub_ops.clip_result({"status": "x", "took_ms": "y", "headers": "z", "body_text": None})
    assert out == {"status": 0, "headers": {}, "body_text": "", "truncated": False, "error": "", "took_ms": 0,
                   "not_sent": False}
    assert hub_ops.clip_result({"not_sent": "yes"})["not_sent"] is False, "только настоящее true"


def test_probe_outcome():
    ok = hub_ops.probe_outcome({"status": 200, "body_text": json.dumps(
        {"name": "user1", "firstName": "Иван", "lastName": "Тестов", "roles": ["DEVELOPER"]})})
    assert ok == {"ok": True, "user": "Иван Тестов", "login": "user1", "roles": ["DEVELOPER"], "detail": ""}
    assert not hub_ops.probe_outcome({"status": 401})["ok"]
    assert "заново" in hub_ops.probe_outcome({"status": 401})["detail"]
    assert "не дозвонился" in hub_ops.probe_outcome({"status": 0, "error": "timeout"})["detail"]
    assert "500" in hub_ops.probe_outcome({"status": 500})["detail"]
    assert not hub_ops.probe_outcome({"status": 200, "body_text": "не json"})["ok"]


def test_refusal_text_has_hub_code_and_message():
    """Отказ Hub (4xx) – код и короткое пояснение из тела ответа: оператор видит, что поправить."""
    body = '{"message": "  Поле reason\\n обязательно  ", "code": 17}'
    state, error = hub_ops.outcome_state("status", {"status": 400, "body_text": body})
    assert state == "failed" and error == "Hub ответил кодом 400: Поле reason обязательно"
    assert hub_ops.outcome_state("status", {"status": 403, "body_text": "<html>"})[1] == "Hub ответил кодом 403"
    assert hub_ops.outcome_state("read", {"status": 404, "error": "нет"})[1] == "Hub ответил кодом 404: нет"
    assert hub_ops.outcome_state("read", {"status": 0})[1] == "ответа от Hub нет"
    assert hub_ops.hub_message('["x"]') == "" and hub_ops.hub_message('{"error": "' + "я" * 400 + '"}') == "я" * 300
