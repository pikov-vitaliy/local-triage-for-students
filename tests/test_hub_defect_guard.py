"""Находка с дефектом, созданным в Hub (ADR-0121): смена решения, статус из карточки и снятие отметки «Внесено в
Hub» – отказ 409 reason=defect без подтверждения и успех с defect_confirm=1 (статус с dev32 – через дефект: панели у
находки в дефекте нет, отправка отклоняется, сосед в дефекте из группы исключается); то же повторное сохранение – без
подтверждения; «Отправить выбранные в Hub» исключает такую находку, и транзакция постановки проверяет то же; новая
находка группы привязывается к готовому дефекту («создан» или «привязка неполная»); строка привязки после чтения –
как строка создания (без состава – «неизвестен», без находки – «привязка неполная», неизвестная привязка без находки –
«не принят» со сбоем, доведённым показом карточки); запрет второго дефекта по группе – в транзакции, состав группы –
там же; «Проверить в Hub» – только сверка (404, состав, сбой – пояснение); ключ операции записи – со строкой дефекта;
подсказка статуса – по группе; состав привязки – показанный оператору, только того же Hub и приложения, groupId – из
заготовки строки создания; цели чтения проверки – по строке дефекта. Данные, адреса и номера выдуманы."""

from __future__ import annotations

import json
import re
from datetime import date

import pytest

from app import hub_defects, hub_status
from app.db import Database
from app.routes import hub_defect_routes, hub_status_routes
from hub_fixtures import SAST_ROWS, make_hub_xlsx
from test_defect import save_sast
from test_hub_defects import BLANK, FIX, HUB_DESCRIPTION, REASON, SERVICE, blank, create, hub_job, hub_settings, no_job, pair_project
from test_hub_defects import sast_ready, shown, to_preview, verify
from test_hub_status_routes import AS_JSON, HUB, send, worker_headers
from test_sca import sca_text_ready
from test_sca_package_decision import UPD, post_package
from test_web import ORIGIN, create_project, hidden_fields, prepared, start_run, upload, wait_run, web  # noqa: F401

BOUND = ("Находка входит в дефект №555 (ID1), созданный в Hub. Дефект в Hub не изменится – поправьте его в Hub сами. "
         "Сохранить решение?")
FP_TEXT = "Ложное срабатывание: значение берётся из белого списка, внешний ввод в запрос не попадает."


@pytest.fixture(autouse=True)
def fixed_today(monkeypatch):
    monkeypatch.setattr(hub_status_routes, "today", lambda: date(2026, 10, 28))


# ============================================================================ помощники


def created(web, pid: int, url: str, defect_id: int = 555, links: tuple = (510001,), service: bool = True) -> dict:
    """Дефект из карточки url до «создан»: заготовка, «Создать», ответ на создание и подтверждающее чтение."""
    row = to_preview(web, pid, url, service=service)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, body={"id": defect_id})
    hub_job(web, body={"id": defect_id, "linkedIssues": [{"id": i, "type": "SAST"} for i in links]})
    row = web.app.state.db.hub_defect(row["id"])
    assert row["state"] == "done", row["error"]
    return row


def post_review(web, url: str, comment: str, decision: str = "true_positive", fix: str = FIX, as_json: bool = True,
                **extra):
    """Решение формой карточки как есть (без проверки ответа): редакция и скрытые поля – из текущей карточки."""
    card = web.client.get(url).text
    data = {**hidden_fields(card), "review_revision": re.search(r'name="review_revision" value="(\d+)"', card).group(1),
            "decision": decision, "final_verdict": "", "comment": comment, "fix": fix, "reviewed": "1",
            "action": "save", **extra}
    return web.client.post(f"{url}/review", headers=AS_JSON if as_json else ORIGIN, data=data, follow_redirects=False)


def link_fields(card: str) -> dict:
    """Поля формы «Привязать к дефекту» из карточки."""
    form = re.search(r'<form [^>]*id="hub-defect-link-form".*?</form>', card, re.S).group(0)
    return {name: re.search(rf'name="{name}" value="([^"]*)"', form).group(1)
            for name in ("review_revision", "text_hash", "defect", "targets")}


def recheck(web, pid: int, defect_id: int):
    return web.client.post(f"/projects/{pid}/hub/defects/{defect_id}/recheck", headers=AS_JSON)


def last_op(db, purpose: str) -> dict:
    return [o for o in db.hub_ops_list() if o["purpose"] == purpose][0]


# ============================================================================ тексты и правила


def test_bound_texts_and_states():
    row = {"hub_defect_id": "555", "number": 1}
    assert hub_defects.bound_text(row, hub_defects.SAVE_QUESTION) == BOUND
    assert hub_defects.bound_name(row) == "дефект №555 (ID1)" and hub_defects.bound_label(row) == "№555 (ID1)"
    creating = {"hub_defect_id": "", "number": 2}
    assert hub_defects.bound_text(creating, "Вопрос?", "510005").startswith(
        "Находка 510005 входит в дефект ID2, который создаётся в Hub (номер в Hub ещё не известен).")
    old = {"decision": "agree", "final_verdict": "true_positive", "final_comment": "а", "final_fix": "б"}
    assert not hub_defects.decision_changes(old, "agree", "true_positive", "а", "б")
    assert not hub_defects.decision_changes(old, "disagree", "true_positive", "а", None), "новый ответ модели – не смена"
    assert hub_defects.decision_changes(old, "agree", "true_positive", "а", "в")
    assert hub_defects.decision_changes(old, "agree", "true_positive", "другое", None)
    assert hub_defects.decision_changes(old, "disagree", "false_positive", "а", "")
    assert set(hub_defects.BOUND_STATES) == {"creating", "created", "linking", "mismatch", "unknown", "unconfirmed", "done"}
    # снятие привязки по 404 вырезано из сборки (бэклог 39): такого состояния нет
    assert "released" not in hub_defects.STATES and "released" not in Database.HUB_DEFECT_FINAL


# ============================================================================ п. 2: смена решения


def test_changed_decision_needs_confirmation_and_marks_the_card(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = created(web, pid, url)
    card = web.client.get(url).text
    assert 'id="defect-bound-row" hidden' in card and 'id="hub-defect-decision-changed"' not in card
    # то же решение ещё раз – без подтверждения: решение не меняется, отметка остаётся
    again = post_review(web, url, REASON)
    assert again.status_code == 200, again.text
    assert db.get_review(pid, "510001")["entered_hub"] == 1
    assert 'id="hub-defect-decision-changed"' not in web.client.get(url).text, "редакция новее, текст тот же"
    # другое обоснование без подтверждения – 409 reason=defect, решение прежнее
    r = post_review(web, url, REASON + " Уточнено.")
    assert r.status_code == 409 and r.json() == {"ok": False, "detail": BOUND, "reason": "defect"}
    assert db.get_review(pid, "510001")["final_comment"] == REASON
    r = post_review(web, url, FP_TEXT, decision="false_positive", fix="")
    assert r.status_code == 409 and r.json()["reason"] == "defect"
    # без скрипта – карточка с текстом отказа, черновиком и открытым флажком подтверждения
    page = post_review(web, url, REASON + " Уточнено.", as_json=False)
    assert page.status_code == 409 and BOUND in page.text
    assert 'id="defect-bound-row">' in page.text and 'name="defect_confirm" value="1" id="defect-bound-confirm"' in page.text
    assert REASON + " Уточнено." in page.text
    assert db.get_review(pid, "510001")["final_comment"] == REASON
    # с подтверждением – сохранено; дефект в Hub прежний, запросов в Hub нет; карточка помечает смену решения
    ok = post_review(web, url, REASON + " Уточнено.", defect_confirm="1")
    assert ok.status_code == 200, ok.text
    assert db.get_review(pid, "510001")["final_comment"] == REASON + " Уточнено."
    assert db.hub_defect(row["id"])["state"] == "done" and db.hub_defect_bound(pid, "510001")["id"] == row["id"]
    no_job(web)
    card = web.client.get(url).text
    assert 'id="hub-defect-decision-changed"' in card
    assert "Решение изменено после создания дефекта №555 (ID1) – дефект в Hub прежний" in card
    # прежний текст вернули (тоже смена – с подтверждением): текст снова тот, с которым создан дефект – пометки нет
    assert post_review(web, url, REASON).status_code == 409
    assert post_review(web, url, REASON, defect_confirm="1").status_code == 200
    assert 'id="hub-defect-decision-changed"' not in web.client.get(url).text


def test_unbound_finding_saves_without_confirmation(web):
    """Заготовка и предпросмотр находку не привязывают: смена решения – как раньше."""
    pid, url = sast_ready(web)
    to_preview(web, pid, url)
    r = post_review(web, url, REASON + " Без дефекта в Hub.")
    assert r.status_code == 200, r.text
    assert web.app.state.db.hub_defect_bound(pid, "510001") is None


# ============================================================================ п. 3: статус


def test_status_of_bound_finding_goes_through_the_defect(web):
    """dev32: у находки в дефекте панели «Отправить в Hub» нет – пояснение и ссылка на
    дефект; отправка отклоняется и с прежним флажком подтверждения."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = created(web, pid, url)
    assert post_review(web, url, FP_TEXT, decision="false_positive", fix="", defect_confirm="1").status_code == 200
    card = web.client.get(url).text
    assert 'id="hub-send-in-defect"' in card and 'id="hub-send-form"' not in card
    assert "Находка входит в дефект №555 (ID1): статус и комментарий в Hub у неё идут через дефект" in card
    assert "отвяжите её от дефекта в Hub, затем на вкладке «Дефекты» нажмите «Синхронизировать»" in card  # из приложения
    assert f'href="/projects/{pid}/defects/{row["id"]}"' in card
    assert "примените «Pull из Hub» у дефекта" in hub_defects.in_defect_text({**row, "origin": "import"})
    assert 'id="hub-send-defect-row"' not in card and 'id="hub-send-defect-confirm"' not in card
    for extra in ({}, {"defect_confirm": "1"}):
        r = send(web, pid, "510001", extra=extra)
        assert r.status_code == 400 and "идут через дефект" in r.json()["detail"], r.text
    assert not [o for o in db.hub_ops_list() if o["purpose"] == "status"]
    assert db.hub_defect_bound(pid, "510001")["hub_defect_id"] == "555", "дефект в приложении прежний"
    # находка вошла в дефект между сборкой запроса и постановкой – отказ транзакции тем же пояснением
    with db._tx() as c:
        with pytest.raises(hub_defects.DefectBound) as exc:
            hub_defects.refuse_in_defect(c, pid, ["510001"], own="510001")
    assert str(exc.value).startswith("Находка входит в дефект №555 (ID1):")


def test_send_selected_excludes_bound_finding_and_checks_it_in_the_transaction(web, monkeypatch):
    pid, url = sast_ready(web)
    db = web.app.state.db
    created(web, pid, url)
    assert post_review(web, url, FP_TEXT, decision="false_positive", fix="", defect_confirm="1").status_code == 200
    page = web.client.get(f"/projects/{pid}/hub/send-selected?hub_id=510001").text
    assert "входит в дефект №555 (ID1) – статус противоречил бы дефекту в Hub" in page
    # предпросмотр не увидел привязку (например, дефект создан в другой вкладке) – её проверяет транзакция постановки
    review = db.get_review(pid, "510001")
    monkeypatch.setattr(db, "hub_defect_bound", lambda *args, **kwargs: None)
    # форма такого предпросмотра несёт назначение, по которому он собран: тот же Hub и приложение 7 (KIMI-12)
    r = web.client.post(f"/projects/{pid}/hub/send-selected", headers=AS_JSON, data={
        "target": f"510001|{review['revision']}|{db.finding_sig(pid, '510001')}", "comment": FP_TEXT,
        "expires": "2027-01-26", "hub_base": HUB, "hub_app_id": "7"})
    assert r.status_code == 400 and "входит в дефект №555 (ID1)" in r.json()["detail"], r.text
    assert not [o for o in db.hub_ops_list() if o["purpose"] == "status"]


# ============================================================================ п. 4: снятие отметки


def test_unmarking_entered_of_bound_finding_needs_confirmation(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    created(web, pid, url)
    assert db.get_review(pid, "510001")["entered_hub"] == 1
    card = web.client.get(url).text
    assert 'id="unenter-defect-row">' in card and 'form="unenter-form" id="unenter-defect-confirm"' in card
    r = web.client.post(f"{url}/entered", headers=AS_JSON, data={"entered": "0"})
    assert r.status_code == 409 and r.json()["reason"] == "defect", r.text
    assert "№555 (ID1)" in r.json()["detail"] and r.json()["detail"].endswith("Снять отметку «Внесено в Hub»?")
    assert db.get_review(pid, "510001")["entered_hub"] == 1
    page = web.client.post(f"{url}/entered", headers=ORIGIN, data={"entered": "0"})
    assert page.status_code == 409 and "Снять отметку «Внесено в Hub»?" in page.text
    r = web.client.post(f"{url}/entered", headers=AS_JSON, data={"entered": "0", "defect_confirm": "1"})
    assert r.status_code == 200, r.text
    assert db.get_review(pid, "510001")["entered_hub"] == 0
    no_job(web)  # Hub не трогается


def test_sca_unmarking_entered_of_bound_set_needs_confirmation(web):
    pid = prepared(web)
    db = web.app.state.db
    hub_settings(web, pid)
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    url = f"/projects/{pid}/sca/findings/{db.get_finding_by_hub_id(pid, '73001')['id']}"
    sca_text_ready(web, url)
    links = [{"id": 73001, "type": "SCA_S"}, {"id": 73002, "type": "SCA_S"}]
    assert blank(web, url).status_code == 200
    hub_job(web, body={**BLANK, "linkedIssues": links})
    hub_job(web, body=SERVICE)
    row = db.hub_defects(pid)[0]
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, body={"id": 900})
    hub_job(web, body={"id": 900, "linkedIssues": links})
    assert db.hub_defect(row["id"])["state"] == "done" and db.get_review(pid, "73001")["entered_hub"] == 1
    assert 'id="unenter-defect-row"' in web.client.get(url).text
    r = web.client.post(f"{url}/entered", headers=AS_JSON, data={"entered": "0"})
    assert r.status_code == 409 and r.json()["reason"] == "defect" and "№900" in r.json()["detail"], r.text
    r = web.client.post(f"{url}/entered", headers=AS_JSON, data={"entered": "0", "defect_confirm": "1"})
    assert r.status_code == 200 and db.get_review(pid, "73001")["entered_hub"] == 0


# ============================================================================ п. 5: новая находка группы


def test_new_group_member_is_linked_to_the_existing_defect(web):
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    first = created(web, pid, url)
    assert [t["hub_id"] for t in json.loads(first["targets_json"])] == ["510001"]
    sibling = f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510005')['id']}"
    # другой текст решения – отдельный дефект, как раньше
    save_sast(web, pid, "510005", "true_positive", "", REASON, "Другая рекомендация.")
    card = web.client.get(sibling).text
    assert 'id="hub-defect-button"' in card and 'id="hub-defect-link-button"' not in card
    # тот же текст – «Привязать к дефекту №555 (ID1)» вместо второй заготовки
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    card = web.client.get(sibling).text
    assert 'id="hub-defect-link-button"' in card and "Привязать к дефекту №555 (ID1)" in card
    assert 'id="hub-defect-button"' not in card and 'id="hub-defect-link-left-out"' not in card
    assert re.search(r'id="hub-defect-link-targets">[^<]*\(1\): <a class="mono" href="[^"]+">510005</a>', card)
    fields = link_fields(card)
    assert fields["defect"] == str(first["id"]) and fields["targets"] == "510005"
    # вторая заготовка по той же группе – отказ с подсказкой
    r = web.client.post(f"{sibling}/hub-defect", headers=AS_JSON,
                        data={"review_revision": fields["review_revision"], "text_hash": fields["text_hash"]})
    assert r.status_code == 400 and "Привязать к дефекту" in r.json()["detail"], r.text
    # другой дефект в форме (устаревшая карточка) – отказ, ничего не ставится
    r = web.client.post(f"{sibling}/hub-defect-link", headers=AS_JSON, data={**fields, "defect": "999"})
    assert r.status_code == 400 and "Дефект группы изменился" in r.json()["detail"]
    r = web.client.post(f"{sibling}/hub-defect-link", headers=AS_JSON, data=fields)
    assert r.status_code == 200, r.text
    answer = r.json()
    assert answer["done"] is False and "№555 (ID1)" in answer["message"]
    row = db.hub_defect(answer["defect_id"])
    assert row["state"] == "linking" and row["hub_defect_id"] == "555" and row["number"] == 1 and row["kind"] == "SAST"
    assert row["summary"] == first["summary"] and row["command_text"] == first["command_text"]
    assert row["hub_link"] == first["hub_link"] and row["blank_op_id"] is None and row["create_op_id"] is None
    assert [t["hub_id"] for t in json.loads(row["targets_json"])] == ["510005"]
    assert db.hub_defect_bound(pid, "510005")["id"] == row["id"]
    link = hub_job(web, body={})
    assert link["purpose"] == "defect_link" and link["method"] == "POST" and link["path"] == "/defects/555/link"
    assert link["body"] == {"defectId": 555, "issueIds": [510005], "issueType": "SAST", "groupId": None}
    assert db.get_review(pid, "510005")["entered_hub"] == 0, "привязка без чтения ничего не завершает"
    read = hub_job(web, body={"id": 555, "linkedIssues": [{"id": 510001, "type": "SAST"}, {"id": 510005, "type": "SAST"}]})
    assert read["purpose"] == "defect_read" and read["path"] == "/defects/555"
    no_job(web)
    row = db.hub_defect(row["id"])
    assert row["state"] == "done" and hub_defects.VERIFY_NOTE_DONE in row["error"]
    assert db.get_review(pid, "510005")["entered_hub"] == 1
    assert db.defect_number(pid, "sast:510005") == db.defect_number(pid, "sast:510001") == 1
    assert len([o for o in db.hub_ops_list() if o["purpose"] in ("defect_blank", "defect_create")]) == 2, \
        "второй дефект не создавался"
    card = web.client.get(sibling).text
    assert 'id="hub-defect-done"' in card and "Находки привязаны к дефекту в Hub" in card and "№555" in card
    assert 'id="hub-defect-link-button"' not in card
    page = web.client.get(f"/projects/{pid}/defects").text
    assert page.count('data-state="done"') == 2


def test_rejected_link_frees_the_new_member(web):
    """Hub определённо отказал в привязке (4xx): в Hub ничего не изменилось – строка «не принят», находка свободна,
    карточка снова предлагает привязку."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    created(web, pid, url)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    sibling = f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510005')['id']}"
    r = web.client.post(f"{sibling}/hub-defect-link", headers=AS_JSON, data=link_fields(web.client.get(sibling).text))
    assert r.status_code == 200, r.text
    hub_job(web, status=400, body={"errorMessage": "Bad Request"})
    row = db.hub_defect(r.json()["defect_id"])
    assert row["state"] == "failed" and "отклонена" in row["error"]
    assert db.hub_defect_bound(pid, "510005") is None
    no_job(web)
    assert 'id="hub-defect-link-button"' in web.client.get(sibling).text


# ============================================================================ п. 6: «Проверить в Hub»


def test_recheck_404_is_only_a_note(web):
    """Снятие привязки по 404 вырезано из сборки (бэклог 39): «Проверить в Hub» – только сверка, строка «создан»,
    находки остаются привязанными, итог – пояснением; повторная доставка ничего не меняет."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = created(web, pid, url)
    # кнопки «Проверить в Hub» с dev33 нет (у дефекта – Push и Pull); маршрут остаётся и проверяется напрямую
    assert 'id="hub-defect-recheck"' not in web.client.get(url).text
    assert f'id="hub-defect-recheck-{row["id"]}"' not in web.client.get(f"/projects/{pid}/defects").text
    r = recheck(web, pid, row["id"])
    assert r.status_code == 200 and r.json()["done"] is False, r.text
    assert recheck(web, pid, row["id"]).status_code == 409, "вторая проверка, пока идёт первая"
    state = web.client.get(r.json()["status_url"]).json()
    assert state["done"] is False and "Проверяю в Hub" in state["text"]["hub-defect-status"]
    job = hub_job(web, status=404, body={"errorMessage": "Not Found"})
    assert job["purpose"] == "defect_read" and job["method"] == "GET" and job["path"] == "/defects/555"
    fresh = db.hub_defect(row["id"])
    assert fresh["state"] == "done" and fresh["verify_op_id"] is None
    assert hub_defects.recheck_note(fresh) == hub_defects.RECHECK_404  # итог хранится, но не выводится (dev33)
    assert (fresh["targets_json"], fresh["number_keys_json"]) == (row["targets_json"], row["number_keys_json"])
    assert db.hub_defect_bound(pid, "510001")["id"] == row["id"], "находка остаётся привязанной"
    assert db.get_review(pid, "510001")["entered_hub"] == 1
    hub_defects.after_op(db, db.hub_op(job["op_id"]))  # повторная доставка
    assert db.hub_defect(row["id"]) == fresh
    card = web.client.get(url).text
    assert hub_defects.RECHECK_404 not in card and 'id="hub-defect-form"' not in card and 'id="hub-defect-recheck"' not in card
    assert hub_defects.RECHECK_404 not in web.client.get(f"/projects/{pid}/defects").text
    r = blank(web, url, {"review_revision": "1", "text_hash": "x"})
    assert r.status_code == 400 and "уже создан" in r.json()["detail"]


def test_create_key_is_per_defect_row(web):
    """Ключ операции «Создать» – со строкой дефекта (key_extra): повтор той же строки отклоняется."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, body={"id": 555})
    assert create(web, pid, row["id"]).status_code == 409
    op = db.hub_op(db.hub_defect(row["id"])["create_op_id"])
    assert op["state"] == "done"
    with pytest.raises(ValueError, match="уже выполнена"):
        db.hub_enqueue(purpose="defect_create", request=json.loads(op["request_json"]), hub_url=HUB, app_id=7,
                       project_id=pid, targets=json.loads(op["targets_json"]), text=row["summary"],
                       key_extra=f"defect-row:{row['id']}")


def test_missing_target_in_the_creation_chain_is_not_a_release(web):
    """Уточнение п. 6 (ревью): цели нет в чтении незавершённой цепочки – это шаг привязки ADR-0120, а не
    освобождение; «Проверить в Hub» – только у подтверждённого дефекта."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, body={"id": 556})
    hub_job(web, body={"id": 556, "linkedIssues": []})  # первое чтение без находки – привязка, не освобождение
    row = db.hub_defect(row["id"])
    assert row["state"] == "linking" and db.hub_defect_bound(pid, "510001")["id"] == row["id"]
    assert recheck(web, pid, row["id"]).status_code == 409
    hub_job(web, body={})  # привязка
    hub_job(web, body={"id": 556, "linkedIssues": []})  # второе чтение – всё ещё без находки
    row = db.hub_defect(row["id"])
    assert row["state"] == "mismatch" and [t["hub_id"] for t in json.loads(row["targets_json"])] == ["510001"]
    assert db.hub_defect_bound(pid, "510001")["id"] == row["id"], "привязка неполная – находка не освобождена"
    card = web.client.get(url).text
    assert "Дефект создан в Hub: " in card and "Привязка к дефекту в Hub неполная" not in card
    assert recheck(web, pid, row["id"]).status_code == 409
    no_job(web)


def test_recheck_never_frees_by_linked_issues(web):
    """Правка 1 ревью: linkedIssues в Hub – находки со статусом Open (docs/hub-write-plan.md), отсутствие находки
    отвязку не доказывает – только пояснение, цели и защита остаются; ответ без состава – «проверка не выполнена»."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    row = created(web, pid, url, defect_id=600, links=(510001, 510005))
    targets, keys, left = row["targets_json"], row["number_keys_json"], row["left_out_json"]
    answers = [({"id": 600, "linkedIssues": [{"id": 510001, "type": "SAST"}]},
                hub_defects.RECHECK_MISSING.format(ids="510005")),
               ({"id": 600}, hub_defects.RECHECK_NO_LIST), ({"id": 600, "linkedIssues": None}, hub_defects.RECHECK_NO_LIST)]
    for body, note in answers:
        assert recheck(web, pid, row["id"]).status_code == 200
        hub_job(web, body=body)
        fresh = db.hub_defect(row["id"])
        assert fresh["state"] == "done" and fresh["verify_op_id"] is None
        assert (fresh["targets_json"], fresh["number_keys_json"], fresh["left_out_json"]) == (targets, keys, left)
        assert db.hub_defect_bound(pid, "510005")["id"] == row["id"], "защита остаётся"
        assert hub_defects.recheck_note(fresh) == note
    sibling = f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510005')['id']}"
    card = web.client.get(sibling).text
    assert 'id="hub-defect-link-button"' not in card and 'id="unenter-defect-row"' in card


def test_recheck_failure_all_linked_and_stale_handler(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    rid = created(web, pid, url)["id"]
    assert recheck(web, pid, rid).status_code == 200
    first = db.hub_defect(rid)["verify_op_id"]
    hub_job(web, status=503, body={"errorMessage": "Service Unavailable"})
    row = db.hub_defect(rid)
    assert row["state"] == "done" and row["verify_op_id"] is None and "не удалась" in hub_defects.recheck_note(row)
    assert recheck(web, pid, rid).status_code == 200
    second = db.hub_defect(rid)["verify_op_id"]
    assert second != first
    hub_defects.after_op(db, db.hub_op(first))  # устаревший обработчик – прежнее чтение
    assert db.hub_defect(rid)["verify_op_id"] == second
    hub_job(web, body={"id": 555, "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    row = db.hub_defect(rid)
    assert row["state"] == "done" and hub_defects.recheck_note(row) == hub_defects.RECHECK_OK
    view = hub_defects.view(row)
    assert view["tone"] == "ok" and hub_defects.RECHECK_OK not in view["text"]  # итог не выводится (dev33)
    assert [t["hub_id"] for t in json.loads(row["targets_json"])] == ["510001"]
    hub_defects.after_op(db, db.hub_op(second))  # повторная доставка
    assert db.hub_defect(rid) == row
    # истёкшая аренда исполнителя во время проверки – показ карточки заканчивает её пояснением
    assert recheck(web, pid, rid).status_code == 200
    job = web.client.get("/api/hub/jobs", params={"worker_id": "w1", "hub_url": "https://hub.example.org", "wait": 0},
                         headers=worker_headers(web)).json()["job"]
    assert job["purpose"] == "defect_read"
    db.hub_expire_leases(now="2099-01-01T00:00:00+00:00")
    web.client.get(url)
    row = db.hub_defect(rid)
    assert row["state"] == "done" and row["verify_op_id"] is None and "не удалась" in hub_defects.recheck_note(row)
    # проверка – только у созданного дефекта
    db.hub_defect_update(rid, state="mismatch")
    assert recheck(web, pid, rid).status_code == 409


# ============================================================================ правки по ревью (10 находок)


def test_op_key_extra_separates_defect_rows():
    """Правка 4: ключ операции записи цепочки дефекта – со строкой дефекта; без key_extra ключ прежний."""
    from app import hub_ops
    base = dict(hub_url=HUB, app_id=7, purpose="defect_create", targets=[{"issue_type": "SAST", "issue_id": 1}],
                text="t", request={"method": "POST", "path": "/defects", "body": {"a": 1}})
    assert hub_ops.op_key(**base) == hub_ops.op_key(**base, key_extra="")
    assert hub_ops.op_key(**base, key_extra="defect-row:1") != hub_ops.op_key(**base, key_extra="defect-row:2")
    assert hub_ops.op_key(**base, key_extra="defect-row:1") != hub_ops.op_key(**base)


def test_link_compares_with_the_defect_text_not_the_neighbours_current_decision(web):
    """Правка 2: готовый дефект для привязки – по тексту команды строки дефекта; решение соседа, изменённое после
    создания дефекта, не в счёт; транзакция привязки проверяет, что текст строки тот же."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    first = created(web, pid, url)
    save_sast(web, pid, "510001", "true_positive", "", REASON + " Уточнено.", FIX, defect_confirm="1")
    sibling = f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510005')['id']}"
    # текст как у текущего решения соседа, но не как у дефекта – отдельный дефект, не привязка
    save_sast(web, pid, "510005", "true_positive", "", REASON + " Уточнено.", FIX)
    card = web.client.get(sibling).text
    assert 'id="hub-defect-link-button"' not in card and 'id="hub-defect-button"' in card
    # текст как у дефекта – привязка, хотя решение соседа уже другое
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    card = web.client.get(sibling).text
    assert "Привязать к дефекту №555 (ID1)" in card
    with pytest.raises(ValueError, match="изменился"):
        db.hub_defect_link_start(pid, first["id"], "555", item={}, body_hash="0" * 32, kind="SAST", number=1,
                                 summary="x", anchor_hub_id="510005", targets=[], number_keys=[],
                                 command_text=first["command_text"], hub_url=HUB, app_id=7)
    r = web.client.post(f"{sibling}/hub-defect-link", headers=AS_JSON, data=link_fields(card))
    assert r.status_code == 200, r.text
    assert db.hub_defect(r.json()["defect_id"])["command_text"] == first["command_text"]


def test_second_defect_of_the_group_is_refused_in_the_transaction(web):
    """Запрет второго дефекта по группе – в транзакции, сообщение по состоянию дефекта соседа: «создан» – «Создать»
    соседа с открытым предпросмотром отклоняется («привяжите»); «создаётся» – заготовка отклоняется («дождитесь
    итога»); «результат неизвестен» – («сверьте дефект … в карточке находки …»)."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    sibling = card_of(web, pid, "510005")
    first = to_preview(web, pid, url)
    # пока у первой предпросмотр, соседу – своя заготовка (первая не привязана)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    second = to_preview(web, pid, sibling, service=False)
    assert [t["hub_id"] for t in json.loads(second["targets_json"])] == ["510005"]
    assert create(web, pid, first["id"]).status_code == 200
    hub_job(web, body={"id": 555})
    hub_job(web, body={"id": 555, "linkedIssues": linked(510001)})
    assert db.hub_defect(first["id"])["state"] == "done"
    r = create(web, pid, second["id"])
    assert r.status_code == 400 and "привяжите к дефекту №555 (ID1)" in r.json()["detail"], r.text
    assert db.hub_defect(second["id"])["state"] == "preview"
    assert len([o for o in db.hub_ops_list() if o["purpose"] == "defect_create"]) == 1, "второй POST не поставлен"
    # «создаётся»: «Создать» ушло, ответа ещё нет
    pid = pair_project(web)
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    sibling = card_of(web, pid, "510005")
    row = to_preview(web, pid, url, service=False)
    assert create(web, pid, row["id"]).status_code == 200
    assert db.hub_defect(row["id"])["state"] == "creating"
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    r = blank(web, sibling)
    assert r.status_code == 400 and "дождитесь итога дефекта" in r.json()["detail"], r.text
    # «результат неизвестен»
    hub_job(web, status=0, error="timeout")
    assert db.hub_defect(row["id"])["state"] == "unknown"
    r = blank(web, sibling)
    assert r.status_code == 400 and "сверьте дефект" in r.json()["detail"], r.text
    assert "в карточке находки 510001" in r.json()["detail"]
    assert "«Дефект для Hub»" in r.json()["detail"] and "«Отметить: дефект создан в Hub»" in r.json()["detail"]
    assert len([o for o in db.hub_ops_list(project_id=pid) if o["purpose"] == "defect_blank"]) == 1
    no_job(web)


def test_status_hint_covers_the_whole_group(web):
    """Правка 8, с dev32: свободная находка B, её сосед A с тем же решением привязан к дефекту – панель B обычная,
    статус уходит только по B, сосед в дефекте назван в ответе как не отправляемый."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    created(web, pid, url)
    save_sast(web, pid, "510001", "false_positive", "", FP_TEXT, "", defect_confirm="1")
    save_sast(web, pid, "510005", "false_positive", "", FP_TEXT, "")
    assert db.hub_defect_bound(pid, "510005") is None
    card = web.client.get(f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510005')['id']}").text
    assert 'id="hub-send-form"' in card and 'id="hub-send-in-defect"' not in card and 'id="hub-send-defect-row"' not in card
    r = send(web, pid, "510005")
    assert r.status_code == 200, r.text
    assert "Входит в дефект и не отправляется (статус через дефект): 510001." in r.json()["message"]
    op = [o for o in db.hub_ops_list() if o["purpose"] == "status"][0]
    assert [t["hub_id"] for t in json.loads(op["targets_json"])] == ["510005"]
    # транзакция постановки: исключённый сосед всё ещё в дефекте – иначе отказ «обновите карточку» (ревью dev32)
    check = hub_status_routes.in_defect_check(pid, ["510001"])
    with pytest.raises(RuntimeError, match="откат"):  # транзакция откатывается: строки дефекта остаются
        with db._tx() as c:
            check(c)
            c.execute("DELETE FROM hub_defects")
            with pytest.raises(hub_status_routes.StaleTarget, match="510001 вышла из дефекта"):
                check(c)
            raise RuntimeError("откат")
    assert db.hub_defect_bound(pid, "510001") is not None


def triple_project(web) -> int:
    """Три находки SAST той же строки и категории с одинаковым кодом (одна группа)."""
    pid = create_project(web.client)
    rows = [SAST_ROWS[0]] + [dict(SAST_ROWS[0], **{"Issue id": hub_id}) for hub_id in ("510005", "510006")]
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "triple.xlsx", sast=rows, practices="auto",
                                                  severities="auto")).status_code == 303
    r = web.client.post(f"/projects/{pid}/repos", data={"repos_dir": "team"}, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303, r.text
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    hub_settings(web, pid)
    return pid


def card_of(web, pid: int, hub_id: str) -> str:
    return f"/projects/{pid}/findings/{web.app.state.db.get_finding_by_hub_id(pid, hub_id)['id']}"


def start_link(web, pid: int, hub_id: str) -> int:
    """«Привязать к дефекту» из карточки находки hub_id; номер строки привязки."""
    url = card_of(web, pid, hub_id)
    r = web.client.post(f"{url}/hub-defect-link", headers=AS_JSON, data=link_fields(web.client.get(url).text))
    assert r.status_code == 200, r.text
    return int(r.json()["defect_id"])


def linked(*ids: int) -> list[dict]:
    return [{"id": i, "type": "SAST"} for i in ids]


def test_link_row_read_without_composition_is_unknown(web):
    """B1: у строки привязки ответ чтения без состава (linkedIssues null или нет) – «результат неизвестен» и
    «Сверить», а не «нет ни одной находки»; у создания неразобранный состав также не запускает привязку."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    created(web, pid, url)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    link_id = start_link(web, pid, "510005")
    hub_job(web, body={})  # привязка выполнена
    hub_job(web, body={"id": 555, "linkedIssues": None})
    row = db.hub_defect(link_id)
    assert row["state"] == "unknown" and "не разобран" in row["error"] and hub_defects.view(row)["verify"]
    assert db.hub_defect_bound(pid, "510005")["id"] == link_id
    assert verify(web, pid, link_id).status_code == 200
    hub_job(web, body={"id": 555})  # и без ключа состава – снова «неизвестен»
    assert db.hub_defect(link_id)["state"] == "unknown"
    assert verify(web, pid, link_id).status_code == 200
    hub_job(web, body={"id": 555, "linkedIssues": linked(510001, 510005)})
    assert db.hub_defect(link_id)["state"] == "done" and db.get_review(pid, "510005")["entered_hub"] == 1
    # Неразобранный состав не даёт основания менять связи.
    pid = pair_project(web)
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    row = to_preview(web, pid, url, service=False)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, body={"id": 557})
    hub_job(web, body={"id": 557, "linkedIssues": None})
    assert db.hub_defect(row["id"])["state"] == "unconfirmed"
    assert not [o for o in db.hub_ops_list(project_id=pid) if o["purpose"] == "defect_link"]


def test_link_done_without_the_target_is_mismatch_and_keeps_the_binding(web):
    """B2: привязка выполнена (2xx), а находки в составе нет – «привязка неполная», находка остаётся привязанной
    (в linkedIssues только Open – отсутствие отвязку не доказывает), «Привязать» ей не предлагается."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    created(web, pid, url)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    link_id = start_link(web, pid, "510005")
    hub_job(web, body={})
    hub_job(web, body={"id": 555, "linkedIssues": linked(510001)})
    row = db.hub_defect(link_id)
    assert row["state"] == "mismatch" and "510005" in row["error"]
    assert db.hub_op(row["link_op_id"])["state"] == "done"
    assert db.hub_defect_bound(pid, "510005")["id"] == link_id, "находка остаётся привязанной"
    assert db.get_review(pid, "510005")["entered_hub"] == 0
    card = web.client.get(card_of(web, pid, "510005")).text
    assert 'id="hub-defect-link-button"' not in card and 'id="hub-defect-done"' in card
    assert "Привязка к дефекту в Hub неполная: " in card and "Находки привязаны к дефекту в Hub" not in card
    assert db.hub_ops_list(states=("queued", "taken", "unknown")) == []


def test_unknown_link_without_the_target_fails_and_a_crash_is_finished_on_view(web, monkeypatch):
    """B2: привязка с неизвестным исходом, «Сверить» – находки нет в составе: «не принят» одной записью итога
    (confirm_op_id, effects_done=0), неизвестная операция привязки закрывается как невыполненная в последствиях; сбой
    между записью итога и закрытием операции доводит показ карточки. Затем явная «Привязать» – новая строка, уходит."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    created(web, pid, url)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    link_id = start_link(web, pid, "510005")
    hub_job(web, status=0, error="timeout")
    assert db.hub_defect(link_id)["state"] == "unknown"
    assert verify(web, pid, link_id).status_code == 200
    original = hub_defects._apply_effects

    def crash(*args, **kwargs):
        raise RuntimeError("сбой после записи итога")

    monkeypatch.setattr(hub_defects, "_apply_effects", crash)
    job = web.client.get("/api/hub/jobs", params={"worker_id": "w1", "hub_url": HUB, "wait": 0},
                         headers=worker_headers(web)).json()["job"]
    assert job["purpose"] == "defect_read"
    try:
        status = web.client.post(f"/api/hub/jobs/{job['attempt_id']}/result", headers=worker_headers(web),
                                 content=json.dumps({"lease_token": job["lease_token"], "worker_id": "w1", "status": 200,
                                                     "body_text": json.dumps({"id": 555, "appId": 7, "summary": db.hub_defect(link_id)["summary"],
                                                         "description": hub_defects.description_html(db.hub_defect(link_id)["command_text"], HUB_DESCRIPTION),
                                                         "linkedIssues": linked(510001)}),
                                                     "error": ""})).status_code
    except RuntimeError:
        status = 500
    assert status == 500
    monkeypatch.setattr(hub_defects, "_apply_effects", original)
    row = db.hub_defect(link_id)
    assert row["state"] == "failed" and row["effects_done"] == 0 and row["confirm_op_id"] == row["read_op_id"]
    assert row["error"] == hub_defects.LINK_NOT_DONE.format(defect="555", ids="510005")
    assert db.hub_op(row["link_op_id"])["state"] == "unknown"
    web.client.get(card_of(web, pid, "510005"))  # показ карточки доводит последствия
    row = db.hub_defect(link_id)
    assert row["effects_done"] == 1 and db.hub_op(row["link_op_id"])["state"] == "failed"
    assert db.hub_defect_bound(pid, "510005") is None
    assert db.hub_ops_list(states=("queued", "taken", "unknown")) == []
    second = start_link(web, pid, "510005")
    assert second != link_id
    link = hub_job(web, body={})
    assert link["purpose"] == "defect_link" and link["path"] == "/defects/555/link"


def test_partial_link_is_mismatch_for_the_whole_row(web):
    """B2: из двух новых находок в составе дефекта только одна (привязка с неизвестным исходом, «Сверить») –
    «привязка неполная» для строки целиком, цели не освобождаются."""
    pid = triple_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    created(web, pid, url)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    save_sast(web, pid, "510006", "true_positive", "", REASON, FIX)
    link_id = start_link(web, pid, "510005")
    assert sorted(t["hub_id"] for t in json.loads(db.hub_defect(link_id)["targets_json"])) == ["510005", "510006"]
    hub_job(web, status=0, error="timeout")
    assert verify(web, pid, link_id).status_code == 200
    hub_job(web, body={"id": 555, "linkedIssues": linked(510001, 510005)})
    row = db.hub_defect(link_id)
    assert row["state"] == "mismatch" and "510006" in row["error"]
    assert sorted(t["hub_id"] for t in json.loads(row["targets_json"])) == ["510005", "510006"]
    assert db.hub_defect_bound(pid, "510005")["id"] == link_id and db.hub_defect_bound(pid, "510006")["id"] == link_id
    card = web.client.get(card_of(web, pid, "510006")).text
    assert "Привязка к дефекту в Hub неполная: " in card and "Находки привязаны к дефекту в Hub" not in card


def test_neighbour_in_mismatch_is_offered_for_linking(web):
    """B3: дефект соседа «создан, привязка неполная» (номер в Hub известен) – новой находке группы с тем же текстом
    предлагается «Привязать», привязка проходит; заготовка второго дефекта – отказ «привяжите»."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, body={"id": 556})
    hub_job(web, body={"id": 556, "linkedIssues": []})  # первое чтение без находки – привязка
    hub_job(web, body={})
    hub_job(web, body={"id": 556, "linkedIssues": []})  # и после неё – «привязка неполная»
    assert db.hub_defect(row["id"])["state"] == "mismatch"
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    sibling = card_of(web, pid, "510005")
    card = web.client.get(sibling).text
    assert "Привязать к дефекту №556 (ID1)" in card
    fields = link_fields(card)
    r = web.client.post(f"{sibling}/hub-defect", headers=AS_JSON,
                        data={"review_revision": fields["review_revision"], "text_hash": fields["text_hash"]})
    assert r.status_code == 400 and "привяжите к дефекту №556 (ID1)" in r.json()["detail"], r.text
    r = web.client.post(f"{sibling}/hub-defect-link", headers=AS_JSON, data=fields)
    assert r.status_code == 200, r.text
    link = hub_job(web, body={})
    assert link["path"] == "/defects/556/link" and link["body"]["issueIds"] == [510005]
    hub_job(web, body={"id": 556, "linkedIssues": linked(510005)})
    assert db.hub_defect(r.json()["defect_id"])["state"] == "done"


def test_group_composition_is_read_in_the_transaction(web, monkeypatch):
    """B4: состав соседей группы читается в транзакции: подготовка соседа не видит (здесь – чтение группы до
    транзакции подменено пустым), а он уже в идущем дефекте с тем же текстом – заготовка отклоняется."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200  # «создаётся»
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    sibling = card_of(web, pid, "510005")
    fields = shown(web, sibling)
    monkeypatch.setattr(db, "group_rows", lambda *args, **kwargs: [])
    r = blank(web, sibling, fields)
    assert r.status_code == 400 and "дождитесь итога дефекта" in r.json()["detail"], r.text
    assert len([o for o in db.hub_ops_list(project_id=pid) if o["purpose"] == "defect_blank"]) == 1


def test_link_transaction_checks_body_text_and_group(web):
    """B4, B5: транзакция привязки сверяет отпечаток тела новой находки с текстом команды готового дефекта и то, что
    готовый дефект – дефект группы находки (соседи читаются в транзакции)."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    first = created(web, pid, url)
    with pytest.raises(ValueError, match="изменился"):
        db.hub_defect_link_start(pid, first["id"], "555", item={}, body_hash="0" * 32, kind="SAST", number=1,
                                 summary="x", anchor_hub_id="510005", targets=[], number_keys=[],
                                 command_text=first["command_text"], hub_url=HUB, app_id=7)
    with pytest.raises(hub_status.StatusRefused, match="Состав группы изменился"):
        db.hub_enqueue_many([], check=hub_defect_routes.link_group_check(db, pid, "999999", first["id"]))
    assert db.hub_enqueue_many([], check=hub_defect_routes.link_group_check(db, pid, "510005", first["id"])) == []


# ============================================================================ круг 3 ревью


def test_link_refuses_when_a_neighbour_joined_after_the_card_was_shown(web):
    """A1: форма «Привязать» передаёт показанный состав; сосед с тем же текстом получил «Проверено» в другой вкладке –
    старая форма отклоняется тем же отказом, что устаревшая цель (и без скрипта), ничего не ставится; обновлённая
    карточка показывает обоих, привязка уходит по обоим."""
    pid = triple_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    created(web, pid, url)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    save_sast(web, pid, "510006", "true_positive", "", REASON, FIX)
    db.set_reviewed(pid, "510006", False)
    sibling = card_of(web, pid, "510005")
    card = web.client.get(sibling).text
    assert re.search(r'id="hub-defect-link-left-out">[^<]*<span class="mono">510006</span> – нет отметки «Проверено»',
                     card)
    fields = link_fields(card)
    assert fields["targets"] == "510005"
    db.set_reviewed(pid, "510006", True)  # другая вкладка: тот же текст и «Проверено»
    r = web.client.post(f"{sibling}/hub-defect-link", headers=AS_JSON, data=fields)
    assert r.status_code == 400 and "Состав привязки изменился" in r.json()["detail"], r.text
    page = web.client.post(f"{sibling}/hub-defect-link", headers=ORIGIN, data=fields, follow_redirects=False)
    assert page.status_code == 400 and "Состав привязки изменился" in page.text
    assert not [o for o in db.hub_ops_list(project_id=pid) if o["purpose"] == "defect_link"]
    assert db.hub_defect_bound(pid, "510005") is None and db.hub_defect_bound(pid, "510006") is None
    no_job(web)
    fields = link_fields(web.client.get(sibling).text)
    assert fields["targets"] == "510005,510006"
    r = web.client.post(f"{sibling}/hub-defect-link", headers=AS_JSON, data=fields)
    assert r.status_code == 200, r.text
    assert sorted(hub_job(web, body={})["body"]["issueIds"]) == [510005, 510006]


def test_link_refuses_when_a_shown_neighbour_dropped_out(web):
    """A1, обратный случай: у показанного соседа сняли «Проверено» в другой вкладке – старая форма не привязывает
    молча одну находку, а отклоняется; ничего не ставится."""
    pid = triple_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    created(web, pid, url)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    save_sast(web, pid, "510006", "true_positive", "", REASON, FIX)
    sibling = card_of(web, pid, "510005")
    fields = link_fields(web.client.get(sibling).text)
    assert fields["targets"] == "510005,510006"
    db.set_reviewed(pid, "510006", False)
    r = web.client.post(f"{sibling}/hub-defect-link", headers=AS_JSON, data=fields)
    assert r.status_code == 400 and "Состав привязки изменился" in r.json()["detail"], r.text
    assert not [o for o in db.hub_ops_list(project_id=pid) if o["purpose"] == "defect_link"]
    assert db.hub_defect_bound(pid, "510005") is None
    no_job(web)


def test_defect_of_another_hub_app_does_not_block_the_group(web):
    """B1: дефект группы создан в приложении Hub 7, номер приложения проекта сменили на 8 – «Привязать» не
    предлагается (дефект в другом приложении), карточка показывает «Создать дефект в Hub», запрет второго дефекта по
    группе (транзакция заготовки и «Создать») строку другого приложения не учитывает. Номер ID1 группы держит дефект
    приложения 7 – заготовку отклоняет занятость номера (была до изменения, бэклог 42)."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    first = created(web, pid, url)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    sibling = card_of(web, pid, "510005")
    assert 'id="hub-defect-link-button"' in web.client.get(sibling).text
    db.update_project(pid, hub_app_id=8)
    card = web.client.get(sibling).text
    assert 'id="hub-defect-link-button"' not in card and 'id="hub-defect-button"' in card
    group = hub_defect_routes.group_defect_check
    assert db.hub_enqueue_many([], check=group(db, pid, "510005", first["command_text"], ["510005"], hub_url=HUB,
                                               app_id=8)) == []
    with pytest.raises(hub_defect_routes.DefectRefused, match="привяжите к дефекту №555"):
        db.hub_enqueue_many([], check=group(db, pid, "510005", first["command_text"], ["510005"], hub_url=HUB,
                                            app_id=7))
    r = blank(web, sibling)
    assert r.status_code == 409 and "привяжите" not in r.json()["detail"], r.text
    assert "Номер ID1 уже занят" in r.json()["detail"]  # была до изменения: бэклог 42
    no_job(web)


def test_link_to_a_link_row_takes_group_id_from_the_creation_row(web):
    """B3: готовый дефект для новой находки – строка привязки (находки строки создания нет в выгрузке): groupId
    привязки – из заготовки строки создания, которую строка привязки получила от родителя."""
    pid = triple_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    row = to_preview(web, pid, url, blank_body={**BLANK, "groupId": 42})
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, body={"id": 555})
    hub_job(web, body={"id": 555, "linkedIssues": linked(510001)})
    assert db.hub_defect(row["id"])["state"] == "done"
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    first_link = start_link(web, pid, "510005")
    assert hub_job(web, body={})["body"]["groupId"] == 42
    hub_job(web, body={"id": 555, "linkedIssues": linked(510001, 510005)})
    assert db.hub_defect(first_link)["state"] == "done"
    with db._tx() as c:
        c.execute("UPDATE findings SET missing = 1 WHERE project_id = ? AND hub_id = ?", (pid, "510001"))
    save_sast(web, pid, "510006", "true_positive", "", REASON, FIX)
    card = web.client.get(card_of(web, pid, "510006")).text
    assert link_fields(card)["defect"] == str(first_link), "готовый дефект – строка привязки"
    second_link = start_link(web, pid, "510006")
    link = hub_job(web, body={})
    assert link["body"] == {"defectId": 555, "issueIds": [510006], "issueType": "SAST", "groupId": 42}
    hub_job(web, body={"id": 555, "linkedIssues": linked(510001, 510005, 510006)})
    assert db.hub_defect(second_link)["state"] == "done"


def test_rechecks_of_one_defect_from_two_rows_are_both_queued(web):
    """B4: строка создания и строка привязки одного дефекта №555 – «Проверить в Hub» по обеим ставится (цель чтения –
    строка дефекта, не номер), обе доходят до итога; та же строка дважды – по-прежнему отказ."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    first = created(web, pid, url)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    link_id = start_link(web, pid, "510005")
    hub_job(web, body={})
    hub_job(web, body={"id": 555, "linkedIssues": linked(510001, 510005)})
    assert db.hub_defect(link_id)["state"] == "done"
    assert recheck(web, pid, first["id"]).status_code == 200
    r = recheck(web, pid, link_id)
    assert r.status_code == 200, r.text
    reads = [o for o in db.hub_ops_list(states=("queued",)) if o["purpose"] == "defect_read"]
    assert len(reads) == 2 and {json.loads(o["request_json"])["path"] for o in reads} == {"/defects/555"}
    assert recheck(web, pid, link_id).status_code == 409, "та же строка – вторая проверка, пока идёт первая"
    for _ in range(2):
        hub_job(web, body={"id": 555, "linkedIssues": linked(510001, 510005)})
    assert hub_defects.recheck_note(db.hub_defect(first["id"])) == hub_defects.RECHECK_OK
    assert hub_defects.recheck_note(db.hub_defect(link_id)) == hub_defects.RECHECK_OK
    no_job(web)


def test_verify_candidate_and_recheck_of_one_number_do_not_block_each_other(web):
    """B4: «Проверить в Hub» строки Y (№555) взята исполнителем и ещё без ответа, а сверка строки X (другой проект того
    же Hub и приложения, номер не известен) дошла до кандидата №555 – чтение кандидата ставится, сверка не обрывается;
    обе доходят до итога."""
    pid1, url1 = sast_ready(web)
    db = web.app.state.db
    done = created(web, pid1, url1)
    pid2, url2 = sast_ready(web)
    row = to_preview(web, pid2, url2, service=False)
    assert create(web, pid2, row["id"]).status_code == 200
    hub_job(web, status=0, error="timeout")
    row = db.hub_defect(row["id"])
    assert row["state"] == "unknown" and not row["hub_defect_id"]
    assert recheck(web, pid1, done["id"]).status_code == 200
    taken = web.client.get("/api/hub/jobs", params={"worker_id": "w1", "hub_url": HUB, "wait": 0},
                           headers=worker_headers(web)).json()["job"]
    assert taken["purpose"] == "defect_read" and taken["path"] == "/defects/555"
    assert verify(web, pid2, row["id"]).status_code == 200
    hub_job(web, body={"filteredEntities": [{"id": 555, "summary": row["summary"]}], "totalEntitiesCount": 1})
    assert db.hub_defect(row["id"])["error"] == "сверяю: читаю дефект №555 из Hub…"
    candidate = hub_job(web, body={"id": 555, "summary": row["summary"], "linkedIssues": linked(510001),
                                   "description": hub_defects.description_html(row["command_text"], HUB_DESCRIPTION)})
    assert candidate["path"] == "/defects/555"
    fresh = db.hub_defect(row["id"])
    assert fresh["state"] == "done" and fresh["hub_defect_id"] == "555"
    r = web.client.post(f"/api/hub/jobs/{taken['attempt_id']}/result", headers=worker_headers(web), content=json.dumps(
        {"lease_token": taken["lease_token"], "worker_id": "w1", "status": 200,
         "body_text": json.dumps({"id": 555, "summary": row["summary"],
                                                         "description": row["body_html"],
                                                         "linkedIssues": linked(510001)}), "error": ""}))
    assert r.status_code == 200, r.text
    assert hub_defects.recheck_note(db.hub_defect(done["id"])) == hub_defects.RECHECK_OK
    no_job(web)


# ============================================================================ круг 4 ревью: нечисловой номер, тексты отказа


def non_numeric_pair(web) -> int:
    """Две находки SAST одной группы: 510001 и нечисловой номер «A-1» (выгрузка такой номер допускает)."""
    pid = create_project(web.client)
    second = dict(SAST_ROWS[0], **{"Issue id": "A-1"})
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "pair-a1.xlsx", sast=[SAST_ROWS[0], second],
                                                  practices="auto", severities="auto")).status_code == 303
    r = web.client.post(f"/projects/{pid}/repos", data={"repos_dir": "team"}, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303, r.text
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    hub_settings(web, pid)
    return pid


def test_card_with_non_numeric_hub_id_in_the_group_opens(web):
    """Круг 4 (второй ревьюер, C1): подсказка статуса собирает группу отправки при показе карточки – нечисловой номер
    у находки или у соседа не роняет карточку (было 500), подсказка – по самой находке."""
    pid = non_numeric_pair(web)
    url_a1, _ = save_sast(web, pid, "A-1", "false_positive", "", FP_TEXT)
    url_num, _ = save_sast(web, pid, "510001", "false_positive", "", FP_TEXT)
    assert web.client.get(url_a1).status_code == 200
    assert web.client.get(url_num).status_code == 200


def test_link_offer_with_non_numeric_member_does_not_break_the_card(web):
    """Круг 4 (C1): у группы готовый дефект, новая находка «A-1» с тем же текстом – карточка открывается, предложения
    «Привязать» нет (привязка по нечисловому номеру невозможна)."""
    pid = non_numeric_pair(web)
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    created(web, pid, url)
    url_a1, _ = save_sast(web, pid, "A-1", "true_positive", "", REASON, FIX)
    card = web.client.get(url_a1)
    assert card.status_code == 200
    assert 'id="hub-defect-link-form"' not in card.text


def test_create_from_preview_after_neighbour_defect_tells_to_cancel_the_preview(web):
    """Круг 4 (C3, C2): у A открыт предпросмотр, сосед B с тем же текстом получил свой дефект – «Создать» у A
    отклоняется с советом «Отменить предпросмотр», затем «Привязать», и с ручным путём на случай удалённого дефекта;
    предпросмотр A не тронут, POST создания не поставлен."""
    pid = pair_project(web)
    db = web.app.state.db
    url_a, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    row_a = to_preview(web, pid, url_a)
    url_b, _ = save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    created(web, pid, url_b, links=(510005,), service=False)  # справочник прочитан предпросмотром A
    creates = len([o for o in db.hub_ops_list() if o["purpose"] == "defect_create"])
    r = create(web, pid, row_a["id"])
    assert r.status_code == 400, r.text
    text = r.text
    assert "Отменить предпросмотр" in text and "Привязать к дефекту" in text and "Дефект для Hub" in text
    assert db.hub_defect(row_a["id"])["state"] == "preview"
    assert len([o for o in db.hub_ops_list() if o["purpose"] == "defect_create"]) == creates


def test_rejected_link_names_the_manual_path(web):
    """Круг 4 (C2): отказ Hub на привязку новой находки (например, дефект удалён) – строка «не принят», в пояснении
    ручной путь; находка снова может привязаться."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    created(web, pid, url)
    url_b, _ = save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    link_id = start_link(web, pid, "510005")
    hub_job(web, status=404, body={"errorMessage": "defect not found"})
    row = db.hub_defect(link_id)
    assert row["state"] == "failed", row
    assert "Дефект для Hub" in row["error"] and "Отметить: дефект создан в Hub" in row["error"]
    assert 'id="hub-defect-link-form"' in web.client.get(url_b).text


def test_link_closed_by_reading_is_not_called_a_hub_refusal(web):
    """Круг 5 (D2): привязка с неизвестным исходом, «Сверить», в составе новой находки нет – строка «не принят» по
    итогу чтения; карточка не пишет «Hub не принял» (Hub не отказывал), подсказка ручного пути называет вкладку
    «Дефекты» (D1)."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    created(web, pid, url)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    link_id = start_link(web, pid, "510005")
    hub_job(web, status=0, error="timeout")
    assert db.hub_defect(link_id)["state"] == "unknown"
    assert verify(web, pid, link_id).status_code == 200
    hub_job(web, body={"id": 555, "linkedIssues": linked(510001)})
    row = db.hub_defect(link_id)
    assert row["state"] == "failed" and row.get("confirm_op_id"), row
    text = hub_defects.view(row)["text"]
    assert not text.startswith("Hub не принял"), text
    card = web.client.get(card_of(web, pid, "510005")).text
    assert "Hub не принял" not in card
