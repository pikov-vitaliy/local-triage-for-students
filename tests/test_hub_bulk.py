"""«Отправить выбранные в Hub» (ADR-0119): предпросмотр состава (кто уйдёт, кто исключён и почему), постановка одной
операции status по нескольким находкам SAST с общим комментарием и сроком, отметки по ответу Hub с признаком «общий
комментарий», отказы при изменении состава между предпросмотром и постановкой. Данные и адреса выдуманы."""

from __future__ import annotations

import json
import re
from datetime import date

import pytest

from app import hub_ops
from app.db import text_hash
from test_hub_status_routes import AS_JSON, HUB, ORIGIN, decide, fid, project, run_worker, sast, sca  # noqa: F401
from test_web import web  # noqa: F401


@pytest.fixture(autouse=True)
def fixed_today_bulk(monkeypatch):
    """Срок в этих тестах – 2027-01-26 от «сегодня» 28.10.2026: у hub_bulk своя ссылка today (круг 3 Codex)."""
    from app.routes import hub_bulk
    monkeypatch.setattr(hub_bulk, "today", lambda: date(2026, 10, 28))

COMMON = "Имя таблицы задано константой в конфигурации, внешний ввод в эти запросы не попадает."
AS_PAGE = {**ORIGIN, "Accept": "text/html,application/xhtml+xml"}


def preview(web, pid: int, *hub_ids: str) -> str:
    query = "&".join(f"hub_id={h}" for h in hub_ids)
    r = web.client.get(f"/projects/{pid}/hub/send-selected?{query}")
    assert r.status_code == 200, r.text[:300]
    return r.text


def targets_of(html: str) -> list[str]:
    return re.findall(r'name="target" value="([^"]+)"', html)


def target_fields_of(html: str) -> dict:
    """Назначение из формы предпросмотра: основа адреса Hub и номер приложения, по которым он собран (KIMI-12)."""
    out = {}
    for name, field_id in (("hub_base", "bulk-hub-base"), ("hub_app_id", "bulk-app-id")):
        found = re.search(rf'id="{field_id}" value="([^"]*)"', html)
        out[name] = found.group(1) if found else ""
    return out


def send(web, pid: int, targets: list[str], comment: str = COMMON, expires: str = "2027-01-26", headers=None,
         shown: dict | None = None):
    """Отправка формы предпросмотра; shown – назначение из её разметки (target_fields_of), по умолчанию – из
    предпросмотра этих находок, открытого сейчас."""
    if shown is None:
        ids = [t.split("|", 1)[0] for t in targets]
        shown = target_fields_of(preview(web, pid, *ids)) if ids else {}
    data = {"target": list(targets), "comment": comment, "expires": expires,  # httpx: список значений – повтор поля
            **shown}
    return web.client.post(f"/projects/{pid}/hub/send-selected", data=data, headers=headers or AS_PAGE,
                           follow_redirects=False)


def test_preview_lists_ready_and_excluded_with_reasons(web):
    pid = project(web, [sast("101", 2), sast("102", 5), sast("103", 7), sast("104", 9), sast("105", 11), sca("201")])
    decide(web, pid, "101")
    decide(web, pid, "105", comment="Другое обоснование.")
    web.app.state.db.save_review(pid, "102", decision="agree", final_verdict="false_positive", final_comment="x",
                                 reviewed=False)
    decide(web, pid, "104", verdict="true_positive", decision="disagree")
    html = preview(web, pid, "101", "102", "103", "104", "105", "201", "999", "101")
    ready = re.findall(r'<tr data-hub-id="([^"]+)"', html)
    assert ready == ["101", "105"], ready
    excluded = re.search(r'<ul id="bulk-excluded">(.*?)</ul>', html, re.S).group(1)
    assert "102</span> – нет отметки «Проверено»" in excluded
    assert "103</span> – решения нет" in excluded
    assert "104</span> – решение – не «Ложное срабатывание»" in excluded
    assert "201</span> – не находка SAST" in excluded
    assert "999</span> – нет в текущей выгрузке" in excluded
    assert len(targets_of(html)) == 2 and 'id="bulk-comment"' in html
    assert ">Имя таблицы задано константой, внешний ввод в запрос не попадает.</textarea>" in html  # текст первой


def test_selected_findings_go_in_one_request_and_get_bulk_marks(web):
    pid = project(web, [sast("101", 2), sast("105", 11)])
    decide(web, pid, "101")
    decide(web, pid, "105", comment="Другое обоснование.")
    html = preview(web, pid, "101", "105")
    r = send(web, pid, targets_of(html))
    assert r.status_code == 303, r.text[:300]
    location = r.headers["location"]
    assert "hub_id=101&hub_id=105&op=" in location and "ok=hub_bulk_queued" in location
    page = web.client.get(location).text
    assert "Поставлено в очередь" in page and 'id="bulk-form"' not in page and "В очереди" in page
    job = run_worker(web)
    assert job["path"] == "/issue/status/change"
    assert sorted(i["issueId"] for i in job["body"]["issues"]) == [101, 105]
    assert job["body"]["reason"] == COMMON and job["body"]["status"] == "False Positive"
    assert job["body"]["expiredAt"] == "2027-01-26T00:00:00Z"
    db = web.app.state.db
    for hub_id, saved in (("101", "Имя таблицы задано константой, внешний ввод в запрос не попадает."),
                          ("105", "Другое обоснование.")):
        review = db.get_review(pid, hub_id)
        assert review["entered_hub"] == 1 and review["entered_text_hash"] == text_hash(COMMON)
        assert json.loads(review["entered_parts"])["bulk"] == 1
        assert review["final_comment"] == saved, "сохранённое решение не менялось"
    page = web.client.get(location).text
    assert "Записано в Hub" in page and "находок: 2" in page
    card = web.client.get(f"/projects/{pid}/findings/{fid(web, pid, '105')}").text
    assert 'id="entered-bulk"' in card and 'id="entered-changed"' not in card
    # повторно выбранные – уже в Hub: исключены с причиной
    again = preview(web, pid, "101", "105")
    assert "статус уже внесён в Hub" in again and not targets_of(again)


def test_one_selected_finding_uses_update(web):
    pid = project(web, [sast("101", 2)])
    decide(web, pid, "101")
    r = send(web, pid, targets_of(preview(web, pid, "101")))
    assert r.status_code == 303
    assert run_worker(web)["path"] == "/issue/status/update"


def test_excluded_or_changed_between_preview_and_post_is_refused(web):
    pid = project(web, [sast("101", 2), sast("102", 5)])
    decide(web, pid, "101")
    decide(web, pid, "102")
    db = web.app.state.db
    shown = targets_of(preview(web, pid, "101", "102"))
    # сосед потерял «Проверено» после предпросмотра
    db.save_review(pid, "102", decision="agree", final_verdict="false_positive", final_comment="x", reviewed=False)
    r = send(web, pid, shown)
    assert r.status_code == 400 and "Состав изменился" in r.text and "102 (нет отметки «Проверено»)" in r.text
    assert db.hub_ops_list() == []
    # редакция решения другой находки изменилась
    decide(web, pid, "102")
    decide(web, pid, "101", comment="Новая редакция.")
    r = send(web, pid, shown)
    assert r.status_code == 400 and "Решение или данные находки 101 изменились" in r.text
    assert db.hub_ops_list() == []
    # подделанный список целей: находка, которой не было в предпросмотре
    r = send(web, pid, targets_of(preview(web, pid, "101")) + ["102|0|zzz"])
    assert r.status_code == 400 and "102" in r.text
    # пустой комментарий и срок
    fresh = targets_of(preview(web, pid, "101", "102"))
    assert send(web, pid, fresh, comment="  ").status_code == 400
    assert send(web, pid, fresh, expires="").status_code == 400
    assert db.hub_ops_list() == []


def test_blocker_and_json_answer(web):
    pid = project(web, [sast("101", 2)], hub_app_id=None)
    decide(web, pid, "101")
    html = preview(web, pid, "101")
    assert 'id="bulk-blocker"' in html and "Номер приложения" in html and not targets_of(html)
    assert send(web, pid, ["101|1|x"]).status_code == 400
    web.app.state.db.update_project(pid, hub_app_id=7)
    answer = send(web, pid, targets_of(preview(web, pid, "101")), headers=AS_JSON)
    assert answer.status_code == 200 and answer.json()["ok"] and "находок – 1" in answer.json()["message"]
    assert "В очереди" in answer.json()["text"]["hub-send-status"]


def test_list_page_offers_send_selected(web):
    pid = project(web, [sast("101", 2)])
    html = web.client.get(f"/projects/{pid}/findings?kind=SAST").text
    button = re.search(r'<button[^>]*id="send-selected"[^>]*>', html).group(0)
    assert f'formaction="/projects/{pid}/hub/send-selected"' in button and 'formmethod="get"' in button
    empty = web.client.get(f"/projects/{pid}/hub/send-selected").text
    assert 'id="bulk-empty"' in empty


def test_open_operation_excludes_the_finding_instead_of_blocking_the_batch(web):
    """Круг 1 Codex: у A незакрытая операция статуса – A исключается с её номером, B уходит."""
    pid = project(web, [sast("101", 2), sast("105", 11)])
    decide(web, pid, "101")
    decide(web, pid, "105")
    first = send(web, pid, targets_of(preview(web, pid, "101")))
    assert first.status_code == 303
    html = preview(web, pid, "101", "105")
    assert "есть незакрытая операция №" in html and "queued" in html
    assert [t.split("|")[0] for t in targets_of(html)] == ["105"]
    r = send(web, pid, targets_of(html))
    assert r.status_code == 303, r.text[:300]


def test_non_numeric_hub_id_is_excluded_with_reason(web):
    """Круг 3 Codex: номер «A-1» допустим в выгрузке, но в Hub статус ставится только по числу – такая находка
    исключается с причиной, предпросмотр не падает."""
    pid = project(web, [sast("101", 2), sast("A-1", 11)])
    decide(web, pid, "101")
    decide(web, pid, "A-1")
    html = preview(web, pid, "101", "A-1")
    assert [t.split("|")[0] for t in targets_of(html)] == ["101"]
    assert "A-1" in html and "не номер Hub" in html


def test_open_operation_is_found_by_the_queue_key_scope(web):
    """Круг 2 Codex: открытая операция ищется по области ключей очереди (адрес Hub, приложение, тип, номер), а не по
    последней операции находки: смена приложения снимает конфликт, а старая открытая операция, скрытая более новой
    закрытой, по-прежнему исключает находку."""
    db = web.app.state.db
    pid = project(web, [sast("101", 2), sast("105", 11)])
    decide(web, pid, "101")
    decide(web, pid, "105")
    assert send(web, pid, targets_of(preview(web, pid, "101"))).status_code == 303  # операция №1 для приложения 7
    run_worker(web, status=500, body={})  # ответ 5xx у записи – «результат неизвестен»: №1 открыта (unknown)
    assert db.hub_last_op(pid, "101", "status")["state"] == "unknown"
    html = preview(web, pid, "101", "105")
    assert "есть незакрытая операция №" in html and [t.split("|")[0] for t in targets_of(html)] == ["105"]
    db.update_project(pid, hub_app_id=8)  # другое приложение Hub – ключи не пересекаются: 101 снова в партии
    assert sorted(t.split("|")[0] for t in targets_of(preview(web, pid, "101", "105"))) == ["101", "105"]
    assert send(web, pid, targets_of(preview(web, pid, "101"))).status_code == 303  # операция №2 для приложения 8
    run_worker(web, status=400, body={"errorMessage": "нет"})  # определённый отказ: №2 – failed
    assert db.hub_last_op(pid, "101", "status")["state"] == "failed"
    db.update_project(pid, hub_app_id=7)  # прежнее приложение: №1 всё ещё открыта, хотя последняя – failed №2
    html = preview(web, pid, "101", "105")
    assert "есть незакрытая операция №" in html and [t.split("|")[0] for t in targets_of(html)] == ["105"]


def test_duplicate_delivery_does_not_overwrite_a_later_manual_mark(web):
    """Круг 1 Codex: после done оператор снял отметку и поставил свою (другой текст, та же редакция); повторная
    доставка результата её не перетирает. (Находка с ранее поставленной отметкой в партию не входит – правило
    ADR-0116, статус уже в Hub.)"""
    from app import hub_effects
    pid = project(web, [sast("101", 2), sast("105", 11)])
    decide(web, pid, "101")
    decide(web, pid, "105")
    db = web.app.state.db
    r = send(web, pid, targets_of(preview(web, pid, "101", "105")))
    assert r.status_code == 303
    run_worker(web)
    op = db.hub_last_op(pid, "101", "status")
    assert op["state"] == "done"
    review = db.get_review(pid, "101")
    db.mark_entered(pid, "101", False, revision=review["revision"], entered_hash="", entered_parts="")
    manual = db.mark_entered(pid, "101", True, revision=review["revision"], entered_hash=text_hash("текст решения"),
                             entered_parts="{}")
    assert manual["entered_text_hash"] == text_hash("текст решения")
    hub_effects.after_result(db, db.hub_op(op["id"]))  # повторная доставка
    after = db.get_review(pid, "101")
    assert after["entered_text_hash"] == text_hash("текст решения") and after["entered_hub"] == 1
    assert not hub_effects.effects_pending(db, db.hub_op(op["id"])), "ожидать отметку больше не нужно"


def test_too_many_warning_only_when_real_ids_are_dropped(web):
    from app.routes.hub_bulk import MAX_SELECTED
    pid = project(web, [sast("101", 2)])
    ids = [str(100 + i) for i in range(MAX_SELECTED)]
    exact = web.client.get(f"/projects/{pid}/hub/send-selected?" + "&".join(f"hub_id={h}" for h in ids)).text
    assert "Выбрано больше" not in exact
    repeats = web.client.get(f"/projects/{pid}/hub/send-selected?" + "&".join(f"hub_id={h}" for h in ids + ids[:3])).text
    assert "Выбрано больше" not in repeats, "повторы – не отброшенные номера"
    more = web.client.get(f"/projects/{pid}/hub/send-selected?" + "&".join(f"hub_id={h}" for h in ids + ["999"])).text
    assert "Выбрано больше" in more


def test_bulk_note_hidden_when_mark_is_removed_or_replaced(web):
    pid = project(web, [sast("101", 2)])
    decide(web, pid, "101")
    assert send(web, pid, targets_of(preview(web, pid, "101"))).status_code == 303
    run_worker(web)
    finding_id = fid(web, pid, "101")
    off = web.client.post(f"/projects/{pid}/findings/{finding_id}/entered", data={"entered": "0"}, headers=AS_JSON).json()
    assert off["ok"] and "entered-bulk" in off["hide"]
    revision = web.app.state.db.get_review(pid, "101")["revision"]
    from test_hub_status_routes import shown_text_hash
    on = web.client.post(f"/projects/{pid}/findings/{finding_id}/entered",
                         data={"entered": "1", "review_revision": str(revision),
                               "text_hash": shown_text_hash(web, pid, "101")}, headers=AS_JSON).json()
    assert on["ok"], on
    assert "entered-bulk" in on["hide"]


def test_bulk_mark_survives_verification_round(web):
    """«Результат неизвестен» → «Сверить»: ответ Hub с общим комментарием совпадает с отправленным – отметки с bulk."""
    pid = project(web, [sast("101", 2), sast("102", 5)])
    decide(web, pid, "101")
    decide(web, pid, "102")
    r = send(web, pid, targets_of(preview(web, pid, "101", "102")))
    op_id = int(re.search(r"op=(\d+)", r.headers["location"]).group(1))
    run_worker(web, status=503)
    assert web.app.state.db.hub_op(op_id)["state"] == "unknown"
    v = web.client.post(f"/projects/{pid}/hub/verify", data={"op_id": str(op_id)}, headers=AS_JSON)
    assert v.status_code == 200, v.text
    for issue in (101, 102):
        job = run_worker(web, body={"issueId": issue, "issueType": "SAST", "status": "False Positive",
                                    "reason": COMMON, "expiredAt": "2027-01-26T23:59:59Z"})
        assert job["path"].startswith("/issue/status?")
    assert web.app.state.db.hub_op(op_id)["state"] == "done"
    assert all(web.app.state.db.get_review(pid, h)["entered_hub"] == 1 for h in ("101", "102"))
    assert hub_ops.normalize_text(COMMON) == hub_ops.normalize_text(web.app.state.db.hub_op(op_id)["text_norm"])


def test_common_comment_keeps_first_line_indent(web):
    """Ревью круга 5 (ADR-0149 п. 5): общий комментарий уходит как написан – отступ первой строки остаётся, хвостовые
    пробелы и пустые строки по краям – нет."""
    pid = project(web, [sast("101", 2), sast("105", 11)])
    decide(web, pid, "101")
    decide(web, pid, "105")
    r = send(web, pid, targets_of(preview(web, pid, "101", "105")), comment="\n  " + COMMON + "  \n\n")
    assert r.status_code == 303, r.text[:300]
    assert run_worker(web)["body"]["reason"] == "  " + COMMON
