"""Служебный блок Hub для дефекта без блока и без заготовки (0.9.26.dev31): дефект занесён из Hub, в
описании Hub блока нет (потерян записью только текста до dev30), заготовки у строки нет – «Push в Hub» запрашивает у Hub
заготовку по находкам дефекта (шаг «blank»), сохраняет её в строке и добавляет её блок в описание следом за текстом.
Данные выдуманы, сети нет."""

from __future__ import annotations

import json
import re

from app import hub_defects
from test_hub_defect_update import (  # noqa: F401
    BLOCK,
    act,
    deliver,
    form_fields,
    hub_body,
    note,
    phase,
    put_click,
    read_job,
    ready,
    sent_body,
    tab,
    take,
    web,
)

TEXT = "Текст без блока."
TEXT_ONLY = hub_body(description=hub_defects.command_html(TEXT))
BLANK = {"summary": "заготовка Hub", "description": BLOCK, "priority": {"name": "Major", "rank": 2},
         "severity": {"name": "Medium", "rank": 2}, "groupId": 3}


def no_block_row(web, text: str = TEXT) -> tuple[int, dict]:
    """Дефект №777, занесённый из Hub: заготовки у строки нет, черновик текста – text."""
    pid, row = ready(web, build=False)
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET draft_command_text = ? WHERE id = ?", (text, row["id"]))
    row = db.hub_defect(row["id"])
    assert not str(row["blank_json"] or "").strip() and row["origin"] == "import"
    return pid, row


def start(web, pid: int, row: dict, body: dict | None = None) -> dict:
    """«Push в Hub» и ответ первого чтения; вкладка обрабатывает ответ (подготовка маршрутом)."""
    r = act(web, pid, row["id"], "update")
    assert r.status_code == 200, r.text
    read_job(web, body if body is not None else TEXT_ONLY)
    tab(web, pid)
    return web.app.state.db.hub_defect(row["id"])


def blank_job(web, status: int = 200, body: dict | None = None, error: str = "") -> dict:
    job = take(web)
    assert job is not None and job["method"] == "GET" and job["path"].startswith("/defects/blank?"), job
    deliver(web, job, status, body if body is not None else BLANK, error=error)
    return job


def test_push_requests_a_blank_and_adds_its_block(web):
    pid, row = no_block_row(web)
    db = web.app.state.db
    fresh = start(web, pid, row)
    state = hub_defects.update_state(fresh)
    assert state["step"] == "blank" and state["blank_tried"] is True and fresh["update_op_id"], state
    assert "заготовку для служебного блока" in hub_defects.update_view(fresh)[0]
    assert "заготовку" in tab(web, pid)
    job = blank_job(web)
    assert re.fullmatch(r"/defects/blank\?appId=\d+&issueIds=510001&type=SAST", job["path"]), job["path"]
    tab(web, pid)
    fresh = db.hub_defect(row["id"])
    state = hub_defects.update_state(fresh)
    assert state["phase"] == "preview", note(db, row["id"])
    assert state["block_mode"] == "added" and state["blank_fetched"] is True and state["block"] == BLOCK
    assert "first_read" not in state
    assert state["new"]["description"] == hub_defects.command_html(TEXT) + "\n" + BLOCK
    assert json.loads(fresh["blank_json"])["description"] == BLOCK, "заготовка сохранена в строке"
    assert json.loads(fresh["blank_json"])["_targets"] == [510001], "заготовка помечена составом запроса"
    assert fresh["update_op_id"] is None
    page = tab(web, pid)
    assert "только что запрошенной у Hub по находкам дефекта" in page
    card = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    assert 'id="defect-hub-block"' in card and "из заготовки" in card and "InvoiceDao.java" in card
    # Push: второе чтение (тот же объект), PUT – текст и блок заготовки, подтверждение чтением
    assert put_click(web, pid, row).status_code == 200
    read_job(web, TEXT_ONLY)
    put = take(web)
    assert put is not None and put["method"] == "PUT" and put["path"] == "/defects/777", put
    assert put["body"]["description"] == hub_defects.command_html(TEXT) + "\n" + BLOCK
    deliver(web, put, 204, text="")
    read_job(web, sent_body(db, row["id"]))
    assert phase(db, row["id"]) == "done", note(db, row["id"])
    assert take(web) is None


def test_blank_refusal_gives_a_preview_without_the_block(web):
    """Hub не дал заготовку: предпросмотр без блока, с предупреждением; заготовка в строке не появляется; следующая
    подготовка спрашивает снова. Текст правлен: без правки и без блока отправлять было бы нечего."""
    pid, row = no_block_row(web, TEXT + " Правка.")
    db = web.app.state.db
    start(web, pid, row)
    blank_job(web, status=500, body={}, error="Hub ответил кодом 500")
    tab(web, pid)
    fresh = db.hub_defect(row["id"])
    state = hub_defects.update_state(fresh)
    assert state["phase"] == "preview", note(db, row["id"])
    assert state["block_mode"] == "none" and state["block"] == "" and not state.get("blank_fetched")
    assert any("заготовку Hub для служебного блока получить не удалось" in w and "500" in w for w in state["warnings"]), state["warnings"]
    assert state["new"]["description"] == hub_defects.command_html(TEXT + " Правка.")
    assert not str(fresh["blank_json"] or "").strip()
    r = act(web, pid, row["id"], "update-cancel", form_fields(web, pid, f"hub-update-cancel-form-{row['id']}"))
    assert r.status_code == 200, r.text
    start(web, pid, row)
    assert hub_defects.update_state(db.hub_defect(row["id"]))["step"] == "blank"
    blank_job(web, body={"description": ""})  # пустое описание – тоже без блока
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "preview" and state["block"] == ""
    assert any("в ответе Hub нет описания" in w for w in state["warnings"]), state["warnings"]


def test_no_blank_request_when_hub_has_the_block(web):
    """Описание Hub с блоком – заготовка не запрашивается."""
    pid, row = ready(web, build=False)
    db = web.app.state.db
    fresh = start(web, pid, row, hub_body())  # описание Hub по умолчанию – с блоком
    assert hub_defects.update_state(fresh)["phase"] in ("preview", "cancelled"), note(db, row["id"])
    assert take(web) is None and not str(fresh["blank_json"] or "").strip()


def test_no_blank_request_when_the_blank_is_saved(web):
    """В Hub блока нет, а заготовка сохранена (дефект создан из приложения или заготовка уже запрошена) – без запроса."""
    pid, row = no_block_row(web)
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET blank_json = ? WHERE id = ?",
                  (json.dumps({"description": BLOCK, "_targets": [510001]}), row["id"]))
    fresh = start(web, pid, db.hub_defect(row["id"]))
    state = hub_defects.update_state(fresh)
    assert state["phase"] == "preview" and state["block_mode"] == "added" and not state.get("blank_fetched"), state
    assert take(web) is None


def test_update_blank_item_needs_hub_issue_numbers():
    row = {"id": 4, "project_id": 1, "hub_url": "https://hub.example.invalid", "app_id": 7, "kind": "SAST",
           "targets_json": json.dumps([{"hub_id": "510001", "issue_id": 510001, "issue_type": "SAST"}])}
    item, why = hub_defects.update_blank_item(row)
    assert why == "" and item["purpose"] == "defect_blank" and item["request"]["method"] == "GET"
    assert item["request"]["path"] == "/defects/blank?appId=7&issueIds=510001&type=SAST"
    assert item["targets"] == [{"defect_update": 4, "issue_type": hub_defects.UPDATE_TYPE, "issue_id": 4}]
    assert hub_defects.update_blank_item({**row, "targets_json": "[]"}) == (None, "у находок дефекта нет номеров Hub")
    assert "без типа находки Hub" in hub_defects.update_blank_item({**row, "kind": "DAST-x"})[1]
    assert "нет приложения Hub" in hub_defects.update_blank_item({**row, "app_id": None})[1]
    assert hub_defects.update_blank_item({**row, "targets_json": json.dumps([{"hub_id": "x", "issue_id": "x"}])})[1]
    many = json.dumps([{"hub_id": str(600000 + i), "issue_id": 600000 + i, "issue_type": "SAST"}
                       for i in range(hub_defects.ISSUE_IDS_MAX // 7 + 2)])  # шесть цифр и запятая на номер – длиннее предела
    item, why = hub_defects.update_blank_item({**row, "targets_json": many})
    assert item is None and "issueIds" in why


def test_blank_refusal_with_unchanged_text_keeps_the_warning(web):
    """Текст не менялся, блока нет, заготовку не дали: итог «Изменений для отправки нет» несёт причину (ревью dev31,
    круг 1) – оператор видит, что служебные сведения не восстановлены."""
    pid, row = no_block_row(web)
    db = web.app.state.db
    start(web, pid, row)
    blank_job(web, status=500, body={}, error="Hub ответил кодом 500")
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "cancelled", note(db, row["id"])
    assert "Изменений для отправки нет" in state["note"] and "заготовку Hub для служебного блока получить не удалось" in state["note"]
    assert any("500" in w for w in state["warnings"])
    text, tone, final = hub_defects.update_view(db.hub_defect(row["id"]))
    assert "получить не удалось" in text and final


def test_saved_blank_of_another_composition_is_requested_again(web):
    """Заготовка, запрошенная для другого состава (после «Pull из Hub» состав изменился), не годится: шаг «blank»
    запрашивает новую по нынешним находкам; заготовка без отметки состава (получена при создании) годится."""
    pid, row = no_block_row(web)
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET blank_json = ? WHERE id = ?",
                  (json.dumps({"description": "<p>Информация об объекте сканирования:</p><p>старый состав</p>",
                               "_targets": [510002]}), row["id"]))
    assert not hub_defects.saved_blank_fits(db.hub_defect(row["id"]))
    fresh = start(web, pid, db.hub_defect(row["id"]))
    assert hub_defects.update_state(fresh)["step"] == "blank"
    job = blank_job(web)
    assert "issueIds=510001&" in job["path"]
    tab(web, pid)
    fresh = db.hub_defect(row["id"])
    state = hub_defects.update_state(fresh)
    assert state["phase"] == "preview" and state["block"] == BLOCK and state["blank_fetched"] is True
    assert json.loads(fresh["blank_json"])["_targets"] == [510001]
    assert hub_defects.saved_blank_fits(fresh)
    legacy = {**fresh, "blank_json": json.dumps({"description": BLOCK})}
    assert hub_defects.saved_blank_fits(legacy), "прежняя заготовка без отметки годится: новую Hub для привязанных находок не выдаст"


def test_composition_refusal_comes_before_the_blank_request(web):
    """В Hub у дефекта находка сверх целей строки: отказ п. 2 («сначала «Pull из Hub»») – без запроса заготовки, чтобы
    не сохранить заготовку для устаревшего состава."""
    pid, row = no_block_row(web)
    two = hub_body(links=((510001, "SAST"), (510002, "SAST")), description=hub_defects.command_html(TEXT))
    fresh = start(web, pid, row, two)
    state = hub_defects.update_state(fresh)
    assert state["phase"] == "refused", state
    assert any("Pull" in r for r in state["refusals"]), state["refusals"]
    assert take(web) is None and not str(fresh["blank_json"] or "").strip()


def test_create_body_drops_the_composition_mark():
    body = hub_defects.create_body({"id": 1, "description": "<p>x</p>", "_targets": [1, 2], "stage": "DEV"}, 7, "T",
                                   "<p>d</p>", None, None)
    assert "_targets" not in body and "id" not in body and body["stage"] == "DEV"


def test_unfit_blank_and_refused_request_send_only_the_text(web):
    """Заготовка другого состава, а новую Hub не дал: негодная заготовка не идёт ни в предпросмотр, ни в PUT, ни в
    карточку (ревью dev31, круг 2) – оператору обещан только текст, и уходит только текст."""
    pid, row = no_block_row(web, TEXT + " Правка.")
    db = web.app.state.db
    foreign = {"description": "<p>Информация об объекте сканирования:</p><p>чужой состав</p>", "_targets": [510002]}
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET blank_json = ? WHERE id = ?", (json.dumps(foreign), row["id"]))
    row = db.hub_defect(row["id"])
    assert hub_defects.block_for_write(row, {"description": "<p>x</p>"}) == ("", "")
    assert hub_defects.block_for_display(row, {"description": "<p>x</p>"}) == ("", "")
    start(web, pid, row)
    blank_job(web, status=500, body={}, error="Hub ответил кодом 500")
    tab(web, pid)
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "preview" and state["block"] == "" and state["block_mode"] == "none", note(db, row["id"])
    assert state["new"]["description"] == hub_defects.command_html(TEXT + " Правка.")
    assert any("получить не удалось" in w for w in state["warnings"])
    card = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    assert "чужой состав" not in card
    assert put_click(web, pid, row).status_code == 200
    read_job(web, TEXT_ONLY)
    put = take(web)
    assert put["method"] == "PUT" and put["body"]["description"] == hub_defects.command_html(TEXT + " Правка.")
    assert "чужой состав" not in put["body"]["description"]


def test_blank_failure_text_names_the_reason():
    """Причина, по которой заготовку нельзя запросить (например, issueIds длиннее предела), попадает в предупреждение
    предпросмотра словами update_blank_item."""
    row = {"id": 4, "project_id": 1, "hub_url": "https://hub.example.invalid", "app_id": 7, "kind": "SAST",
           "targets_json": json.dumps([{"hub_id": str(600000 + i), "issue_id": 600000 + i}
                                       for i in range(hub_defects.ISSUE_IDS_MAX // 7 + 2)])}  # шесть цифр и запятая
    item, why = hub_defects.update_blank_item(row)
    text = hub_defects.blank_failure_text(why)
    assert item is None and text.startswith("заготовку Hub для служебного блока получить не удалось (")
    assert "issueIds" in text and text.endswith("в описание уйдёт только текст приложения")
