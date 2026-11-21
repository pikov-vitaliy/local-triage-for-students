"""«Push в Hub» (ADR-0125): заголовок и текст дефекта, занесённого из Hub, по текущим решениям – запросом
`PUT /defects/{id}` через исполнителя. Схема 28 (новая база, 27 → 28, 26 → 28, копия, откат шага, повторное
открытие). Данные, адреса и номера выдуманы."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app import hub_defects
from app.db import Database, dumps, text_hash
from test_defect import save_sast
from test_hub_defect_import import apply_sync, DESCRIPTION, defect_body, deliver, imported, take, tab
from test_hub_defects import FIX, REASON, hub_settings, pair_project
from test_hub_status_routes import AS_JSON, worker_headers
from test_web import ORIGIN, prepared, start_run, wait_run, web  # noqa: F401


# ============================================================================ схема 28


def test_schema_28_fields_are_known_to_row_updates(tmp_path: Path):
    """Колонки 28 записываются только через перечни полей строки: update_op_id – ещё и поле операции (expect_op)."""
    db = Database(tmp_path / "t.db")
    try:
        assert {"update_op_id", "update_json", "text_generation"} <= Database.HUB_DEFECT_FIELDS
        assert "update_op_id" in Database.HUB_DEFECT_OP_FIELDS
        assert "text_generation" not in Database.HUB_DEFECT_OP_FIELDS
    finally:
        db.close()


# ============================================================================ помощники цепочки

OLD_SUMMARY = "ID5 - SQL injection (SAST)"
NEW_SUMMARY = "ID5 - Внедрение SQL-кода (SAST)"
BLOCK = ("<p>Информация об объекте сканирования:</p><p>ID: 510001, файл InvoiceDao.java, строка 58</p>"
         "<p>ID: 510002, файл Renderer.java</p>")
assert DESCRIPTION.endswith(BLOCK)


def hub_body(links=((510001, "SAST"),), summary: str = OLD_SUMMARY, description: str = DESCRIPTION, **extra) -> dict:
    """Ответ `GET /defects/777` со структурой настоящего (поля как у интерфейса Hub – выдуманные значения)."""
    fields = {"author": {"login": "user1", "name": "Иван Тестов"}, "createTs": "2026-10-27T12:00:00Z",
              "updateTs": "2026-10-28T12:00:00Z", "priorityId": 2, "severityId": 3, "settings": {}, "status": "Open",
              "priority": {"name": "High"}, "severity": {"name": "High"}, "externalBugs": [], "dueDate": "2026-11-10T18:00:00+01:00", "type": "Software", "stage": "DEV", "source": "Tool"}
    return defect_body(777, links=links, summary=summary, description=description, **{**fields, **extra})


def ready(web, links=((510001, "SAST"),), summary: str = OLD_SUMMARY, build: bool = True) -> tuple[int, dict]:
    """Проект с прогоном, решение «Подтверждаю дефект» с «Проверено» по 510001 и дефект №777 (ID5), занесённый из Hub."""
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    hub_settings(web, pid)
    save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    row = imported(web, pid, "777", hub_body(links=links, summary=summary))
    assert row["origin"] == "import" and row["text_generation"] == 0
    if build:
        assemble(web, pid, row)
    return pid, web.app.state.db.hub_defect(row["id"])


def assemble(web, pid, row):
    current = web.app.state.db.hub_defect(row["id"])
    return web.client.post(f"/projects/{pid}/defects/{row['id']}/text-from-decisions", headers=AS_JSON,
                           data={"draft_revision": str(current["draft_revision"])})


def act(web, pid: int, row_id: int, action: str, data: dict | None = None):
    return web.client.post(f"/projects/{pid}/hub/defects/{row_id}/{action}", headers=AS_JSON, data=data or {})


def form_fields(web, pid: int, form_id: str) -> dict:
    form = re.search(rf'<form [^>]*id="{form_id}".*?</form>', tab(web, pid), re.S)
    assert form is not None, f"во вкладке нет формы {form_id}"
    return dict(re.findall(r'name="([^"]+)" value="([^"]*)"', form.group(0)))


def phase(db, row_id: int) -> str:
    return hub_defects.update_state(db.hub_defect(row_id)).get("phase", "")


def note(db, row_id: int) -> str:
    state = hub_defects.update_state(db.hub_defect(row_id))
    return " ".join([str(state.get("note") or "")] + [str(x) for x in state.get("refusals") or []])


def read_job(web, body: dict | None = None, status: int = 200, text: str | None = None, error: str = "") -> dict:
    job = take(web)
    assert job is not None and job["method"] == "GET" and job["path"] == "/defects/777", job
    deliver(web, job, status, body if body is not None else hub_body(), text, error)
    return job


def to_preview(web, pid: int, row: dict, body: dict | None = None) -> dict:
    r = act(web, pid, row["id"], "update")
    assert r.status_code == 200, r.text
    read_job(web, body)
    tab(web, pid)
    return web.app.state.db.hub_defect(row["id"])


def put_click(web, pid: int, row: dict):
    return act(web, pid, row["id"], "update-put", form_fields(web, pid, f"hub-update-put-form-{row['id']}"))


def to_put(web, pid: int, row: dict, second: dict | None = None, first: dict | None = None) -> dict:
    """Предпросмотр → «Push в Hub» → второе чтение (тот же объект): возвращает задание `PUT`."""
    to_preview(web, pid, row, first)
    assert phase(web.app.state.db, row["id"]) == "preview", note(web.app.state.db, row["id"])
    r = put_click(web, pid, row)
    assert r.status_code == 200, r.text
    read_job(web, second if second is not None else first)
    put = take(web)
    assert put is not None and put["method"] == "PUT" and put["path"] == "/defects/777", (put, note(
        web.app.state.db, row["id"]))
    return put


def sent_body(db, row_id: int, **extra) -> dict:
    """Ответ Hub после записи: объект второго чтения с отправленными заголовком и описанием."""
    sent = hub_defects.update_state(db.hub_defect(row_id))["sent"]
    return hub_body(**{"summary": sent["summary"], "description": sent["description"], "updateTs": "2026-10-29T12:00:00Z",
                       **extra})


def to_done(web, pid: int, row: dict) -> dict:
    db = web.app.state.db
    put = to_put(web, pid, row)
    deliver(web, put, 204, text="")
    read_job(web, sent_body(db, row["id"]))
    fresh = db.hub_defect(row["id"])
    assert hub_defects.update_state(fresh)["phase"] == "done", hub_defects.update_state(fresh)
    return fresh


def ops(db, purpose: str) -> list[dict]:
    return [o for o in db.hub_ops_list(limit=10000) if o["purpose"] == purpose]


# ============================================================================ успех: подготовка → предпросмотр → PUT → подтверждение


def test_update_chain_preview_put_confirm_and_marks(web):
    pid, row = ready(web)
    db = web.app.state.db
    assert row["number"] == 5
    assert db.get_review(pid, "510001")["entered_hub"] == 0 and db.defect_number(pid, "sast:510001") is None
    page = tab(web, pid)
    assert f'id="hub-update-form-{row["id"]}"' in page and "Push в Hub</button>" in page
    preview = to_preview(web, pid, row)
    state = hub_defects.update_state(preview)
    assert state["phase"] == "preview" and state["generation"] == 1 and preview["update_op_id"] is None, state
    assert state["new"]["summary"] == NEW_SUMMARY and state["block"] == BLOCK, "блок Hub переносится байт в байт (dev30)"
    page = tab(web, pid)
    assert f'id="hub-update-preview-{row["id"]}"' in page and NEW_SUMMARY in page and OLD_SUMMARY in page
    assert f'id="hub-update-put-form-{row["id"]}"' in page and f'id="hub-update-cancel-form-{row["id"]}"' in page
    assert f'id="hub-update-form-{row["id"]}"' not in page, "предпросмотр не заменяется второй подготовкой"
    r = put_click(web, pid, row)
    assert r.status_code == 200, r.text
    read_job(web)
    put = take(web)
    assert put is not None and put["method"] == "PUT" and put["path"] == "/defects/777"
    second = hub_body()
    # тело – объект второго чтения как есть, кроме summary и description; временные поля соответствуют DefectDto
    assert {k: v for k, v in put["body"].items() if k not in ("summary", "description")} == {
        k: v for k, v in second.items() if k not in ("summary", "description")}
    assert put["body"]["updateTs"] == "2026-10-28T12:00:00Z" and isinstance(put["body"]["createTs"], str)
    assert put["body"]["summary"] == NEW_SUMMARY
    # dev30: описание в Hub – текст дефекта из приложения и следом исходный блок Hub
    assert put["body"]["description"] == hub_defects.command_html(state["new"]["command_text"]) + "\n" + BLOCK
    command = db.hub_defect(row["id"])
    assert hub_defects.update_state(command)["phase"] == "putting" and command["state"] == "done"
    assert put["purpose"] == "defect_update"
    assert hub_defects.update_state(command)["sent_object"] == put["body"]
    deliver(web, put, 204, text="")
    assert phase(db, row["id"]) == "confirming"
    read_job(web, sent_body(db, row["id"]))
    done = db.hub_defect(row["id"])
    state = hub_defects.update_state(done)
    assert state["phase"] == "done" and done["text_generation"] == 1 and done["effects_done"] == 1
    observed = json.loads(done["import_json"])
    # в строке – разбор подтверждающего чтения, текст генератора – только в update_json (вариант A, ADR-0125 п. 4)
    assert done["summary"] == NEW_SUMMARY and done["command_text"] == observed["command_text"]
    assert done["body_html"] == put["body"]["description"] and done["update_op_id"] is None
    # отпечаток подтверждённого текста – от разбора подтверждающего чтения (круг 1 ревью, C2)
    assert state["confirmed"] == {"summary": NEW_SUMMARY, "number": 5, "generation": 1, "op": done["confirm_op_id"],
                                  "text_hash": text_hash(observed["command_text"])}
    assert observed["summary"] == NEW_SUMMARY and [t["hub_id"] for t in observed["accepted"]] == ["510001"]
    # отметки «Внесено в Hub» и номер ID5 ключу – только по подтверждённому обновлению
    review = db.get_review(pid, "510001")
    assert review["entered_hub"] == 1 and review["entered_decision_hash"] == text_hash(state["new"]["command_text"])
    assert db.defect_number(pid, "sast:510001") == 5
    assert len(ops(db, "defect_update")) == 1 and ops(db, "defect_update")[0]["state"] == "done"
    assert "Обновлено в Hub" in tab(web, pid)


def test_tab_and_card_show_the_update_steps_with_polling(web):
    """Вкладка: у строки в пути – текст шага и опрос состояния (data-poll), кнопок шага нет; JSON состояния дефекта –
    не конечный, пока операция шага в очереди; конечный – перезагрузка вкладки."""
    pid, row = ready(web)
    assert act(web, pid, row["id"], "update").status_code == 200
    page = tab(web, pid)
    assert "Готовлю обновление: читаю дефект №777" in page
    assert f'data-poll="/projects/{pid}/hub/defects/{row["id"]}"' in page
    assert f'id="hub-update-form-{row["id"]}"' not in page and f'id="hub-sync-form-{row["id"]}"' not in page
    state = web.client.get(f"/projects/{pid}/hub/defects/{row['id']}").json()
    assert state["done"] is False and "reload" not in state
    read_job(web)
    state = web.client.get(f"/projects/{pid}/hub/defects/{row['id']}").json()
    assert state["done"] is True and state["reload"] is True
    page = tab(web, pid)
    assert "Обновление подготовлено" in page and f'data-poll="/projects/{pid}/hub/defects/{row["id"]}"' not in page


# ============================================================================ блок Hub и описание (п. 2)


@pytest.mark.parametrize("description,block", [
    (DESCRIPTION, BLOCK),
    # текст команды абзацами, строками, списком, ссылками и сущностями; перевод строки перед блоком – не в блоке
    ("<p>Текст &amp; «кавычки»<br>строка</p><p>Рекомендация:</p><ol><li>Один</li><li><a href=\"https://example.org/x\">"
     "ссылка</a></li></ol>\n<p>Информация об объекте сканирования:</p><ul><li>файл</li></ul>",
     "<p>Информация об объекте сканирования:</p><ul><li>файл</li></ul>"),
    # блок Hub в своей вложенной обёртке
    ("<p>Текст.</p><div><div><p>Информация об объекте сканирования:</p><p>файл</p></div></div><p>хвост</p>",
     "<div><div><p>Информация об объекте сканирования:</p><p>файл</p></div></div><p>хвост</p>"),
    # граница – строкой через <br> в начале элемента, сущность пробела, пустой элемент перед ней
    ("<p>Текст.</p><p><br>Информация об объекте сканирования:<br>файл&nbsp;A</p>",
     "<p><br>Информация об объекте сканирования:<br>файл&nbsp;A</p>"),
    # граница – текст вне элементов
    ("<p>Текст.</p>Информация об объекте сканирования:<br>файл", "Информация об объекте сканирования:<br>файл"),
])
def test_hub_block_is_the_original_substring(description, block):
    got, problem = hub_defects.hub_block(description)
    assert (got, problem) == (block, "")
    assert description.endswith(got)
    text = "После анализа команда «Платформа» приняла решение.\n\nОбоснование:\nтекст\n\nРекомендация:\n1) Мера."
    assembled, problem = hub_defects.update_description(text)
    assert problem == "" and assembled == hub_defects.command_html(text), "описание – только текст (31.10)"


@pytest.mark.parametrize("description,words", [
    ("<p>Текст без блока Hub.</p>", "нет строки"),
    # блок Hub в одной обёртке с текстом команды
    ("<div><p>Текст команды.</p><p>Информация об объекте сканирования:</p><p>файл</p></div>", "склеен"),
    ("<p>Текст команды.<br>Информация об объекте сканирования:<br>файл</p>", "склеен"),
    ("Текст команды.\nИнформация об объекте сканирования:\nфайл", "склеен"),
    ("", "нет строки"),
])
def test_hub_block_refusals_mean_manual_fix(description, words):
    got, problem = hub_defects.hub_block(description)
    assert got == "" and words in problem and "вручную" in problem


def test_assembled_description_is_only_the_operator_text():
    """Собранное описание – только текст оператора и ничего больше."""
    text = "Обоснование:\nблок"
    assembled, problem = hub_defects.update_description(text)
    assert problem == "" and assembled == hub_defects.command_html(text)
    assert "Информация об объекте сканирования" not in assembled


def test_new_content_exact_or_normalized_and_other_fields():
    text = "Обоснование:\nтекст\n\nРекомендация:\n1) Мера."
    description = hub_defects.description_html(text, BLOCK)
    sent = {"summary": NEW_SUMMARY, "description": description, "command_text": text, "block": BLOCK}
    assert hub_defects.update_content_new({"summary": NEW_SUMMARY, "description": description}, sent)
    # Hub нормализовал HTML текста команды, блок – прежний: новое содержимое
    normalized = description.replace("<br>", "<br/>").replace("<p>Обоснование", "<p >Обоснование")
    assert normalized != description
    assert hub_defects.update_content_new({"summary": NEW_SUMMARY, "description": normalized}, sent)
    # с 31.10 отправляется только текст: подтверждает только всё описание целиком (ревью A3, B1)
    only = {"summary": NEW_SUMMARY, "description": hub_defects.command_html(text), "command_text": text, "block": ""}
    assert hub_defects.update_content_new({"summary": NEW_SUMMARY, "description": hub_defects.command_html(text)}, only)
    tidy = hub_defects.command_html(text).replace("<br>", "<br/>")
    assert hub_defects.update_content_new({"summary": NEW_SUMMARY, "description": tidy}, only), "нормализация HTML"
    assert not hub_defects.update_content_new({"summary": NEW_SUMMARY, "description": description}, only), \
        "тот же текст и хвост блока Hub – описание не заменено"
    assert not hub_defects.update_content_new({"summary": OLD_SUMMARY, "description": description}, sent)
    assert not hub_defects.update_content_new({"summary": NEW_SUMMARY, "description": DESCRIPTION}, sent)
    changed_block = description.replace("строка 58", "строка 59")
    assert not hub_defects.update_content_new({"summary": NEW_SUMMARY, "description": changed_block}, sent)
    base = hub_body()
    assert hub_defects.update_other_diffs(base, {**base, "summary": "x", "description": "y", "updateTs": 1}) == []
    assert hub_defects.update_other_diffs(base, {**base, "status": "Closed", "dueDate": 5}) == ["dueDate", "status"]


# ============================================================================ отбор (п. 2)


def app_row(db, pid: int, number: int = 9, defect_id: str = "777", state: str = "done") -> dict:
    row = db.hub_defect_insert(pid, kind="SAST", number=number, summary=f"ID{number} - x (SAST)",
                               anchor_hub_id="510003", targets=[{"hub_id": "510003", "issue_id": 510003,
                                                                 "issue_type": "SAST", "revision": 1}],
                               number_keys=["sast:510003"], command_text="x", hub_url="https://hub.example.org",
                               app_id=7)
    return db.hub_defect_update(row["id"], state=state, hub_defect_id=defect_id)


def test_app_and_imported_defects_can_start_update(web):
    pid, row = ready(web)
    db = web.app.state.db
    other = app_row(db, pid, defect_id="555")
    assert f'id="hub-update-form-{other["id"]}"' in tab(web, pid)
    r = act(web, pid, other["id"], "update")
    assert r.status_code == 200, r.text
    assert db.hub_defect(other["id"])["update_op_id"]


def test_two_rows_of_one_hub_defect_are_refused(web):
    pid, row = ready(web)
    db = web.app.state.db
    app_row(db, pid, number=5, defect_id="777")  # строка привязки того же дефекта Hub
    r = act(web, pid, row["id"], "update")
    assert r.status_code == 409 and "несколько строк" in r.json()["detail"] and "обновление закрыто" in r.json()["detail"]
    assert db.hub_defect(row["id"])["update_op_id"] is None and phase(db, row["id"]) == ""


def test_open_sync_and_unapplied_sync_preview_refuse_the_update(web):
    pid, row = ready(web)
    db = web.app.state.db
    assert act(web, pid, row["id"], "sync").status_code == 200
    r = act(web, pid, row["id"], "update")
    assert r.status_code == 409 and "Pull из Hub" in r.json()["detail"]
    read_job(web, hub_body(stage="TEST"))  # расхождение: предпросмотр sync_json
    assert json.loads(db.hub_defect(row["id"])["sync_json"]).get("read")
    page = tab(web, pid)
    assert f'id="hub-update-form-{row["id"]}"' not in page, "при неприменённой сверке кнопки нет"
    r = act(web, pid, row["id"], "update")
    assert r.status_code == 409 and "«Применить» или «Отменить» сверку" in r.json()["detail"]
    shown = form_fields(web, pid, f"hub-sync-cancel-form-{row['id']}")["shown"]
    assert act(web, pid, row["id"], "sync-cancel", {"shown": shown}).status_code == 200
    assert act(web, pid, row["id"], "update").status_code == 200


def test_running_update_refuses_sync_apply_recheck_and_a_second_update(web):
    pid, row = ready(web)
    db = web.app.state.db
    # предпросмотр сверки, сохранённый раньше, – чтобы проверить «Применить» при идущем обновлении (другая вкладка)
    assert act(web, pid, row["id"], "sync").status_code == 200
    read_job(web, hub_body(links=((510001, "SAST"), (510003, "SAST"))))
    stale_sync = db.hub_defect(row["id"])["sync_json"]
    shown = form_fields(web, pid, f"hub-sync-apply-form-{row['id']}")["shown"]
    assert act(web, pid, row["id"], "sync-cancel", {"shown": shown}).status_code == 200
    assert act(web, pid, row["id"], "update").status_code == 200
    r = act(web, pid, row["id"], "update")
    assert r.status_code == 409 and "уже идёт" in r.json()["detail"]
    r = act(web, pid, row["id"], "sync")
    assert r.status_code == 409 and "«Push в Hub»" in r.json()["detail"]
    r = act(web, pid, row["id"], "recheck")
    assert r.status_code == 409  # занесённому дефекту «Проверить в Hub» не применяется (ADR-0124)
    read_job(web)
    put = to_put_from_preview(web, pid, row)

    def apply_refused() -> None:
        db.hub_defect_update(row["id"], sync_json=stale_sync)
        before = db.hub_defect(row["id"])
        r = act(web, pid, row["id"], "sync-apply", {"shown": text_hash(stale_sync)})
        assert r.status_code == 409 and "«Push в Hub»" in r.json()["detail"], r.text
        after = db.hub_defect(row["id"])
        assert {k: after[k] for k in ("targets_json", "summary", "number", "import_json", "update_json")} == {
            k: before[k] for k in ("targets_json", "summary", "number", "import_json", "update_json")}
        db.hub_defect_update(row["id"], sync_json="")

    assert phase(db, row["id"]) == "putting"
    apply_refused()
    deliver(web, put, 204, text="")
    assert phase(db, row["id"]) == "confirming"
    apply_refused()
    job = take(web)
    deliver(web, job, 500, text="")  # подтверждающее чтение не удалось: фаза confirming без операции
    assert phase(db, row["id"]) == "confirming" and db.hub_defect(row["id"])["update_op_id"] is None
    apply_refused()
    assert act(web, pid, row["id"], "sync").status_code == 409
    assert act(web, pid, row["id"], "update").status_code == 409


def to_put_from_preview(web, pid: int, row: dict, second: dict | None = None) -> dict:
    """Из открытого предпросмотра: «Push в Hub» и второе чтение; возвращает задание `PUT`."""
    r = put_click(web, pid, row)
    assert r.status_code == 200, r.text
    read_job(web, second)
    put = take(web)
    assert put is not None and put["method"] == "PUT", (put, note(web.app.state.db, row["id"]))
    return put


def test_sast_refusals_text_readiness_and_empty(web):
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    hub_settings(web, pid)
    db = web.app.state.db
    save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    save_sast(web, pid, "510004", "true_positive", "", REASON, "Другая рекомендация.")
    two = imported(web, pid, "777", hub_body(links=((510001, "SAST"), (510004, "SAST"))))
    generated = assemble(web, pid, two)
    assert generated.status_code == 409 and "разный текст решения" in generated.text
    # текст из Hub (черновик не собран из решений) без правки – «Изменений для отправки нет», без отказа по формату
    # (если ничего не меняем – никаких разниц)
    to_preview(web, pid, two, hub_body(links=((510001, "SAST"), (510004, "SAST"))))
    state = hub_defects.update_state(db.hub_defect(two["id"]))
    assert state["phase"] == "cancelled" and state.get("note") == "Изменений для отправки нет", state
    # находка без решения «Подтверждаю дефект»
    db.hub_defect_update(two["id"], targets_json=json.dumps(
        [{"hub_id": "510003", "issue_id": 510003, "issue_type": "SAST", "revision": 0}]))
    to_preview(web, pid, two, hub_body(links=((510003, "SAST"),)))
    assert phase(db, two["id"]) == "refused" and "нет решения «Подтверждаю дефект»" in note(db, two["id"])
    # пустой состав
    db.hub_defect_update(two["id"], targets_json="[]")
    to_preview(web, pid, two, hub_body(links=()))
    assert phase(db, two["id"]) == "refused" and "нет находок" in note(db, two["id"])
    assert not ops(db, "defect_update")


def test_fresh_hub_composition_refusal_and_warning(web):
    pid, row = ready(web)
    db = web.app.state.db
    # находка выгрузки, привязанная в Hub после занесения, – «сначала «Pull из Hub»»
    to_preview(web, pid, row, hub_body(links=((510001, "SAST"), (510003, "SAST"))))
    assert phase(db, row["id"]) == "refused" and "добавлены находки 510003" in note(db, row["id"])
    assert "Pull из Hub" in note(db, row["id"])
    # находка не из выгрузки – предупреждение; цели нет в ответе – не отвязка, обновлению не мешает
    to_preview(web, pid, row, hub_body(links=((599999, "SAST"),)))
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "preview", state
    assert any("599999" in w for w in state["warnings"]) and "599999" in tab(web, pid)


# ============================================================================ номер ID (п. 2)


@pytest.mark.parametrize("summary,words", [
    ("ID5 и ID6 - SQL (SAST)", "неоднозначен"),
    ("ID6 - SQL (SAST)", "было ID5, стало ID6"),
])
def test_number_from_the_hub_title_must_be_the_reserve(web, summary, words):
    pid, row = ready(web)
    db = web.app.state.db
    to_preview(web, pid, row, hub_body(summary=summary))
    assert phase(db, row["id"]) == "refused" and words in note(db, row["id"]), note(db, row["id"])
    assert "Pull из Hub" in note(db, row["id"])


def test_row_without_number_is_refused(web):
    pid, row = ready(web, summary="SQL injection (SAST)")
    db = web.app.state.db
    assert row["number"] is None
    to_preview(web, pid, row, hub_body(summary="ID5 - SQL injection (SAST)"))
    assert phase(db, row["id"]) == "refused" and "нет номера" in note(db, row["id"])
    assert "сначала «Pull из Hub»" in note(db, row["id"])


def test_number_taken_by_others_and_own_key_rules(web):
    pid, row = ready(web)
    db = web.app.state.db
    db.set_defect_number(pid, "sast:510003", 5)  # посторонняя находка
    to_preview(web, pid, row)
    assert phase(db, row["id"]) == "refused" and "номер ID5 занят" in note(db, row["id"])
    assert "sast:510003" in note(db, row["id"])
    with db._tx() as c:
        c.execute("DELETE FROM defects WHERE defect_key = 'sast:510003'")
    other = app_row(db, pid, number=5, defect_id="556")  # резерв другой строки
    to_preview(web, pid, row)
    assert phase(db, row["id"]) == "refused" and f"строка {other['id']}" in note(db, row["id"])
    db.hub_defect_update(other["id"], state="cancelled")
    # ключ цели с иным номером – отказ с ключом и номером
    db.set_defect_number(pid, "sast:510001", 9)
    to_preview(web, pid, row)
    assert phase(db, row["id"]) == "refused" and "у ключа sast:510001 уже номер ID9" in note(db, row["id"])
    db.set_defect_number(pid, "sast:510001", 5)
    to_preview(web, pid, row)
    assert phase(db, row["id"]) == "preview", note(db, row["id"])


def test_number_of_a_linked_finding_not_in_the_export_is_own(web):
    pid, row = ready(web)
    db = web.app.state.db
    with db._tx() as c:  # находка 510002 пропала из выгрузки (missing), за её ключом – номер этого дефекта
        c.execute("UPDATE findings SET missing = 1 WHERE project_id = ? AND hub_id = '510002'", (pid,))
    db.set_defect_number(pid, "sast:510002", 5)
    to_preview(web, pid, row, hub_body(links=((510001, "SAST"), (510002, "SAST"))))
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "preview", state
    assert any("510002" in w for w in state["warnings"])


def test_number_checks_repeat_in_the_put_transaction_on_its_connection(web, monkeypatch):
    """Номер заняли между предпросмотром и «Push в Hub»: транзакция постановки `PUT` проверяет снова – на своём
    соединении (варианты *_in), обёртки общего соединения при постановке не вызываются; PUT не поставлен – stale."""
    from app.db import Database
    pid, row = ready(web)
    db = web.app.state.db
    to_preview(web, pid, row)
    assert put_click(web, pid, row).status_code == 200
    for name in ("defect_keys_with_number", "hub_defects_with_number", "defect_keys_of_findings", "import_findings",
                 "hub_defect_holder"):
        monkeypatch.setattr(Database, name, lambda *a, **k: (_ for _ in ()).throw(AssertionError("общее соединение")))
    db.set_defect_number(pid, "sast:510003", 5)
    read_job(web)
    monkeypatch.undo()
    assert phase(db, row["id"]) == "stale" and "номер ID5 занят" in note(db, row["id"]), note(db, row["id"])
    assert not ops(db, "defect_update")
    assert "Обновление не отправлено" in tab(web, pid)


def test_number_changed_in_hub_between_preview_and_put(web):
    pid, row = ready(web)
    db = web.app.state.db
    to_preview(web, pid, row)
    assert put_click(web, pid, row).status_code == 200
    read_job(web, hub_body(summary="ID6 - SQL injection (SAST)"))
    assert phase(db, row["id"]) == "stale" and "summary" in note(db, row["id"])
    assert not ops(db, "defect_update")



def test_changed_after_preview_names_the_change_and_returns_to_defect_card(web):
    """«Push в Hub» не должен давать страницу «Ошибка 409» с одной кнопкой «К проектам», не сказав, что
    изменилось. Отказ без скрипта – карточка дефекта с сообщением и предпросмотром; причина названа."""
    pid, row = ready(web)
    db = web.app.state.db
    to_preview(web, pid, row)
    fields = form_fields(web, pid, f"hub-update-put-form-{row['id']}")
    save_sast(web, pid, "510001", "true_positive", "", REASON + " Уточнено.", FIX, defect_confirm="1")
    r = web.client.post(f"/projects/{pid}/hub/defects/{row['id']}/update-put", headers=ORIGIN,
                        data={**fields, "back": "defect-card"})
    assert r.status_code == 409
    assert 'id="defect-title"' in r.text and 'class="flash flash-err"' in r.text, "отказ – на карточке дефекта"
    assert "изменилось:" in r.text and "510001" in r.text
    assert "текст решения" in r.text or "решение сохранено заново" in r.text
    assert "Подготовить обновление" not in r.text
    assert phase(db, row["id"]) == "preview" and not ops(db, "defect_update")
    js = put_click(web, pid, row)
    assert js.status_code == 409 and "изменилось:" in js.json()["detail"]


def test_prep_changes_lists_each_kind_of_change():
    new = {"summary": "ID5 - A", "command_text": "T", "draft_revision": 1, "members_snapshot": [1], "fingerprint": "",
           "number_keys": ["sast:1"],
           "targets": [{"hub_id": "1", "revision": 1, "sig": "s", "decision_hash": "d", "entered_parts": "p"},
                       {"hub_id": "2", "revision": 1, "sig": "s", "decision_hash": "d", "entered_parts": "p"}]}
    same = hub_defects.prep_changes(new, new)
    assert same == []
    prep = {**new, "summary": "ID5 - B", "draft_revision": 2,
            "targets": [{"hub_id": "1", "revision": 2, "sig": "x", "decision_hash": "e", "entered_parts": "q"},
                        {"hub_id": "3", "revision": 1, "sig": "s", "decision_hash": "d", "entered_parts": "p"}]}
    text = "; ".join(hub_defects.prep_changes(new, prep))
    for part in ("заголовок", "черновик сохранён заново", "вошли находки 3", "ушли находки 2",
                 "решение сохранено заново – находка 1", "данные находки", "текст решения – находка 1",
                 "части отметки"):
        assert part in text, (part, text)
    # ревью 30.10: прежний формат хранил текст решения как entered_hash – тот же текст не называется изменённым
    legacy = {**new, "targets": [{"hub_id": "1", "revision": 1, "sig": "s", "entered_hash": "d", "entered_parts": "p"},
                                 {"hub_id": "2", "revision": 1, "sig": "s", "entered_hash": "d", "entered_parts": "p"}]}
    assert hub_defects.prep_changes(legacy, new) == []
    swapped = {**new, "targets": list(reversed(new["targets"]))}
    assert hub_defects.prep_changes(new, swapped) == ["порядок находок"]



def test_prep_sig_ignores_app_version_in_parts_but_not_their_content():
    """Предпросмотр, подготовленный до развёртывания новой сборки, не должен отказывать «изменилось после
    предпросмотра» из-за версии приложения в частях отметки."""
    def prep(parts):
        return {"kind": "SAST", "summary": "ID5 - A", "command_text": "T", "number_keys": ["sast:1"], "fingerprint": "",
                "targets": [{"hub_id": "1", "revision": 1, "sig": "s", "decision_hash": "d", "entered_parts": parts}]}
    old = '{"app": "0.9.26.dev1", "comment": "c", "defect": 1, "fix": "f", "team": "t"}'
    new = '{"app": "0.9.26.dev2", "comment": "c", "defect": 1, "fix": "f", "team": "t"}'
    other = '{"app": "0.9.26.dev2", "comment": "c2", "defect": 1, "fix": "f", "team": "t"}'
    assert hub_defects.update_prep_sig(prep(old)) == hub_defects.update_prep_sig(prep(new))
    assert hub_defects.update_prep_sig(prep(old)) != hub_defects.update_prep_sig(prep(other))
    assert hub_defects.prep_changes(prep(old), prep(new)) == []
    assert any("части отметки" in x for x in hub_defects.prep_changes(prep(old), prep(other)))
    assert hub_defects.parts_without_app("не JSON") == "не JSON"
    assert hub_defects.parts_without_app('{"comment": "c"}') == '{"comment": "c"}'


def test_preview_survives_new_app_version_and_put_is_queued(web, monkeypatch):
    """Предпросмотр подготовлен одной сборкой, «Push в Hub» нажато после развёртывания следующей – запись
    ставится, а не отказывает."""
    from app.routes import findings as card
    pid, row = ready(web)
    db = web.app.state.db
    to_preview(web, pid, row)
    monkeypatch.setattr(card, "__version__", "99.0.0")
    r = put_click(web, pid, row)
    assert r.status_code == 200, r.text
    assert phase(db, row["id"]) == "checking", note(db, row["id"])
    # до конца цепочки (ревью A): второе чтение, PUT, подтверждающее чтение, отметка без ложного «текст изменился»
    read_job(web)
    put = take(web)
    assert put is not None and put["method"] == "PUT", (put, note(db, row["id"]))
    deliver(web, put, 204, text="")
    read_job(web, sent_body(db, row["id"]))
    assert phase(db, row["id"]) == "done", note(db, row["id"])
    assert db.get_review(pid, "510001")["entered_hub"] == 1


def test_matching_sync_names_lines_below_the_text_and_unsent_draft(web):
    """Источник истины – Hub: строки ниже текста в описании Hub –
    часть принятого описания Hub, совпавшая сверка их расхождением не называет; неотправленный черновик – называет."""
    pid, row = ready(web, build=False)
    db = web.app.state.db
    body = hub_body(description=DESCRIPTION + "<p>Комментарий рецензента: замечание.</p>")
    assert act(web, pid, row["id"], "sync").status_code == 200
    read_job(web, body)
    # ADR-0132: новое в блоке показывается как правка и принимается при «Применить», принятое расхождением не называется
    state = json.loads(db.hub_defect(row["id"])["sync_json"])
    assert state["block_diff"] == ["+ Комментарий рецензента: замечание."], state
    assert apply_sync(web, pid, row["id"]).status_code == 200
    row = db.hub_defect(row["id"])
    assert act(web, pid, row["id"], "sync").status_code == 200
    read_job(web, body)
    state = json.loads(db.hub_defect(row["id"])["sync_json"])
    assert state["matches"] and state["extra_lines"] >= 3, state
    page = tab(web, pid)
    assert "Ниже текста в описании Hub ещё" not in page and "заменит описание текстом из приложения" not in page
    assert f'id="hub-sync-matches-{row["id"]}"' in page and "text-ok hub-sync-matches" in page
    assert "неотправленные изменения" not in page
    db.hub_defect_update(row["id"], draft_command_text=row["command_text"] + "\nПравка оператора.")
    page = tab(web, pid)  # предупреждение о черновике – в строке дефекта, не списком под таблицей (0.9.26.dev18)
    anchor = page.index(f'id="hub-sync-matches-{row["id"]}"')
    cell = page[anchor:page.index("</span>", anchor)]
    assert "в черновике неотправленные правки" in cell and "text-warn hub-sync-matches" in page[anchor - 200:anchor]
    assert anchor < page.index("</table>")


def test_unknown_put_then_old_description_with_same_text_is_not_success(web):
    """Ревью B1 31.10: PUT не дошёл, сверка вернула прежнее описание – тот же текст и хвост блока Hub; это не успех."""
    pid, row = ready(web)
    db = web.app.state.db
    put = to_put(web, pid, row)
    deliver(web, put, 0, error="TimeoutError")
    assert act(web, pid, row["id"], "update-verify").status_code == 200
    old = sent_body(db, row["id"])
    old["description"] = old["description"] + "\n" + BLOCK
    read_job(web, old)
    assert phase(db, row["id"]) != "done", note(db, row["id"])
    assert not db.get_review(pid, "510001")["entered_hub"]


def test_boundary_line_inside_operator_text_is_refused():
    """Ревью A2 31.10: строка «Информация об объекте сканирования:» в тексте – отказ, иначе чтение обрежет текст."""
    assembled, problem = hub_defects.update_description("Обоснование:\nИнформация об объекте сканирования:\nещё")
    assert assembled == "" and "Информация об объекте сканирования:" in problem
    ok, problem = hub_defects.update_description("Обоснование: Информация об объекте сканирования: в строке")
    assert problem == "" and ok

def test_card_refusal_falls_back_to_plain_refusal_when_card_cannot_be_built(web, monkeypatch):
    """Ревью 30.10: карточку не собрать (ValueError) – прежний отказ 409, а не ошибка 500."""
    from app.routes import defect_card_routes
    pid, row = ready(web)
    to_preview(web, pid, row)
    fields = form_fields(web, pid, f"hub-update-put-form-{row['id']}")
    save_sast(web, pid, "510001", "true_positive", "", REASON + " Уточнено.", FIX, defect_confirm="1")

    def broken(*args, **kwargs):
        raise ValueError("Владелец черновика не найден.")

    monkeypatch.setattr(defect_card_routes, "page_context", broken)
    r = web.client.post(f"/projects/{pid}/hub/defects/{row['id']}/update-put", headers=ORIGIN,
                        data={**fields, "back": "defect-card"})
    assert r.status_code == 409 and "изменилось:" in r.text


# ============================================================================ гонки во время второго чтения


def test_decision_changed_during_the_second_read_puts_nothing(web):
    pid, row = ready(web)
    db = web.app.state.db
    to_preview(web, pid, row)
    assert put_click(web, pid, row).status_code == 200
    save_sast(web, pid, "510001", "true_positive", "", REASON + " Уточнено.", FIX, defect_confirm="1")
    read_job(web)
    assert phase(db, row["id"]) == "stale" and "изменились после предпросмотра" in note(db, row["id"])
    assert not ops(db, "defect_update")


def test_finding_data_changed_during_the_second_read_puts_nothing(web, monkeypatch):
    pid, row = ready(web)
    db = web.app.state.db
    to_preview(web, pid, row)
    assert put_click(web, pid, row).status_code == 200
    from app.routes import hub_defect_routes
    real = hub_defect_routes.prepare_update

    def prepared_then_changed(request, current):  # данные находки меняются между подготовкой и транзакцией
        prep = real(request, current)
        with db._tx() as c:
            c.execute("UPDATE findings SET data_json = (data_json::jsonb || jsonb_build_object('snippet','другое'))::text WHERE project_id = ?"
                      " AND hub_id = '510001'", (pid,))
        return prep

    monkeypatch.setattr(hub_defect_routes, "prepare_update", prepared_then_changed)
    read_job(web)
    assert phase(db, row["id"]) == "stale" and "510001" in note(db, row["id"]), note(db, row["id"])
    assert not ops(db, "defect_update")


@pytest.mark.parametrize("change", ["hub_url", "app_id"])
def test_hub_address_or_application_changed_during_the_second_read(web, change):
    pid, row = ready(web)
    db = web.app.state.db
    to_preview(web, pid, row)
    assert put_click(web, pid, row).status_code == 200
    if change == "hub_url":
        db.set_settings({"hub_url": "https://other.example.org"})
    else:
        db.update_project(pid, hub_app_id=8)
    read_job(web)
    assert phase(db, row["id"]) == "stale" and "изменились" in note(db, row["id"]), note(db, row["id"])
    assert not ops(db, "defect_update")


def test_defect_changed_in_hub_after_preview_is_stale(web):
    pid, row = ready(web)
    db = web.app.state.db
    to_preview(web, pid, row)
    assert put_click(web, pid, row).status_code == 200
    read_job(web, hub_body(status="Closed", updateTs=1761690000000))
    assert phase(db, row["id"]) == "stale" and "status" in note(db, row["id"]) and "updateTs" not in note(db, row["id"])
    assert not ops(db, "defect_update")
    assert json.loads(db.hub_defect(row["id"])["import_json"])["read_at"], "наблюдаемый снимок – и у stale"
    # только updateTs другой – не изменение
    to_preview(web, pid, row)
    assert put_click(web, pid, row).status_code == 200
    read_job(web, hub_body(updateTs="2026-10-29T12:00:00Z"))
    assert phase(db, row["id"]) == "putting"


# ============================================================================ переходы (таблица п. 3)


def deliver_raw(web, job: dict, status: int = 200, text: str = "", error: str = "", not_sent: bool = False,
                truncated: bool = False) -> dict:
    r = web.client.post(f"/api/hub/jobs/{job['attempt_id']}/result", headers=worker_headers(web), content=json.dumps(
        {"lease_token": job["lease_token"], "worker_id": "w1", "status": status, "headers": {}, "body_text": text,
         "error": error, "not_sent": not_sent, "truncated": truncated}))
    assert r.status_code == 200, r.text
    return r.json()


def record_only(db, job: dict, status: int = 200, body: dict | None = None, text: str | None = None) -> None:
    """Результат записан, последствия – нет (сбой приложения сразу после записи; при перезапуске доставки нет)."""
    out = db.hub_result(job["attempt_id"], job["lease_token"], {
        "status": status, "headers": {}, "body_text": text if text is not None else json.dumps(body or {},
                                                                                              ensure_ascii=False)})
    assert out["outcome"] == "accepted", out


def expire(db) -> None:
    db.hub_expire_leases(now="2999-01-01T00:00:00+00:00")


@pytest.mark.parametrize("origin", ["app", "import"])
def test_cancel_preview_keeps_the_row_and_stale_tabs_are_refused(web, origin):
    pid, row = ready(web)
    db = web.app.state.db
    db.hub_defect_update(row["id"], origin=origin)
    keep = ("targets_json", "number", "summary", "command_text", "text_generation", "state", "import_json")
    to_preview(web, pid, row)
    before = db.hub_defect(row["id"])
    fields = form_fields(web, pid, f"hub-update-cancel-form-{row['id']}")
    assert set(fields) == {"generation", "shown"} and fields["generation"] == "1"
    assert act(web, pid, row["id"], "update-cancel", fields).status_code == 200
    after = db.hub_defect(row["id"])
    assert phase(db, row["id"]) == "cancelled" and {k: after[k] for k in keep} == {k: before[k] for k in keep}
    page = tab(web, pid)
    assert "Подготовка обновления отменена" in page and f'id="hub-update-form-{row["id"]}"' in page
    assert not ops(db, "defect_update")
    # из устаревшей вкладки: второе чтение нового поколения уже идёт – отказ, ничего не меняется
    to_preview(web, pid, row)
    stale = form_fields(web, pid, f"hub-update-cancel-form-{row['id']}")
    put_stale = form_fields(web, pid, f"hub-update-put-form-{row['id']}")
    assert stale["generation"] == "2"
    assert put_click(web, pid, row).status_code == 200
    for action, data in (("update-cancel", stale), ("update-put", put_stale)):
        r = act(web, pid, row["id"], action, data)
        assert r.status_code == 409 and "обновите страницу" in r.json()["detail"], r.text
    assert phase(db, row["id"]) == "checking"
    read_job(web, hub_body(status="Closed"))  # stale
    to_preview(web, pid, row)
    r = act(web, pid, row["id"], "update-cancel", stale)  # прежнее поколение
    assert r.status_code == 409 and phase(db, row["id"]) == "preview"


@pytest.mark.parametrize("status,text,body,words", [
    (404, "{}", None, "нет в Hub (404)"),
    (500, "{}", None, "чтение не удалось"),
    (200, "не JSON", None, "не разобран"),
    (200, None, "other_id", "другой дефект"),
    (200, None, "other_app", "не из приложения"),
    (200, None, "no_list", "состав не прочитан"),
])
def test_first_read_failures_are_read_failed(web, status, text, body, words):
    pid, row = ready(web)
    db = web.app.state.db
    assert act(web, pid, row["id"], "update").status_code == 200
    payload = {"other_id": {**hub_body(), "id": 778}, "other_app": {**hub_body(), "appId": 8},
               "no_list": {k: v for k, v in hub_body().items() if k != "linkedIssues"}}.get(body)
    read_job(web, payload, status=status, text=text)
    assert phase(db, row["id"]) == "read_failed" and words in note(db, row["id"]), note(db, row["id"])
    assert json.loads(db.hub_defect(row["id"])["import_json"])["summary"] == OLD_SUMMARY, "ошибка – не наблюдаемое"
    page = tab(web, pid)
    assert "Обновление не подготовлено" in page and f'id="hub-update-form-{row["id"]}"' in page


def test_second_and_confirming_read_failures_and_reread(web):
    pid, row = ready(web)
    db = web.app.state.db
    to_preview(web, pid, row)
    assert put_click(web, pid, row).status_code == 200
    read_job(web, status=500)
    assert phase(db, row["id"]) == "preview" and "второе чтение не удалось" in note(db, row["id"])
    assert f'id="hub-update-put-form-{row["id"]}"' in tab(web, pid)
    put = to_put_from_preview(web, pid, row)
    deliver(web, put, 204, text="")
    read_job(web, {**hub_body(), "id": 778})  # подтверждающее чтение вернуло чужой дефект
    assert phase(db, row["id"]) == "confirming" and "другой дефект" in note(db, row["id"])
    assert db.hub_defect(row["id"])["update_op_id"] is None
    page = tab(web, pid)
    assert f'id="hub-update-reread-form-{row["id"]}"' in page and "Повторить чтение" in page
    assert f'id="hub-update-form-{row["id"]}"' not in page and f'id="hub-sync-form-{row["id"]}"' not in page
    assert act(web, pid, row["id"], "update").status_code == 409
    assert act(web, pid, row["id"], "update-reread").status_code == 200
    read_job(web, sent_body(db, row["id"]))
    assert phase(db, row["id"]) == "done" and len(ops(db, "defect_update")) == 1


@pytest.mark.parametrize("status,error,not_sent,truncated,want,words", [
    (400, "", False, False, "failed", "Hub не принял"),
    (409, "", False, False, "failed", "Hub не принял"),
    (0, "задание отклонено исполнителем: метод PUT не разрешён", True, False, "failed", "обновите исполнитель в ВМ"),
    (0, "задание отклонено исполнителем: задание для другого адреса Hub", True, False, "failed", "другого адреса"),
    (500, "", False, False, "unknown", "кодом 500"),
    (302, "", False, False, "unknown", "кодом 302"),
    (0, "TimeoutError: timed out", False, False, "unknown", "timed out"),
    (204, "", False, True, "unknown", "усечён"),
])
def test_put_outcomes(web, status, error, not_sent, truncated, want, words):
    pid, row = ready(web)
    db = web.app.state.db
    put = to_put(web, pid, row)
    deliver_raw(web, put, status=status, error=error, not_sent=not_sent, truncated=truncated)
    assert phase(db, row["id"]) == want and words in note(db, row["id"]), note(db, row["id"])
    op = ops(db, "defect_update")[0]
    assert op["state"] == ("failed" if want == "failed" else "unknown"), "прежний исполнитель – failed, не unknown"
    assert take(web) is None, "ни подтверждающего чтения, ни повтора PUT"
    page = tab(web, pid)
    if want == "unknown":
        assert f'id="hub-update-verify-form-{row["id"]}"' in page and f'id="hub-update-form-{row["id"]}"' not in page
        assert act(web, pid, row["id"], "update").status_code == 409
    else:
        assert f'id="hub-update-verify-form-{row["id"]}"' not in page and f'id="hub-update-form-{row["id"]}"' in page
    assert db.get_review(pid, "510001")["entered_hub"] == 0


@pytest.mark.parametrize("origin", ["app", "import"])
def test_put_cancelled_before_issue_is_not_sent(web, origin):
    pid, row = ready(web)
    db = web.app.state.db
    db.hub_defect_update(row["id"], origin=origin)
    to_preview(web, pid, row)
    assert put_click(web, pid, row).status_code == 200
    read_job(web)
    put_op = ops(db, "defect_update")[0]
    assert put_op["state"] == "queued" and db.hub_cancel(put_op["id"])
    page = tab(web, pid)
    assert phase(db, row["id"]) == "failed" and "отменён до выдачи исполнителю" in note(db, row["id"])
    assert db.hub_op(put_op["id"])["state"] == "cancelled"
    assert f'id="hub-update-verify-form-{row["id"]}"' not in page and f'id="hub-update-form-{row["id"]}"' in page
    assert take(web) is None
    # новая попытка – новое поколение и новый ключ
    put = to_put(web, pid, row)
    assert put["op_id"] != put_op["id"]


def test_lease_expiry_per_step(web):
    """Аренда истекла без ответа исполнителя: чтение – операция failed, фаза по шагу (read_failed, preview,
    confirming, у «Сверить» – unknown); PUT – операция и фаза unknown, поздний ответ ничего не меняет."""
    pid, row = ready(web)
    db = web.app.state.db
    assert act(web, pid, row["id"], "update").status_code == 200
    first = take(web)
    expire(db)
    tab(web, pid)
    assert phase(db, row["id"]) == "read_failed" and db.hub_op(first["op_id"])["state"] == "failed"
    to_preview(web, pid, row)
    assert put_click(web, pid, row).status_code == 200
    take(web)
    expire(db)
    tab(web, pid)
    assert phase(db, row["id"]) == "preview" and "второе чтение не удалось" in note(db, row["id"])
    put = to_put_from_preview(web, pid, row)
    expire(db)
    tab(web, pid)
    assert phase(db, row["id"]) == "unknown" and db.hub_op(put["op_id"])["state"] == "unknown"
    assert deliver(web, put, 204, text="")["outcome"] == "late"
    assert phase(db, row["id"]) == "unknown" and take(web) is None
    assert act(web, pid, row["id"], "update-verify").status_code == 200
    verify = take(web)
    expire(db)
    tab(web, pid)
    assert phase(db, row["id"]) == "unknown" and db.hub_op(put["op_id"])["state"] == "unknown"
    assert db.hub_op(verify["op_id"])["state"] == "failed"
    assert act(web, pid, row["id"], "update-verify").status_code == 200
    read_job(web, sent_body(db, row["id"]))
    assert phase(db, row["id"]) == "done" and db.hub_op(put["op_id"])["state"] == "done"
    # подтверждающее чтение с истёкшей арендой – confirming
    put = to_put(web, pid, row)
    deliver(web, put, 204, text="")
    take(web)
    expire(db)
    tab(web, pid)
    assert phase(db, row["id"]) == "confirming" and db.hub_defect(row["id"])["update_op_id"] is None


def test_answers_recorded_without_effects_are_finished_on_view(web):
    """Перезапуск без повторной доставки: ответ каждого шага записан, а последствия – нет; показ вкладки доводит шаг
    (подготовка – по текущим решениям запроса вкладки)."""
    pid, row = ready(web)
    db = web.app.state.db
    assert act(web, pid, row["id"], "update").status_code == 200
    record_only(db, take(web), body=hub_body())
    assert phase(db, row["id"]) == "reading"
    tab(web, pid)
    assert phase(db, row["id"]) == "preview"
    assert put_click(web, pid, row).status_code == 200
    record_only(db, take(web), body=hub_body())
    assert phase(db, row["id"]) == "checking"
    tab(web, pid)
    assert phase(db, row["id"]) == "putting"
    put = take(web)
    record_only(db, put, 204, text="")
    tab(web, pid)
    assert phase(db, row["id"]) == "confirming"
    record_only(db, take(web), body=sent_body(db, row["id"]))
    tab(web, pid)
    assert phase(db, row["id"]) == "done" and db.get_review(pid, "510001")["entered_hub"] == 1


def test_repeated_late_and_old_generation_deliveries_change_nothing(web):
    pid, row = ready(web)
    db = web.app.state.db
    assert act(web, pid, row["id"], "update").status_code == 200
    first = read_job(web)
    snapshot = db.hub_defect(row["id"])["update_json"]
    assert deliver(web, first, body=hub_body(summary="ID5 - другое (SAST)"))["outcome"] == "duplicate"
    assert db.hub_defect(row["id"])["update_json"] == snapshot
    assert put_click(web, pid, row).status_code == 200
    second = read_job(web)
    assert deliver(web, second, body=hub_body())["outcome"] == "duplicate"
    assert len(ops(db, "defect_update")) == 1, "повторная доставка второго чтения – один PUT"
    put = take(web)
    deliver(web, put, 204, text="")
    assert deliver(web, put, 204, text="")["outcome"] == "duplicate"
    confirm = read_job(web, sent_body(db, row["id"]))
    assert take(web) is None, "повторная доставка PUT – одно подтверждающее чтение"
    done = db.hub_defect(row["id"])
    assert deliver(web, confirm, body=hub_body())["outcome"] == "duplicate"
    after = db.hub_defect(row["id"])
    assert after["update_json"] == done["update_json"] and after["text_generation"] == 1
    # ответ прежнего поколения, доставленный поздно, – без изменений
    assert act(web, pid, row["id"], "update").status_code == 200
    old = take(web)
    expire(db)
    tab(web, pid)
    assert act(web, pid, row["id"], "update").status_code == 200
    state = db.hub_defect(row["id"])["update_json"]
    assert deliver(web, old, body=hub_body())["outcome"] == "late"
    assert db.hub_defect(row["id"])["update_json"] == state and phase(db, row["id"]) == "reading"


def test_new_attempt_after_a_done_put_gets_a_new_key(web):
    pid, row = ready(web)
    db = web.app.state.db
    to_done(web, pid, row)
    to_done(web, pid, row)
    puts = ops(db, "defect_update")
    assert len(puts) == 2 and all(o["state"] == "done" for o in puts) and puts[0]["op_key"] != puts[1]["op_key"]
    fresh = db.hub_defect(row["id"])
    assert fresh["text_generation"] == 2 and hub_defects.update_state(fresh)["confirmed"]["generation"] == 2


def test_confirming_read_with_old_content_is_unconfirmed_without_marks(web):
    pid, row = ready(web)
    db = web.app.state.db
    put = to_put(web, pid, row)
    deliver(web, put, 204, text="")
    read_job(web, hub_body())  # прежнее содержимое
    fresh = db.hub_defect(row["id"])
    assert phase(db, row["id"]) == "unconfirmed" and fresh["text_generation"] == 0 and fresh["summary"] == OLD_SUMMARY
    assert db.hub_op(put["op_id"])["state"] == "done", "транспортный успех PUT не переписывается"
    assert db.get_review(pid, "510001")["entered_hub"] == 0 and db.defect_number(pid, "sast:510001") is None
    page = tab(web, pid)
    assert "чтение не подтвердило отправленное содержимое" in page
    assert f'id="hub-update-reread-form-{row["id"]}"' in page and f'id="hub-update-form-{row["id"]}"' in page
    assert act(web, pid, row["id"], "update-reread").status_code == 200
    read_job(web, sent_body(db, row["id"]))
    assert phase(db, row["id"]) == "done" and db.get_review(pid, "510001")["entered_hub"] == 1


@pytest.mark.parametrize("seen,want", [("new", "done"), ("old", "observed_old"), ("other", "unclear"),
                                       # прежний текст, но другие поля объекта второго чтения – не «прежнее» (C3)
                                       ("old_priority", "unclear"), ("old_links", "unclear")])
@pytest.mark.parametrize("origin", ["app", "import"])
def test_verify_after_unknown_put(web, seen, want, origin):
    pid, row = ready(web)
    db = web.app.state.db
    db.hub_defect_update(row["id"], origin=origin)
    put = to_put(web, pid, row)
    deliver_raw(web, put, status=503)
    assert phase(db, row["id"]) == "unknown"
    assert act(web, pid, row["id"], "update-verify").status_code == 200
    page = tab(web, pid)
    assert "Сверяю с Hub" in page and f'id="hub-update-verify-form-{row["id"]}"' not in page
    body = {"new": sent_body(db, row["id"]), "old": hub_body(updateTs=1761700000001),
            "other": hub_body(summary="ID5 - правка в Hub (SAST)"), "old_priority": hub_body(priorityId=5),
            "old_links": hub_body(links=((510001, "SAST"), (599999, "SAST")))}[seen]
    read_job(web, body)
    assert phase(db, row["id"]) == want
    if seen == "old_priority":
        assert "priorityId" in note(db, row["id"]) and "priorityId" in tab(web, pid)
    if seen == "old_links":
        assert "linkedIssues" in note(db, row["id"])
    assert db.hub_op(put["op_id"])["state"] == ("done" if want == "done" else "failed")
    assert (db.get_review(pid, "510001")["entered_hub"] == 1) is (want == "done")
    observed = json.loads(db.hub_defect(row["id"])["import_json"])
    assert observed["summary"] == body["summary"], "наблюдаемый снимок – из чтения «Сверить»"
    page = tab(web, pid)
    assert f'id="hub-update-verify-form-{row["id"]}"' not in page
    if want != "done":
        assert f'id="hub-update-form-{row["id"]}"' in page


@pytest.mark.parametrize("origin", ["app", "import"])
def test_verify_read_failure_keeps_unknown(web, origin):
    pid, row = ready(web)
    db = web.app.state.db
    db.hub_defect_update(row["id"], origin=origin)
    put = to_put(web, pid, row)
    deliver_raw(web, put, status=0, error="ConnectionResetError: обрыв")
    assert act(web, pid, row["id"], "update-verify").status_code == 200
    read_job(web, {**hub_body(), "appId": 8})
    assert phase(db, row["id"]) == "unknown" and "сверка не удалась" in note(db, row["id"])
    assert db.hub_op(put["op_id"])["state"] == "unknown"
    assert f'id="hub-update-verify-form-{row["id"]}"' in tab(web, pid)


def test_confirming_read_with_other_fields_changed_is_done_diff(web):
    pid, row = ready(web)
    db = web.app.state.db
    put = to_put(web, pid, row)
    deliver(web, put, 204, text="")
    read_job(web, sent_body(db, row["id"], status="Closed"))
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "done_diff" and state["diff"] == ["status"]
    assert db.get_review(pid, "510001")["entered_hub"] == 1 and db.defect_number(pid, "sast:510001") == 5
    assert "отличаются и другие поля (status)" in tab(web, pid)


# ============================================================================ успех и последствия (п. 4)


def test_crash_after_success_before_marks_is_finished_on_view(web, monkeypatch):
    pid, row = ready(web)
    db = web.app.state.db
    put = to_put(web, pid, row)
    deliver(web, put, 204, text="")

    def crash(*args, **kwargs):
        raise RuntimeError("сбой после записи итога")

    monkeypatch.setattr(hub_defects, "_apply_effects", crash)
    read_job(web, sent_body(db, row["id"]))  # приём результата не падает: сбой последствий – не 500
    monkeypatch.undo()
    fresh = db.hub_defect(row["id"])
    assert phase(db, row["id"]) == "done" and fresh["effects_done"] == 0 and fresh["text_generation"] == 1
    assert db.get_review(pid, "510001")["entered_hub"] == 0 and db.defect_number(pid, "sast:510001") is None
    tab(web, pid)  # показ вкладки доводит последствия
    fresh = db.hub_defect(row["id"])
    assert fresh["effects_done"] == 1 and db.get_review(pid, "510001")["entered_hub"] == 1
    assert db.defect_number(pid, "sast:510001") == 5


def test_first_import_gets_no_marks_even_when_effects_are_finished(web):
    pid, row = ready(web)
    db = web.app.state.db
    db.hub_defect_update(row["id"], effects_done=0)  # недоведённые последствия у первичного занесения
    tab(web, pid)
    fresh = db.hub_defect(row["id"])
    assert fresh["effects_done"] == 1 and fresh["text_generation"] == 0
    assert db.get_review(pid, "510001")["entered_hub"] == 0 and db.defect_number(pid, "sast:510001") is None


def pair_ready(web) -> tuple[int, dict, str]:
    """Две находки одной группы (510001, 510005) с одинаковым решением; занесён дефект №777 (ID5) с 510001."""
    pid = pair_project(web)
    db = web.app.state.db
    save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    row = imported(web, pid, "777", hub_body())
    assemble(web, pid, row)
    sibling = f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510005')['id']}"
    return pid, row, sibling


def test_crash_between_marks_is_finished_and_earlier_mark_kept(web, monkeypatch):
    pid = pair_project(web)
    db = web.app.state.db
    save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    row = imported(web, pid, "777", hub_body(links=((510001, "SAST"), (510005, "SAST"))))
    assemble(web, pid, row)
    put = to_put(web, pid, row, first=hub_body(links=((510001, "SAST"), (510005, "SAST"))))
    deliver(web, put, 204, text="")
    real, calls = db.mark_entered, []

    def second_fails(*args, **kwargs):
        calls.append(args)
        if len(calls) == 2:
            raise RuntimeError("сбой между отметками")
        return real(*args, **kwargs)

    monkeypatch.setattr(db, "mark_entered", second_fails)
    read_job(web, sent_body(db, row["id"], linkedIssues=[{"id": 510001, "type": "SAST"}, {"id": 510005, "type": "SAST"}]))
    monkeypatch.undo()
    marked = [db.get_review(pid, h)["entered_hub"] for h in ("510001", "510005")]
    assert sorted(marked) == [0, 1] and db.hub_defect(row["id"])["effects_done"] == 0
    first_at = next(db.get_review(pid, h)["entered_hub_at"] for h in ("510001", "510005")
                    if db.get_review(pid, h)["entered_hub"])
    tab(web, pid)
    assert [db.get_review(pid, h)["entered_hub"] for h in ("510001", "510005")] == [1, 1]
    assert first_at in [db.get_review(pid, h)["entered_hub_at"] for h in ("510001", "510005")]


def test_new_revision_and_later_manual_mark_are_not_overwritten(web, monkeypatch):
    pid, row = ready(web)
    db = web.app.state.db
    put = to_put(web, pid, row)
    save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)  # то же решение заново: новая редакция
    deliver(web, put, 204, text="")
    read_job(web, sent_body(db, row["id"]))
    assert phase(db, row["id"]) == "done"
    marked = db.get_review(pid, "510001")  # отметка – по подтверждённому составу, с текущей редакцией (01.11)
    assert marked["entered_hub"] == 1 and json.loads(db.hub_defect(row["id"])["targets_json"])[0]["revision"] == marked["revision"]
    assert db.defect_number(pid, "sast:510001") == 5
    # более поздняя ручная отметка той же редакции другим текстом – не перетирается доводкой последствий
    put2 = to_put(web, pid, row)
    deliver(web, put2, 204, text="")
    monkeypatch.setattr(hub_defects, "_apply_effects", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("сбой")))
    read_job(web, sent_body(db, row["id"]))
    monkeypatch.undo()
    revision = db.get_review(pid, "510001")["revision"]
    db.mark_entered(pid, "510001", True, revision=revision, entered_hash="ручной-текст")
    tab(web, pid)
    assert db.hub_defect(row["id"])["effects_done"] == 1
    assert db.get_review(pid, "510001")["entered_text_hash"] == "ручной-текст"


# ============================================================================ привязка к занесённому после обновления


def link_item(pid: int, targets: list[dict]) -> dict:
    return dict(purpose="defect_link", request=hub_defects.link_request("777", targets, None),
                hub_url="https://hub.example.org", app_id=7, project_id=pid, targets=targets)


SIBLING_TARGETS = [{"hub_id": "510005", "issue_id": 510005, "issue_type": "SAST", "revision": 1, "entered_hash": "h",
                    "entered_parts": "", "sig": "s"}]


def test_imported_defect_is_never_linked_from_the_app(web):
    """Вариант A (ADR-0125 п. 4): к занесённому дефекту «Привязать» не предлагается ни до, ни после успешного
    обновления; «Создать дефект» у соседа – отказ по членству в группе; транзакция привязки к занесённому
    родителю отказывает; в строке – разбор подтверждающего чтения."""
    pid, row, sibling = pair_ready(web)
    db = web.app.state.db
    for when in ("до обновления", "после обновления"):
        if when == "после обновления":
            done = to_done(web, pid, row)
            assert done["command_text"] == json.loads(done["import_json"])["command_text"]
        card = web.client.get(sibling).text
        assert 'id="hub-defect-link-button"' not in card, when
        r = blank_from(web, sibling)
        assert r.status_code == 400 and "занесён из Hub" in r.json()["detail"], (when, r.text)
        assert "Pull из Hub" in r.json()["detail"]
    fresh = db.hub_defect(row["id"])
    with pytest.raises(ValueError, match="занесён из Hub"):
        db.hub_defect_link_start(pid, row["id"], "777", item=link_item(pid, SIBLING_TARGETS),
                                 body_hash=text_hash(fresh["command_text"]), kind="SAST", number=5,
                                 summary=fresh["summary"], anchor_hub_id="510005", targets=SIBLING_TARGETS,
                                 number_keys=["sast:510005"], command_text=fresh["command_text"],
                                 hub_url="https://hub.example.org", app_id=7)
    assert not [r for r in db.hub_defects(pid) if r["state"] == "linking"] and take(web) is None


# ============================================================================ SCA


SCA_OLD = "ID3 - example-parser 1.4.2 (SCA)"


def sca_ready(web, links=((73001, "SCA_S"), (73002, "SCA_S"))) -> tuple[int, dict, str]:
    """Решение «Обновить» по набору example-parser 1.4.2 (73001, 73002), текст набора готов; занесён дефект №777
    (ID3)."""
    from test_sca import sca_text_ready
    from test_sca_package_decision import UPD, post_package
    pid = prepared(web)
    hub_settings(web, pid)
    db = web.app.state.db
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    url = f"/projects/{pid}/sca/findings/{db.get_finding_by_hub_id(pid, '73001')['id']}"
    sca_text_ready(web, url)
    row = imported(web, pid, "777", hub_body(links=links, summary=SCA_OLD))
    assert row["kind"] == "SCA" and row["number"] == 3
    assemble(web, pid, row)
    return pid, web.app.state.db.hub_defect(row["id"]), url


def test_sca_set_defect_update_chain(web):
    from app import defect
    from app.models import Finding
    from app.routes import sca as sca_card
    pid, row, url = sca_ready(web)
    db = web.app.state.db
    sca_links = ((73001, "SCA_S"), (73002, "SCA_S"))
    put = to_put(web, pid, row, first=hub_body(links=sca_links, summary=SCA_OLD))
    assert put["body"]["summary"] == defect.sca_title(3, "example-parser", "1.4.2")
    deliver(web, put, 204, text="")
    read_job(web, sent_body(db, row["id"], linkedIssues=[{"id": 73001, "type": "SCA_S"},
                                                         {"id": 73002, "type": "SCA_S"}]))
    done = db.hub_defect(row["id"])
    assert phase(db, row["id"]) == "done", note(db, row["id"])
    targets = json.loads(done["targets_json"])
    assert sorted(t["hub_id"] for t in targets) == ["73001", "73002"]
    assert len({t["entered_hash"] for t in targets}) == 1 and targets[0]["entered_hash"]
    assert all(db.get_review(pid, h)["entered_hub"] == 1 for h in ("73001", "73002"))
    parser = Finding.from_dict(db.get_finding_by_hub_id(pid, "73001")["data"])
    assert db.defect_number(pid, sca_card.set_key(parser, 0)) == 3
    # C2: текст набора кончается переводом строки, разбор чтения – нет; в строке – разбор (вариант A)
    generated = hub_defects.update_state(done)["new"]["command_text"]
    assert generated.endswith("\n") and generated != done["command_text"]
    assert done["command_text"] == json.loads(done["import_json"])["command_text"]
    # сверка с тем же содержимым Hub текст изменённым не считает (сравниваются одинаковые представления)
    assert act(web, pid, row["id"], "sync").status_code == 200
    read_job(web, sent_body(db, row["id"], linkedIssues=[{"id": 73001, "type": "SCA_S"},
                                                         {"id": 73002, "type": "SCA_S"}]))
    sync_state = json.loads(db.hub_defect(row["id"])["sync_json"])
    assert sync_state["matches"] and "read" not in sync_state


@pytest.mark.parametrize("links,words", [
    (((73001, "SCA_S"),), "в наборе, но не в дефекте: 73002"),
    (((73001, "SCA_S"), (73003, "SCA_S")), "разных версий"),
])
def test_sca_refusals_members_and_versions(web, links, words):
    pid, row, url = sca_ready(web, links=links)
    db = web.app.state.db
    if words == "разных версий":
        r = act(web, pid, row["id"], "update")
        assert r.status_code == 409 and "конфликты" in r.json()["detail"]
        assert not ops(db, "defect_update")
    else:
        to_preview(web, pid, row, hub_body(links=links, summary=SCA_OLD))
        assert phase(db, row["id"]) == "refused" and words in note(db, row["id"]), note(db, row["id"])


def test_sca_set_text_changed_during_the_second_read_puts_nothing(web, monkeypatch):
    from app.routes import hub_defect_routes
    sca_links = ((73001, "SCA_S"), (73002, "SCA_S"))
    pid, row, url = sca_ready(web)
    db = web.app.state.db
    to_preview(web, pid, row, hub_body(links=sca_links, summary=SCA_OLD))
    assert phase(db, row["id"]) == "preview", note(db, row["id"])
    assert put_click(web, pid, row).status_code == 200
    real = hub_defect_routes.prepare_update
    before = db.sca_defect_fingerprint(pid, "73001")

    def prepared_then_changed(request, current):  # текст набора меняется между подготовкой и транзакцией постановки
        prep = real(request, current)
        with db._tx() as c:
            c.execute("UPDATE sca_package_texts SET recommendation_note = recommendation_note || ' Уточнено.'"
                      " WHERE project_id = ?",
                      (pid,))
        return prep

    monkeypatch.setattr(hub_defect_routes, "prepare_update", prepared_then_changed)
    read_job(web, hub_body(links=sca_links, summary=SCA_OLD))
    monkeypatch.undo()
    assert db.sca_defect_fingerprint(pid, "73001") != before
    assert phase(db, row["id"]) == "stale" and "Набор SCA изменился" in note(db, row["id"]), note(db, row["id"])
    assert not ops(db, "defect_update")


# ============================================================================ перезапуск приложения


def app_session(tmp_path, monkeypatch):
    """Экземпляр приложения на папке данных tmp_path/data – как фикстура web, но открывается заново (перезапуск)."""
    from contextlib import contextmanager
    from types import SimpleNamespace

    from fastapi.testclient import TestClient

    from app import metrics
    from app.config import Settings
    from app.main import create_app
    from fake_ollama import FakeOllama
    from test_web import BASE, GPU, write_repos

    @contextmanager
    def session():
        monkeypatch.setattr(metrics, "gpu_stats", lambda: dict(GPU))
        fake = FakeOllama(loaded=["qwen2.5-coder:14b"])
        if not (tmp_path / "repos").exists():
            write_repos(tmp_path / "repos")
        settings = Settings(data_dir=tmp_path / "data", repos_root=tmp_path / "repos", ollama_url=fake.url,
                            max_upload_mb=1, team_name="Тестовая команда", osv_url="")
        try:
            app = create_app(settings)
            with TestClient(app, base_url=BASE) as client:
                yield SimpleNamespace(client=client, app=app, fake=fake, settings=settings, tmp=tmp_path)
        finally:
            fake.close()
    return session()


def test_update_state_survives_a_restart(tmp_path, monkeypatch):
    """Перезапуск: итог успешного обновления и фаза unconfirmed – из базы; привязки к занесённому нет (вариант A)."""
    with app_session(tmp_path, monkeypatch) as first:
        pid, row, sibling = pair_ready(first)
        to_done(first, pid, row)
    with app_session(tmp_path, monkeypatch) as second:
        db = second.app.state.db
        assert phase(db, row["id"]) == "done" and "Обновлено в Hub" in tab(second, pid)
        assert 'id="hub-defect-link-button"' not in second.client.get(sibling).text
        put = to_put(second, pid, row)
        deliver(second, put, 204, text="")
        read_job(second, hub_body(summary="ID5 - правка в Hub (SAST)"))  # чтение C: иное содержимое
        assert phase(db, row["id"]) == "unconfirmed"
    with app_session(tmp_path, monkeypatch) as third:
        assert "чтение не подтвердило отправленное содержимое" in tab(third, pid)
        assert 'id="hub-defect-link-button"' not in third.client.get(sibling).text


# ============================================================================ дополнительно: фазы, номер, отбор


def test_sync_apply_is_refused_while_the_put_result_is_unknown(web):
    pid, row = ready(web)
    db = web.app.state.db
    assert act(web, pid, row["id"], "sync").status_code == 200
    read_job(web, hub_body(links=((510001, "SAST"), (510003, "SAST"))))
    stale_sync = db.hub_defect(row["id"])["sync_json"]
    shown = form_fields(web, pid, f"hub-sync-cancel-form-{row['id']}")["shown"]
    assert act(web, pid, row["id"], "sync-cancel", {"shown": shown}).status_code == 200
    put = to_put(web, pid, row)
    deliver_raw(web, put, status=502)
    assert phase(db, row["id"]) == "unknown" and db.hub_defect(row["id"])["update_op_id"] is None
    db.hub_defect_update(row["id"], sync_json=stale_sync)  # предпросмотр сверки из другой вкладки
    before = db.hub_defect(row["id"])
    r = act(web, pid, row["id"], "sync-apply", {"shown": text_hash(stale_sync)})
    assert r.status_code == 409 and "«Push в Hub»" in r.json()["detail"], r.text
    assert db.hub_defect(row["id"])["targets_json"] == before["targets_json"]
    assert act(web, pid, row["id"], "sync").status_code == 409


def test_unreviewed_target_is_refused(web):
    pid, row = ready(web)
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE reviews SET reviewed = 0 WHERE project_id = ? AND hub_id = '510001'", (pid,))
    to_preview(web, pid, row)
    assert phase(db, row["id"]) == "refused" and "«Проверено»" in note(db, row["id"])


def test_extra_text_in_hub_description_is_replaced_not_refused(web):
    """Чужой комментарий в описании Hub ниже «Информации об объекте сканирования» запись не сохраняет:
    описание заменяется текстом из приложения целиком; склеенный блок – не причина отказа."""
    pid, row = ready(web)
    db = web.app.state.db
    glued = "<div><p>Старый текст.</p>" + BLOCK + "<p>Комментарий рецензента: старый шаблон.</p></div>"
    to_preview(web, pid, row, hub_body(description=glued))
    state = hub_defects.update_state(db.hub_defect(row["id"]))
    assert state["phase"] == "preview", note(db, row["id"])
    assert state["candidate"]["description"] == hub_defects.command_html(state["new"]["command_text"])
    assert "Комментарий рецензента" not in state["candidate"]["description"]


def test_sca_extra_member_of_the_defect_is_refused(web, monkeypatch):
    """Находка дефекта, которой нет среди участников готового набора (набор изменили после занесения), – отказ с
    разницей: «в дефекте, но не в наборе»."""
    from app.routes import sca as sca_card
    sca_links = ((73001, "SCA_S"), (73002, "SCA_S"))
    pid, row, url = sca_ready(web)
    db = web.app.state.db
    real = sca_card.sca_defect

    def without_73002(*args, **kwargs):
        view = real(*args, **kwargs)
        return {**view, "members": [m for m in view.get("members") or [] if m != "73002"]}

    monkeypatch.setattr(sca_card, "sca_defect", without_73002)
    to_preview(web, pid, row, hub_body(links=sca_links, summary=SCA_OLD))
    assert phase(db, row["id"]) == "refused" and "в дефекте, но не в наборе: 73002" in note(db, row["id"]), note(
        db, row["id"])


@pytest.mark.parametrize("taken", ["other_key", "other_row", "own_key"])
def test_each_number_check_repeats_in_the_put_transaction(web, taken):
    pid, row = ready(web)
    db = web.app.state.db
    to_preview(web, pid, row)
    assert put_click(web, pid, row).status_code == 200
    if taken == "other_key":
        db.set_defect_number(pid, "sast:510003", 5)
    elif taken == "other_row":
        app_row(db, pid, number=5, defect_id="556")
    else:
        db.set_defect_number(pid, "sast:510001", 9)
    read_job(web)
    words = {"other_key": "sast:510003", "other_row": "занят", "own_key": "у ключа sast:510001 уже номер ID9"}[taken]
    assert phase(db, row["id"]) == "stale" and words in note(db, row["id"]), note(db, row["id"])
    assert not ops(db, "defect_update")


@pytest.mark.parametrize("origin", ["app", "import"])
def test_reads_cancelled_before_issue_follow_the_step_rules(web, origin):
    """Чтение шага, отменённое до выдачи исполнителю (hub_cancel – только операция в очереди), закрыто без ответа:
    показ вкладки даёт «ошибку чтения» своего шага – read_failed, preview, confirming; у «Сверить» – unknown."""
    pid, row = ready(web)
    db = web.app.state.db
    db.hub_defect_update(row["id"], origin=origin)

    def cancel_current() -> None:
        op_id = db.hub_defect(row["id"])["update_op_id"]
        assert op_id and db.hub_cancel(op_id)
        tab(web, pid)

    assert act(web, pid, row["id"], "update").status_code == 200
    cancel_current()
    assert phase(db, row["id"]) == "read_failed"
    to_preview(web, pid, row)
    assert put_click(web, pid, row).status_code == 200
    cancel_current()
    assert phase(db, row["id"]) == "preview" and "второе чтение не удалось" in note(db, row["id"])
    put = to_put_from_preview(web, pid, row)
    deliver(web, put, 204, text="")
    cancel_current()
    assert phase(db, row["id"]) == "confirming" and db.hub_defect(row["id"])["update_op_id"] is None
    assert act(web, pid, row["id"], "update-reread").status_code == 200
    read_job(web, sent_body(db, row["id"]))
    put = to_put(web, pid, row)
    deliver_raw(web, put, status=504)
    assert act(web, pid, row["id"], "update-verify").status_code == 200
    cancel_current()
    assert phase(db, row["id"]) == "unknown" and db.hub_op(put["op_id"])["state"] == "unknown"


# ============================================================================ круг 1 ревью


def to_unconfirmed(web, pid: int, row: dict) -> dict:
    """PUT выполнен, подтверждающее чтение показало прежний текст – фаза unconfirmed."""
    db = web.app.state.db
    put = to_put(web, pid, row)
    deliver(web, put, 204, text="")
    read_job(web, hub_body())
    assert phase(db, row["id"]) == "unconfirmed"
    return put


@pytest.mark.parametrize("then", ["reread", "prepare"])
def test_unconfirmed_refuses_sync_and_apply(web, then):
    """C1: в фазе unconfirmed «Pull из Hub» и «Применить» сверки отказывают («сначала «Повторить чтение» или
    «Подготовить обновление»»), кнопки сверки нет; «Подготовить обновление» доступна, «Повторить чтение» с отправленным
    текстом – успех, цели те же."""
    pid, row = ready(web)
    db = web.app.state.db
    assert act(web, pid, row["id"], "sync").status_code == 200  # предпросмотр сверки другой вкладки – заранее
    read_job(web, hub_body(links=((510001, "SAST"), (510003, "SAST"))))
    stale_sync = db.hub_defect(row["id"])["sync_json"]
    shown = form_fields(web, pid, f"hub-sync-cancel-form-{row['id']}")["shown"]
    assert act(web, pid, row["id"], "sync-cancel", {"shown": shown}).status_code == 200
    to_unconfirmed(web, pid, row)
    page = tab(web, pid)
    assert f'id="hub-sync-form-{row["id"]}"' not in page
    r = act(web, pid, row["id"], "sync")
    assert r.status_code == 409 and "сначала «Повторить чтение» или заново «Push в Hub»" in r.json()["detail"]
    db.hub_defect_update(row["id"], sync_json=stale_sync)
    keep = ("targets_json", "summary", "number", "import_json", "update_json")
    before = db.hub_defect(row["id"])
    r = act(web, pid, row["id"], "sync-apply", {"shown": text_hash(stale_sync)})
    assert r.status_code == 409 and "сначала «Повторить чтение» или заново «Push в Hub»" in r.json()["detail"]
    after = db.hub_defect(row["id"])
    assert {k: after[k] for k in keep} == {k: before[k] for k in keep}
    db.hub_defect_update(row["id"], sync_json="")
    page = tab(web, pid)
    assert f'id="hub-update-form-{row["id"]}"' in page and f'id="hub-update-reread-form-{row["id"]}"' in page
    hub_ids = sorted(t["hub_id"] for t in json.loads(before["targets_json"]))
    if then == "prepare":
        assert act(web, pid, row["id"], "update").status_code == 200
        assert phase(db, row["id"]) == "reading"
        return
    assert act(web, pid, row["id"], "update-reread").status_code == 200
    read_job(web, sent_body(db, row["id"]))
    done = db.hub_defect(row["id"])
    assert phase(db, row["id"]) == "done"
    assert sorted(t["hub_id"] for t in json.loads(done["targets_json"])) == hub_ids


@pytest.mark.parametrize("action", ["update-reread", "update-verify"])
@pytest.mark.parametrize("sync", ["sync_op_id", "sync_json"])
def test_reread_and_verify_are_refused_while_a_sync_waits(web, action, sync):
    """Страховка «Повторить чтение» и «Сверить» (круг 2 ревью, M3): сверка идёт (sync_op_id) или её предпросмотр не
    применён (sync_json) – отказ, чтение не ставится."""
    pid, row = ready(web)
    db = web.app.state.db
    if action == "update-reread":
        to_unconfirmed(web, pid, row)
    else:
        deliver_raw(web, to_put(web, pid, row), status=503)
        assert phase(db, row["id"]) == "unknown"
    if sync == "sync_op_id":
        db.hub_defect_update(row["id"], sync_op_id=999999)  # сверка другой вкладки «в пути»
    else:
        db.hub_defect_update(row["id"], sync_json=json.dumps({"read": {"summary": OLD_SUMMARY}}))
    r = act(web, pid, row["id"], action)
    assert r.status_code == 409 and "Pull из Hub" in r.json()["detail"], r.text
    assert db.hub_defect(row["id"])["update_op_id"] is None and take(web) is None


def test_double_spaces_in_the_reason_are_done_after_update(web):
    """C2: разбор описания схлопывает пробелы – подтверждение сравнивает разборы: фаза done, в строке – разбор
    подтверждающего чтения (вариант A)."""
    pid = pair_project(web)
    reason = "Подтверждено: owner  из запроса подставляется  в SQL-запрос конкатенацией."
    save_sast(web, pid, "510001", "true_positive", "", reason, FIX)
    row = imported(web, pid, "777", hub_body())
    assemble(web, pid, row)
    done = to_done(web, pid, row)
    assert "  " in hub_defects.update_state(done)["new"]["command_text"] and "  " not in done["command_text"]
    assert done["command_text"] == json.loads(done["import_json"])["command_text"]


def test_confirming_read_with_paragraphs_instead_of_br_is_done(web):
    """C2: Hub переложил `<br>` в абзацы – содержимое то же (структурный разбор), фаза done."""
    pid, row = ready(web)
    db = web.app.state.db
    put = to_put(web, pid, row)
    deliver(web, put, 204, text="")
    sent = hub_defects.update_state(db.hub_defect(row["id"]))["sent"]
    assert "<br>" in sent["description"] and "<br>" not in BLOCK
    read_job(web, sent_body(db, row["id"], description=sent["description"].replace("<br>", "</p><p>")))
    assert phase(db, row["id"]) == "done"


# ============================================================================ круг 2 ревью


def test_missing_field_differs_from_null():
    """K4: поле, которого нет в одном из чтений, отличается и от null – в обе стороны."""
    assert hub_defects.update_other_diffs({"settings": {}}, {}) == ["settings"]
    assert hub_defects.update_other_diffs({}, {"settings": {}}) == ["settings"]
    assert hub_defects._changed_fields({"settings": {}}, {}) == ["settings"]
    assert hub_defects._changed_fields({}, {"settings": {}}) == ["settings"]
    assert hub_defects._changed_fields({"settings": {}, "updateTs": 1}, {"settings": {}}) == []


SYNC_TEXTS = {
    "items_3_4": "<p>Текст команды.</p><p>Рекомендация:<br>3) Первое.<br>4) Второе.</p>",
    "no_space": "<p>Рекомендация:<br>1)текст без пробела</p>",
    "nested": "<p>Рекомендация:</p><ol><li>x<ol><li>y</li></ol></li><li>z</li></ol>",
}


@pytest.mark.parametrize("name", sorted(SYNC_TEXTS))
def test_generation_0_sync_compares_texts_exactly(web, name):
    """Строка поколения 0 хранит разбор описания Hub: «Pull из Hub» с тем же описанием – текст не «изменился»
    (точное сравнение, как в ADR-0124; круг 2 ревью, K1)."""
    pid, row = ready(web)
    db = web.app.state.db
    description = SYNC_TEXTS[name] + BLOCK
    db.hub_defect_update(row["id"], command_text=hub_defects.split_description(description)[0])
    assert act(web, pid, row["id"], "sync").status_code == 200
    read_job(web, hub_body(description=description))
    state = json.loads(db.hub_defect(row["id"])["sync_json"])
    assert state["matches"] and "read" not in state
    assert "Текст дефекта (изменился)" not in tab(web, pid)


def test_generation_0_sync_sees_renumbered_items(web):
    pid, row = ready(web)
    db = web.app.state.db
    before = "<p>Рекомендация:<br>7) Мера.</p>" + BLOCK
    db.hub_defect_update(row["id"], command_text=hub_defects.split_description(before)[0])
    assert act(web, pid, row["id"], "sync").status_code == 200
    read_job(web, hub_body(description="<p>Рекомендация:<br>1) Мера.</p>" + BLOCK))
    assert json.loads(db.hub_defect(row["id"])["sync_json"])["text_changed"] is True
    assert "Текст дефекта (изменился)" in tab(web, pid)


def pair_done(web, reason: str = REASON, confirm_description=None) -> tuple[int, dict, str, dict]:
    """Две находки группы с одним решением, дефект №777 с 510001 занесён и обновлён (поколение 1); confirm_description –
    как Hub вернул описание в подтверждающем чтении (нормализация HTML)."""
    pid = pair_project(web)
    db = web.app.state.db
    save_sast(web, pid, "510001", "true_positive", "", reason, FIX)
    save_sast(web, pid, "510005", "true_positive", "", reason, FIX)
    row = imported(web, pid, "777", hub_body())
    assemble(web, pid, row)
    sibling = f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510005')['id']}"
    put = to_put(web, pid, row)
    deliver(web, put, 204, text="")
    sent = hub_defects.update_state(db.hub_defect(row["id"]))["sent"]
    hub_now = sent_body(db, row["id"], description=(confirm_description(sent["description"]) if confirm_description
                                                    else sent["description"]))
    read_job(web, hub_now)
    done = db.hub_defect(row["id"])
    assert phase(db, row["id"]) == "done"
    return pid, done, sibling, hub_now


def blank_from(web, url: str):
    """«Создать дефект в Hub» по находке url (как устаревшая форма, если карточка уже предлагает «Привязать»)."""
    card = web.client.get(url).text
    shown_hash = (re.search(r'id="hub-defect-text-hash" value="([^"]*)"', card)
                  or re.search(r'<form [^>]*id="hub-defect-link-form".*?name="text_hash" value="([^"]*)"', card, re.S))
    return web.client.post(f"{url}/hub-defect", headers=AS_JSON, data={
        "review_revision": re.search(r'name="review_revision" value="(\d+)"', card).group(1),
        "text_hash": shown_hash.group(1)})


@pytest.mark.parametrize("variant", ["double_spaces", "paragraphs"])
def test_idle_sync_after_success_is_not_a_change(web, variant):
    """После успеха «Pull из Hub» с тем же содержимым Hub: текст не «(изменился)», кнопки «Применить» нет;
    у соседа «Привязать» нет, второй дефект по группе запрещён по членству (вариант A)."""
    reason = "Подтверждено: owner  из запроса подставляется  в SQL-запрос конкатенацией." if variant == "double_spaces" \
        else REASON
    rewrite = (lambda d: d.replace("<br>", "</p><p>")) if variant == "paragraphs" else None
    pid, done, sibling, hub_now = pair_done(web, reason, rewrite)
    db = web.app.state.db
    assert act(web, pid, done["id"], "sync").status_code == 200
    read_job(web, hub_now)
    assert json.loads(db.hub_defect(done["id"])["sync_json"])["matches"]
    assert "Текст дефекта (изменился)" not in tab(web, pid)
    assert f'id="hub-sync-apply-form-{done["id"]}"' not in tab(web, pid)
    assert "совпадают с принятой версией в приложении" in tab(web, pid)
    after = db.hub_defect(done["id"])
    assert after["command_text"] == done["command_text"] and after["summary"] == done["summary"]
    assert 'id="hub-defect-link-button"' not in web.client.get(sibling).text
    r = blank_from(web, sibling)
    assert r.status_code == 400 and "занесён из Hub" in r.json()["detail"], r.text


def test_text_changed_in_hub_after_success_is_applied_as_parsed(web):
    """После успеха текст в Hub правили: сверка – «(изменился)», «Применить» пишет разбор нового текста (ADR-0124)."""
    pid, done, sibling, hub_now = pair_done(web)
    db = web.app.state.db
    edited = {**hub_now, "description": hub_now["description"].replace("конкатенацией", "сцеплением строк")}
    assert edited["description"] != hub_now["description"]
    assert act(web, pid, done["id"], "sync").status_code == 200
    read_job(web, edited)
    snap = json.loads(db.hub_defect(done["id"])["sync_json"])
    assert snap["text_changed"] is True
    shown = form_fields(web, pid, f"hub-sync-apply-form-{done['id']}")["shown"]
    assert act(web, pid, done["id"], "sync-apply", {"shown": shown}).status_code == 200
    after = db.hub_defect(done["id"])
    assert after["command_text"] == snap["read"]["command_text"] and "сцеплением строк" in after["command_text"]
    assert after["draft_command_text"] == after["command_text"]
    assert after["draft_revision"] == done["draft_revision"] + 1
    assert json.loads(after["confirmed_object_json"]) == edited
    event = db._one("SELECT * FROM hub_defect_history ORDER BY id DESC LIMIT 1")
    assert event["event"] == "hub_sync" and event["command_text"] == after["draft_command_text"]
    to_preview(web, pid, after, edited)
    assert phase(db, after["id"]) == "cancelled" and "Изменений для отправки нет" in note(db, after["id"])
    assert take(web) is None


def test_sync_apply_transaction_sees_a_changed_update_state(web):
    """«Применить» сверки: состояние обновления (update_json) изменилось после чтения строки – отказ в транзакции,
    строка не меняется."""
    pid, done, sibling, hub_now = pair_done(web)
    db = web.app.state.db
    assert act(web, pid, done["id"], "sync").status_code == 200
    read_job(web, {**hub_now, "stage": "TEST"})
    row = db.hub_defect(done["id"])
    db.hub_defect_update(row["id"], update_json=json.dumps({**hub_defects.update_state(row), "note": "другая вкладка"}))
    with pytest.raises(ValueError, match=re.escape(hub_defects.IMPORT_SHOWN_CHANGED)):
        hub_defects.apply_import_sync(db, row, shown=text_hash(str(row["sync_json"])))
    assert db.hub_defect(row["id"])["sync_json"] == row["sync_json"]


def test_group_refusal_names_a_running_or_unconfirmed_update(web):
    """K3 и вариант A: пока по занесённому дефекту идёт «Push в Hub» или запись ждёт подтверждения (unconfirmed),
    «Создать дефект» у соседа отказывает с указанием сначала дождаться итога или «Повторить чтение»; после «Повторить
    чтение» (в Hub – B) отметки за прежний текст A у соседа нет."""
    pid, done, sibling, hub_now = pair_done(web)
    db = web.app.state.db
    save_sast(web, pid, "510001", "true_positive", "", REASON + " Уточнено.", FIX, defect_confirm="1")
    assemble(web, pid, done)
    put = to_put(web, pid, done, first=hub_now)
    r = blank_from(web, sibling)
    assert r.status_code == 400 and "по нему идёт «Push в Hub»" in r.json()["detail"], r.text
    deliver(web, put, 204, text="")
    read_job(web, hub_now)  # в Hub – прежний A
    row = db.hub_defect(done["id"])
    assert phase(db, row["id"]) == "unconfirmed"
    assert 'id="hub-defect-link-button"' not in web.client.get(sibling).text
    r = blank_from(web, sibling)
    assert r.status_code == 400 and "сначала «Повторить чтение» или заново «Push в Hub»" in r.json()["detail"], r.text
    assert act(web, pid, row["id"], "update-reread").status_code == 200
    read_job(web, sent_body(db, row["id"]))
    assert phase(db, row["id"]) == "done"
    assert db.get_review(pid, "510005")["entered_hub"] == 0, "за прежний текст A сосед отметки не получил"


def test_group_refusal_for_an_unknown_put_asks_to_verify(web):
    """Круг 4 (второй ревьюер): результат записи неизвестен (аренда истекла) – отказ «Создать дефект» у соседа не
    велит ждать, а называет «Сверить» в строке дефекта."""
    pid, done, sibling, hub_now = pair_done(web)
    db = web.app.state.db
    save_sast(web, pid, "510001", "true_positive", "", REASON + " Уточнено.", FIX, defect_confirm="1")
    assemble(web, pid, done)
    put = to_put(web, pid, done, first=hub_now)
    expire(db)
    tab(web, pid)
    assert phase(db, done["id"]) == "unknown" and db.hub_op(put["op_id"])["state"] == "unknown"
    r = blank_from(web, sibling)
    assert r.status_code == 400 and "нажмите «Сверить» в его строке" in r.json()["detail"], r.text
    assert "дождитесь" not in r.json()["detail"]


# ============================================================================ «Снять номер» у ложного срабатывания


def release(web, pid: int, hub_id: str, number) -> object:
    fid = web.app.state.db.get_finding_by_hub_id(pid, hub_id)["id"]
    return web.client.post(f"/projects/{pid}/findings/{fid}/defect-number/release", headers=AS_JSON,
                           data={"number_shown": str(number)})


def test_release_number_of_a_false_positive_frees_the_imported_title_number(web):
    """Номер, оставшийся у ложного срабатывания от прежней выдачи текста, занимает номер из заголовка занесённого
    дефекта: «Снять номер» удаляет его, «Pull из Hub» → «Применить» снимает предупреждение, «Подготовить
    обновление» номер больше не отклоняет."""
    pid = pair_project(web)
    db = web.app.state.db
    save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    save_sast(web, pid, "510005", "false_positive", "", "Значение не из запроса.")
    db.set_defect_number(pid, "sast:510005", 5)
    row = imported(web, pid, "777", hub_body())
    assemble(web, pid, row)
    assert "номер ID5 уже занят" in str(row["error"]), row["error"]
    card_url = f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510005')['id']}"
    card = web.client.get(card_url).text
    assert 'id="defect-number-release"' in card and "Снять номер ID5" in card
    assert release(web, pid, "510005", 4).status_code == 409, "показан другой номер – не снимается"
    r = release(web, pid, "510005", 5)
    assert r.status_code == 200 and r.json()["ok"], r.text
    assert db.defect_number(pid, "sast:510005") is None
    assert 'id="defect-number-release"' not in web.client.get(card_url).text
    assert act(web, pid, row["id"], "sync").status_code == 200
    read_job(web, hub_body())
    assert json.loads(db.hub_defect(row["id"])["sync_json"])["matches"]
    assert f'id="hub-sync-apply-form-{row["id"]}"' not in tab(web, pid)
    assert "занят" not in str(db.hub_defect(row["id"])["error"] or "")
    to_preview(web, pid, row)
    assert phase(db, row["id"]) == "preview", note(db, row["id"])


def test_release_number_is_refused_for_a_confirmed_or_bound_finding(web):
    """Номер не снимается у находки с решением «Подтверждаю дефект» и у находки, которая входит в дефект приложения."""
    pid = pair_project(web)
    db = web.app.state.db
    save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    db.set_defect_number(pid, "sast:510001", 5)
    card = web.client.get(f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510001')['id']}").text
    assert 'id="defect-number-release"' not in card
    r = release(web, pid, "510001", 5)
    assert r.status_code == 409 and "Ложное срабатывание" in r.json()["detail"], r.text
    imported(web, pid, "777", hub_body())
    save_sast(web, pid, "510001", "false_positive", "", "Значение не из запроса.", defect_confirm="1")
    card = web.client.get(f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510001')['id']}").text
    assert 'id="defect-number-release"' not in card
    r = release(web, pid, "510001", 5)
    assert r.status_code == 409 and "входит в дефект" in r.json()["detail"], r.text
    assert db.defect_number(pid, "sast:510001") == 5


def test_link_through_an_app_row_of_an_imported_defect_is_refused(web):
    """Круг 4 (Codex): строка привязки origin 'app' того же дефекта Hub, что и живая занесённая строка (могла остаться
    от прежней сборки), родителем не выбирается, транзакция привязки к ней отказывает, «Создать дефект» у соседа –
    отказ по членству, как у занесённого."""
    from app.models import Finding
    from app.routes import findings as card
    from app.routes import hub_defect_routes as routes
    pid, row, sibling = pair_ready(web)
    db = web.app.state.db
    f = Finding.from_dict(db.get_finding_by_hub_id(pid, "510005")["data"])
    review = db.get_review(pid, "510005")
    mine = card.sast_entered_text(db, web.settings, pid, f, review)
    targets = [{"hub_id": "510001", "issue_id": 510001, "issue_type": "SAST", "revision": 1, "entered_hash": "h",
                "entered_parts": "", "sig": "s"}]
    with db._tx() as c:  # строка привязки L того же дефекта №777, как её создавала прежняя сборка
        c.execute("INSERT INTO hub_defects(project_id, kind, number, summary, anchor_hub_id, targets_json, command_text,"
                  " hub_url, app_id, hub_defect_id, state, origin, blank_json, created_at, updated_at)"
                  " SELECT project_id, kind, number, summary, '510001', ?, ?, hub_url, app_id, hub_defect_id, 'done',"
                  " 'app', blank_json, created_at, updated_at FROM hub_defects WHERE id = ?",
                  (json.dumps(targets), mine, row["id"]))
    link_row = db.hub_defect_bound(pid, "510001")
    assert link_row["origin"] == "app" and link_row["hub_defect_id"] == "777"
    assert routes.link_parent(db, web.settings, pid, f, review, 7) is None
    assert 'id="hub-defect-link-button"' not in web.client.get(sibling).text
    sib = [{"hub_id": "510005", "issue_id": 510005, "issue_type": "SAST", "revision": 1, "entered_hash": "h",
            "entered_parts": "", "sig": "s"}]
    with pytest.raises(ValueError, match="занесён из Hub"):
        db.hub_defect_link_start(pid, link_row["id"], "777", item=link_item(pid, sib), body_hash=text_hash(mine),
                                 kind="SAST", number=5, summary=link_row["summary"], anchor_hub_id="510005",
                                 targets=sib, number_keys=["sast:510005"], command_text=mine,
                                 hub_url=link_row["hub_url"], app_id=link_row["app_id"])
    r = blank_from(web, sibling)
    assert r.status_code == 400 and "занесён из Hub" in r.json()["detail"], r.text
    assert take(web) is None


def test_release_number_names_other_holders(web):
    """Дельта 5 (второй ревьюер): номер есть и у соседа по группе с решением «Подтверждаю дефект» – у ложного
    срабатывания он снимается, но ответ называет оставшихся держателей, а занесённый дефект с этим номером в заголовке
    по-прежнему видит номер занятым."""
    pid = pair_project(web)
    db = web.app.state.db
    save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    save_sast(web, pid, "510005", "false_positive", "", "Значение не из запроса.")
    db.set_defect_number(pid, "sast:510001", 5)
    db.set_defect_number(pid, "sast:510005", 5)
    r = release(web, pid, "510005", 5)
    assert r.status_code == 200 and r.json()["others"] == ["sast:510001"], r.text
    assert db.defect_number(pid, "sast:510005") is None and db.defect_number(pid, "sast:510001") == 5
    fid = db.get_finding_by_hub_id(pid, "510005")["id"]
    db.set_defect_number(pid, "sast:510005", 5)
    page = web.client.post(f"/projects/{pid}/findings/{fid}/defect-number/release", headers={"Origin": AS_JSON["Origin"]},
                           data={"number_shown": "5"}, follow_redirects=False)
    assert page.status_code == 303 and "defect_number_released_others" in page.headers["location"], page.headers
    assert page.headers["location"].endswith("#step-6")
    shown = web.client.get(page.headers["location"].split("#")[0]).text
    assert "он остаётся у других находок проекта" in shown


def test_numbered_lines_other_than_one_two_three_keep_their_numbers():
    """31.10: «7) …», «9) …» при отправке не превращаются в «1)», «2)» – после «Pull из Hub» текст тот же."""
    for text in ("Блок:\n7) А\n9) Б", "2) Проверить входные данные.", "01) А\n02) Б"):
        assert "\n".join(hub_defects.description_lines(hub_defects.command_html(text))) == text
    for text in ("Рекомендация:\n1) А\n2) Б", "1) А"):  # и «1)», «2)» – текстом, круговой путь тот же
        assert "<ol>" not in hub_defects.command_html(text)
        assert "\n".join(hub_defects.description_lines(hub_defects.command_html(text))) == text


def test_empty_text_is_refused_before_preview(web):
    """Ревью dev9, круг 2: пустой текст дефекта – отказ на подготовке, а не предпросмотр с неизбежным отказом записи."""
    pid, row = ready(web)
    db = web.app.state.db
    db.hub_defect_update(row["id"], draft_command_text="  ")
    to_preview(web, pid, row)
    assert phase(db, row["id"]) == "refused" and "текст дефекта пуст" in note(db, row["id"])


def test_sca_push_of_unchanged_hub_text_needs_no_ready_set_template(web):
    """Дефект, приведённый к Hub, без правок – «Push в Hub» без ошибок: «Изменений для отправки нет».
    Заготовка набора не доведена (Объяснение не сохранено) – это не отказ при отправке текста как есть; «Текст из
    решений» по-прежнему требует готовую заготовку."""
    from test_sca_package_decision import UPD, post_package
    pid = prepared(web)
    hub_settings(web, pid)
    db = web.app.state.db
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    links = ((73001, "SCA_S"), (73002, "SCA_S"))
    row = imported(web, pid, "777", hub_body(links=links, summary=SCA_OLD))
    to_preview(web, pid, row, hub_body(links=links, summary=SCA_OLD))
    assert phase(db, row["id"]) == "cancelled", note(db, row["id"])
    assert "Изменений для отправки нет" in note(db, row["id"])
    assert not ops(db, "defect_update")
    refused = assemble(web, pid, row)
    assert refused.status_code >= 400 and "не готов" in refused.text, refused.text


def test_push_keeps_hub_markup_when_the_visible_text_is_the_same():
    """Описание из редактора Hub (другая разметка того же текста) не переписывается; другой текст – переписывается."""
    hub = {"description": "<div><b>Обоснование:</b></div><div>текст&nbsp;строки</div><ol><li>Мера</li></ol>"}
    # текст, занесённый из Hub, – строки разбора его описания: блоки редактора Hub разделены пустыми строками
    same = hub_defects.command_html("Обоснование:\n\nтекст строки\n\n1) Мера")
    assert hub_defects.keep_hub_markup(hub, same) == hub["description"]
    other = hub_defects.command_html("Обоснование:\nдругой текст\n1) Мера")
    assert hub_defects.keep_hub_markup(hub, other) == other
    assert hub_defects.keep_hub_markup({"description": ""}, same) == same
    with_block = {"description": hub["description"] + "<p>Информация об объекте сканирования:</p><p>ID: 1</p>"}
    assert hub_defects.keep_hub_markup(with_block, same) == with_block["description"], "блок Hub остаётся"
    assert hub_defects.keep_hub_markup(with_block, other) == other, "правка текста – описание заменяется целиком"
    # перенос строки – правка оператора, а не разметка (ревью dev15, B1)
    one_line = {"description": "<p>Рекомендация:<br>1) Проверить A. 2) Проверить B.</p>"}
    split = hub_defects.command_html("Рекомендация:\n1) Проверить A.\n2) Проверить B.")
    assert hub_defects.keep_hub_markup(one_line, split) == split


def test_pull_clears_a_stale_push_result(web):
    """Отказ прошлой подготовки Push не висит в строке после «Pull из Hub»/«Принять»."""
    pid, row = ready(web)
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET update_json=? WHERE id=?",
                  (json.dumps({"phase": "refused", "refusals": ["старый отказ"], "generation": 4}), row["id"]))
        hub_defects.clear_stale_update_in(c, row["id"])
    assert hub_defects.update_state(db.hub_defect(row["id"])) == {"generation": 4}
    with db._tx() as c:  # идущая или неподтверждённая запись не трогается
        c.execute("UPDATE hub_defects SET update_json=? WHERE id=?",
                  (json.dumps({"phase": "unconfirmed", "generation": 5}), row["id"]))
        hub_defects.clear_stale_update_in(c, row["id"])
    assert hub_defects.update_state(db.hub_defect(row["id"]))["phase"] == "unconfirmed"


def test_pull_without_differences_also_clears_a_stale_push_result(web):
    """Ревью dev15 (A1, B2): «Pull из Hub» без различий тоже снимает прошлый отказ подготовки Push."""
    pid, row = ready(web)
    db = web.app.state.db
    db.hub_defect_update(row["id"], update_json=json.dumps({"phase": "read_failed", "note": "сбой", "generation": 2}))
    assert act(web, pid, row["id"], "sync").status_code == 200
    read_job(web, hub_body())
    current = db.hub_defect(row["id"])
    assert json.loads(current["sync_json"]).get("matches"), current["sync_json"]
    assert hub_defects.update_state(current) == {"generation": 2}


def test_kept_hub_description_is_confirmed_byte_for_byte():
    """Ревью dev15 (A2): описание Hub оставлено как есть – подтверждается побайтно, вместе с блоком Hub."""
    from app.defect_dto import DEFECT_CONTRACT
    from app.defect_fields import changed_roots, diff
    base = hub_body(description="<p>Текст</p><p>Информация об объекте сканирования:</p><p>ID: 1</p>")
    base = {**base, "id": 777, "appId": 7}
    sent_object = {**base, "summary": "ID5 - новый заголовок (SAST)"}
    changes = diff(base, sent_object)
    state = {"contract_version": DEFECT_CONTRACT, "base": base, "sent_object": sent_object, "field_diff": changes,
             "changed_roots": changed_roots(changes), "expected_number": 5, "generation": 1, "put_op_id": 1,
             "sent": {"summary": sent_object["summary"], "description": base["description"]}}
    row = {"hub_defect_id": "777", "app_id": 7, "number": 5}
    assert hub_defects.update_confirmed_fields(row, state, dict(sent_object))
    changed_block = {**sent_object, "description": "<p>Текст</p><div>Информация об объекте сканирования:</div><p>ID: 1</p>"}
    assert not hub_defects.update_confirmed_fields(row, state, changed_block)


def test_sca_push_with_unready_template_marks_findings_by_confirmed_composition(web):
    """Push текста как есть при неготовой заготовке набора (правка только заголовка) – запись и подтверждение проходят;
    отметка «Внесено в Hub» ставится по подтверждённому составу без отпечатка решения:
    карточка не сравнивает текст решения (entered_decision_hash пуст), текст в Hub – отпечаток содержимого. До dev23
    (ревью dev15, A3) такая отметка не ставилась."""
    from test_sca_package_decision import UPD, post_package
    pid = prepared(web)
    hub_settings(web, pid)
    db = web.app.state.db
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    links = ((73001, "SCA_S"), (73002, "SCA_S"))
    row = imported(web, pid, "777", hub_body(links=links, summary=SCA_OLD))
    before = {h: db.get_review(pid, h) for h in ("73001", "73002")}
    db.hub_defect_update(row["id"], draft_summary="ID3 - example-parser 1.4.2 (SCA) – уточнено")
    put = to_put(web, pid, db.hub_defect(row["id"]), first=hub_body(links=links, summary=SCA_OLD))
    assert put["body"]["summary"].endswith("уточнено")
    assert put["body"]["description"] == hub_body(links=links, summary=SCA_OLD)["description"], "описание Hub как есть"
    deliver(web, put, 204, text="")
    read_job(web, sent_body(db, row["id"], linkedIssues=[{"id": 73001, "type": "SCA_S"}, {"id": 73002, "type": "SCA_S"}]))
    assert phase(db, row["id"]) == "done", note(db, row["id"])
    done = db.hub_defect(row["id"])
    content = text_hash(dumps({"summary": hub_defects._read_of(sent_body(db, row["id"]))["summary"],
                               "command_text": hub_defects._read_of(sent_body(db, row["id"]))["command_text"]}))
    for h in ("73001", "73002"):
        after = db.get_review(pid, h)
        assert not before[h]["entered_hub"] and after["entered_hub"]
        assert (after["entered_origin"], after["entered_decision_hash"], after["entered_text_hash"]) == ("defect", "", content)
        assert after["entered_defect_id"] == done["id"] and after["revision"] == before[h]["revision"]



def test_old_object_does_not_confirm_a_line_break_edit():
    """Ревью dev15, круг 2: перенос строки – правка; прежний объект Hub её не подтверждает, нормализация HTML – да."""
    old = {"summary": "T", "description": "<p>Рекомендация:<br>1) Проверить A. 2) Проверить B.</p>"}
    sent = {"summary": "T", "description": hub_defects.command_html("Рекомендация:\n1) Проверить A.\n2) Проверить B.")}
    assert not hub_defects.update_content_new(old, sent)
    normalized = {"summary": "T", "description": "<p>Рекомендация:</p><p>1) Проверить A.</p><p>2) Проверить B.</p>"}
    assert hub_defects.update_content_new(normalized, sent)
