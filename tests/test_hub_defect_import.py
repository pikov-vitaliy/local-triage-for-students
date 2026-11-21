"""«Занести из Hub» и «Pull из Hub» (ADR-0124): схема 27 (новая база, 26 → 27, 25 → 27, откат шага при сбое, повторное
открытие); разбор номеров и ссылок, описания HTML (абзацы, строки, пункты, ссылки, сущности, граница блока Hub),
заголовка (номер ID<n>) и вида по составу; начало (20 номеров, повторы, две вкладки, другой Hub и приложение, живая
строка, «ошибка A → начало B → повтор A»); ответ чтения (404, 5xx, неверный JSON, чужие id и appId, состав нет и пуст,
повторная и поздняя доставка, отмена, истечение аренды); предпросмотр (вид, отсутствующие, конфликт, разные версии SCA,
подсказки); «Занести» одной транзакцией – номер только резервируется, сбой посередине, устаревший снимок, другое
приложение; защита ADR-0121, запрет второго дефекта группы, «Привязать» к занесённому – отказ; «Pull из Hub» – только
добавление. Ни в одном пути нет POST к Hub, отметок «Внесено в Hub» и номеров ключам находок. Данные, адреса и номера
выдуманы."""

from __future__ import annotations

import json
import re
import sqlite3

import pytest

from app import defect, defect_check, hub_defects, hub_ops
from app.db import Database, text_hash
from test_defect import save_sast
from test_hub_defects import FIX, REASON, blank, create, hub_settings, pair_project, shown, to_preview
from test_hub_status_routes import AS_JSON, HUB, worker_headers
from test_web import ORIGIN, prepared, web  # noqa: F401

APP_ID = 7
COMMAND = ("После анализа команда «Платформа» приняла решение.\n\nОбоснование:\nowner из запроса подставляется в "
           "SQL-запрос.\n\nРекомендация:\n1) Параметризовать запрос.")
DESCRIPTION = ("<p>После анализа команда «Платформа» приняла решение.<br><br>Обоснование:<br>owner из запроса "
               "подставляется в SQL-запрос.<br><br>Рекомендация:<br>1) Параметризовать запрос.</p>"
               "<p>Информация об объекте сканирования:</p><p>ID: 510001, файл InvoiceDao.java, строка 58</p>"
               "<p>ID: 510002, файл Renderer.java</p>")


def defect_body(defect_id: int = 777, links=((510001, "SAST"),), summary: str = "ID5 - Внедрение SQL-кода (SAST)",
                description: str = DESCRIPTION, app_id: int = APP_ID, **extra) -> dict:
    """Ответ `GET /defects/{id}` поддельного Hub (DefectDto)."""
    return {"id": defect_id, "appId": app_id, "summary": summary, "description": description,
            "linkedIssues": [{"id": i, "type": t} for i, t in links], **extra}


# ============================================================================ помощники


def project(web) -> int:
    pid = prepared(web)
    hub_settings(web, pid)
    return pid


def start(web, pid: int, numbers: str):
    return web.client.post(f"/projects/{pid}/defects/import", data={"numbers": numbers}, headers=AS_JSON)


def take(web) -> dict | None:
    return web.client.get("/api/hub/jobs", params={"worker_id": "w1", "hub_url": HUB, "wait": 0},
                          headers=worker_headers(web)).json()["job"]


def deliver(web, job: dict, status: int = 200, body: dict | None = None, text: str | None = None, error: str = ""):
    r = web.client.post(f"/api/hub/jobs/{job['attempt_id']}/result", headers=worker_headers(web), content=json.dumps(
        {"lease_token": job["lease_token"], "worker_id": "w1", "status": status, "headers": {},
         "body_text": text if text is not None else json.dumps(body or {}, ensure_ascii=False), "error": error}))
    assert r.status_code == 200, r.text
    return r.json()


def answer(web, status: int = 200, body: dict | None = None, text: str | None = None, error: str = "") -> dict:
    job = take(web)
    assert job is not None, "в очереди нет задания"
    assert job["method"] == "GET" and re.fullmatch(r"/defects/\d+", job["path"]), job
    deliver(web, job, status, body, text, error)
    return job


def import_rows(db: Database, pid: int) -> list[dict]:
    return [r for r in db.hub_defects(pid, limit=1000) if r["origin"] == "import"]


def tab(web, pid: int) -> str:
    page = web.client.get(f"/projects/{pid}/defects")
    assert page.status_code == 200
    return page.text


def preview_of(web, pid: int, number: str = "777", body: dict | None = None) -> dict:
    assert start(web, pid, number).status_code == 200
    answer(web, body=body or defect_body(int(number)))
    tab(web, pid)
    row = [r for r in import_rows(web.app.state.db, pid) if r["hub_defect_id"] == number][-1]
    assert row["state"] == "import_preview", row
    return row


def accept_fields(web, pid: int, row_id: int) -> dict:
    form = re.search(rf'<form [^>]*id="hub-import-accept-form-{row_id}".*?</form>', tab(web, pid), re.S).group(0)
    return {name: re.search(rf'name="{name}" value="([^"]*)"', form).group(1) for name in ("op", "shown")}


def accept(web, pid: int, row_id: int, fields: dict | None = None):
    return web.client.post(f"/projects/{pid}/hub/defects/{row_id}/import", headers=AS_JSON,
                           data=fields or accept_fields(web, pid, row_id))


def imported(web, pid: int, number: str = "777", body: dict | None = None) -> dict:
    row = preview_of(web, pid, number, body)
    r = accept(web, pid, row["id"])
    assert r.status_code == 200, r.text
    row = web.app.state.db.hub_defect(row["id"])
    assert row["state"] == "done", row
    return row


def defects_state(db: Database) -> list[tuple]:
    """Таблица номеров дефектов за ключами находок целиком (с временем записи) – для сравнения до и после."""
    return [tuple(r.values()) for r in db._all("SELECT project_id, defect_key, number, updated_at, assigned_at"
                                               " FROM defects ORDER BY project_id, defect_key")]


def read_only(db: Database, before: list[tuple] | None = None) -> None:
    """Ни одной записи в Hub, ни одной отметки «Внесено в Hub», ни одной записи номера за ключами находок: таблица
    defects – та же, что до действий теста (before – defects_state до них; None – пустая)."""
    ops = db.hub_ops_list(limit=10000)
    assert all(o["purpose"] in hub_ops.READ_PURPOSES for o in ops), [o["purpose"] for o in ops]
    assert all(json.loads(o["request_json"])["method"] == "GET" for o in ops)
    assert db._scalar("SELECT COUNT(*) FROM reviews WHERE entered_hub = 1") == 0
    assert defects_state(db) == (before or [])


def sync(web, pid: int, row_id: int):
    return web.client.post(f"/projects/{pid}/hub/defects/{row_id}/sync", headers=AS_JSON)


def apply_sync(web, pid: int, row_id: int, shown_value: str | None = None):
    if shown_value is None:
        form = re.search(rf'<form [^>]*id="hub-sync-apply-form-{row_id}".*?</form>', tab(web, pid), re.S).group(0)
        shown_value = re.search(r'name="shown" value="([^"]*)"', form).group(1)
    return web.client.post(f"/projects/{pid}/hub/defects/{row_id}/sync-apply", headers=AS_JSON,
                           data={"shown": shown_value})


def cancel_fields(web, pid: int, row_id: int) -> dict:
    """Скрытые поля формы «Отменить» предпросмотра сверки, как их показывает вкладка сейчас."""
    form = re.search(rf'<form [^>]*id="hub-sync-cancel-form-{row_id}".*?</form>', tab(web, pid), re.S).group(0)
    return dict(re.findall(r'name="([^"]+)" value="([^"]*)"', form))


def cancel_sync(web, pid: int, row_id: int, shown_value: str):
    return web.client.post(f"/projects/{pid}/hub/defects/{row_id}/sync-cancel", headers=AS_JSON,
                           data={"shown": shown_value})


# ============================================================================ схема 27


# ============================================================================ разбор


def test_import_numbers_from_numbers_and_links():
    assert hub_defects.import_numbers("777, 778\n779;0780") == ["777", "778", "779", "780"]
    assert hub_defects.import_numbers(f"777 {HUB}/#/appprofile/7/defects/777 {HUB}/#/appprofile/7/defects/778?x=1") == [
        "777", "778"]
    assert len(hub_defects.import_numbers(" ".join(str(n) for n in range(1, 21)))) == 20
    for bad, words in (("", "Укажите"), ("abc", "не номер дефекта"), ("0", "больше нуля"),
                       (" ".join(str(n) for n in range(1, 22)), "не больше 20")):
        with pytest.raises(ValueError, match=words):
            hub_defects.import_numbers(bad)


def test_description_lines_paragraphs_lists_links_entities():
    lines = hub_defects.description_lines(
        "<p>Первый &amp; «второй»<br>строка&nbsp;два</p><p>Рекомендация:</p><ol><li>Один</li><li>Два</li></ol>"
        "<ul><li>пункт</li></ul><p>См. <a href=\"https://example.org/a\">страницу</a> и "
        "<a href=\"https://example.org/b\">https://example.org/b</a></p><script>alert(1)</script>")
    assert lines == ["Первый & «второй»", "строка два", "", "Рекомендация:", "1) Один", "2) Два", "", "- пункт", "",
                     "См. страницу (https://example.org/a) и https://example.org/b"]
    # свой же HTML (command_html) читается обратно тем же текстом
    text = COMMAND + "\n2) Белый список имён таблиц."
    assert "\n".join(hub_defects.description_lines(hub_defects.command_html(text))) == text
    # без разметки – по строкам
    assert hub_defects.description_lines("а\n\n\nб") == ["а", "", "б"]


def test_description_block_tags_inside_list_items_do_not_break_the_item():
    """Блочный тег внутри пункта списка (`<li><p>`, `<li><div>`) и `<br>` сразу после маркера (`<li><br>`) – мягкий
    перенос: маркер пункта остаётся с текстом, конец блока не даёт пустой строки; проверка формы ADR-0123 по итоговому
    тексту – без ложного S1."""
    assert hub_defects.description_lines("<ol><li><p>Первый пункт</p></li></ol>") == ["1) Первый пункт"]
    assert hub_defects.description_lines("<ul><li><p>Первый пункт</p></li></ul>") == ["- Первый пункт"]
    assert hub_defects.description_lines("<ol><li><div>Один</div></li><li><div>Два</div></li></ol>") == ["1) Один",
                                                                                                       "2) Два"]
    # `<br>` сразу после маркера пункта маркер от текста не отрывает
    assert hub_defects.description_lines("<ol><li><br><p>A</p></li></ol>") == ["1) A"]
    assert hub_defects.description_lines("<ol><li><br>A</li></ol>") == ["1) A"]
    assert hub_defects.description_lines("<ul><li><br><p>A</p></li></ul>") == ["- A"]
    # второй блок того же пункта – следующей строкой, после списка – снова абзацы
    assert hub_defects.description_lines("<ol><li><p>Один</p><p>пояснение</p></li></ol><p>После</p>") == [
        "1) Один", "пояснение", "", "После"]
    # `<br>` после текста пункта и вне списка – как раньше: новая строка, два подряд – пустая
    assert hub_defects.description_lines("<ol><li>A<br><br>B</li></ol>") == ["1) A", "", "B"]
    assert hub_defects.description_lines("<ul><li>A<br><br>B</li></ul>") == ["- A", "", "B"]
    assert hub_defects.description_lines("<p>x<br><br>y</p>") == ["x", "", "y"]
    # вне списка строка из одного «-» или «1)» маркером пункта не считается
    assert hub_defects.description_lines("<ol><li>A</li></ol><p>-<br>x</p>") == ["1) A", "", "-", "x"]
    phrase = defect.sast_phrase("Платформа")
    description = (f"<p>{phrase}</p><p>Обоснование:</p><p>owner из запроса подставляется в SQL-запрос.</p>"
                   "<p>Рекомендация:</p><ol><li><p>Параметризовать запрос.</p></li><li><p>Белый список имён таблиц."
                   "</p></li></ol><p>Информация об объекте сканирования:</p><p>ID: 510001, файл InvoiceDao.java</p>")
    command, _, note = hub_defects.split_description(description)
    assert note == "" and command.endswith("Рекомендация:\n1) Параметризовать запрос.\n2) Белый список имён таблиц.")
    assert defect_check.sast_problems(command, team_phrase=phrase) == []


def test_description_marker_is_only_the_one_li_placed_links_across_br_and_nested_lists():
    """Маркер пункта – только тот, что поставил `<li>`: текст «-» или «1)» из данных после `<br>` – обычная строка,
    и следующий `<br>` или блок её обрывают; пробел после `<li>` маркер не снимает. Ссылка через `<br>` – текст по
    строкам, адрес после конца ссылки. Вложенный список внутри открытого – без пустых строк."""
    lines = hub_defects.description_lines
    assert lines("<ul><li>A<br>-<br>B</li></ul>") == ["- A", "-", "B"]
    assert lines("<ul><li>A<br>-<p>B</p></li></ul>") == ["- A", "-", "B"]
    assert lines("<ol><li>A<br>1)<br>B</li></ol>") == ["1) A", "1)", "B"]
    # прежние случаи – как были: `<br>` и блок сразу после маркера (в том числе после пробела) его не отрывают
    assert lines("<ol><li> <br>A</li></ol>") == ["1) A"]
    assert lines("<ol><li><br>A</li></ol>") == ["1) A"]
    assert lines("<ul><li><br><p>A</p></li></ul>") == ["- A"]
    assert lines("<ol><li>\n<p>Один</p></li></ol>") == ["1) Один"]
    # ссылка через `<br>`
    assert lines('<p>a <a href="https://example.org/c">ли<br>нк</a> b</p>') == ["a ли", "нк (https://example.org/c) b"]
    # вложенный список
    assert lines("<ol><li>x<ol><li>y</li></ol></li><li>z</li></ol>") == ["1) x", "1) y", "2) z"]
    assert lines("<ul><li>x<ul><li>y</li></ul></li></ul><p>После</p>") == ["- x", "- y", "", "После"]


def test_split_description_by_the_single_hub_block_line():
    command, block, note = hub_defects.split_description(DESCRIPTION)
    assert command == COMMAND and note == ""
    assert block == ["ID: 510001, файл InvoiceDao.java, строка 58", "", "ID: 510002, файл Renderer.java"]
    # текст после границы (комментарий в блоке Hub) в текст команды не попадает
    command, _, _ = hub_defects.split_description(DESCRIPTION + "<p>Комментарий рецензента</p>")
    assert command == COMMAND
    # 31.10: без строки границы описание целиком – текст дефекта (так пишет «Push в Hub»)
    assert hub_defects.split_description("<p>Текст без блока</p>") == ("Текст без блока", [], "")
    assert hub_defects.split_description("<p>Информация об объекте сканирования: demo</p>") == (
        "Информация об объекте сканирования: demo", [], "")
    # блок повторён (ADR-0137): чужое описание – текст до первой границы; подтверждение своей записи – строго
    twice = DESCRIPTION + "<p>Информация об объекте сканирования:</p>"
    assert hub_defects.split_description(twice)[0] == COMMAND and hub_defects.split_description(twice)[2] == ""
    command, block, note = hub_defects.split_description(twice, repeated=False)
    assert command == "" and block == [] and "встречается 2 раза" in note and "текст команды не выделен" in note


def test_title_number_and_kind():
    assert hub_defects.title_number("ID5 - Внедрение SQL-кода (SAST)") == (5, "")
    assert hub_defects.title_number("[Не по шаблону] (замечание) ID12 - x (SCA)") == (12, "")
    # скобка, всё содержимое которой – ID<число>, – номер, а не пометка рецензента: не снимается
    for title in ("[ID3] Внедрение SQL-кода (SAST)", "(ID3) Внедрение SQL-кода (SAST)", "[Ревью] (ID3) x (SAST)",
                  "[ ID3 ] x (SAST)"):
        assert hub_defects.title_number(title) == (3, ""), title
    assert hub_defects.title_number("[ID3 примечание] x (SAST)")[0] is None  # пометка со словами снимается, как раньше
    assert hub_defects.title_number("ID5 - x, см. ID5 (SAST)") == (5, "")
    number, note = hub_defects.title_number("ID5 - x, ID6 (SAST)")
    assert number is None and "неоднозначен" in note
    assert hub_defects.title_number("Внедрение SQL (SAST)")[0] is None
    assert hub_defects.title_number("PID5 - x")[0] is None
    assert hub_defects.import_kind([(1, "SAST"), (2, "SAST")], "") == ("SAST", "")
    assert hub_defects.import_kind([(1, "SCA_S")], "x (SAST)") == ("SCA", "")
    for pairs in ([(1, "SAST"), (2, "SCA_L")], [(1, "SCA_L")], [(1, "SAST"), (2, "SCA_S")]):
        kind, note = hub_defects.import_kind(pairs, "x (SAST)")
        assert kind == "" and "не поддерживается" in note
    assert hub_defects.import_kind([], "ID1 - x (SCA)") == ("SCA", "")
    assert hub_defects.import_kind([], "ID1 - x (SAST)") == ("SAST", "")
    kind, note = hub_defects.import_kind([], "ID1 - x")
    assert kind == "" and "вид не определён" in note


# ============================================================================ начало


def test_start_limits_duplicates_and_queues_reads_only(web):
    pid = project(web)
    db = web.app.state.db
    r = start(web, pid, " ".join(str(n) for n in range(1, 22)))
    assert r.status_code == 400 and "не больше 20" in r.json()["detail"]
    assert start(web, pid, f"777, {HUB}/#/appprofile/7/defects/777").status_code == 200
    rows = import_rows(db, pid)
    assert len(rows) == 1 and rows[0]["state"] == "import_reading" and rows[0]["kind"] == ""
    assert rows[0]["hub_defect_id"] == "777" and rows[0]["hub_link"].endswith("/defects/777")
    assert start(web, pid, " ".join(str(n) for n in range(801, 821))).status_code == 200
    assert len(import_rows(db, pid)) == 21
    ops = db.hub_ops_list(project_id=pid, limit=100)
    assert len(ops) == 21 and {o["purpose"] for o in ops} == {"defect_read"}
    target = json.loads(ops[-1]["targets_json"])[0]
    assert target["issue_type"] == "DEFECT_IMPORT" and target["import_defect"] == target["issue_id"]
    # строки чтения номеров не держат и находок не занимают; счётчик вкладки их считает
    assert db.next_defect_number(pid) == 1 and db.hub_defect_count(pid) == 21
    read_only(db)


def test_start_refuses_a_live_row_of_the_same_defect_but_not_of_another_hub_or_app(web):
    pid = project(web)
    db = web.app.state.db
    assert start(web, pid, "777").status_code == 200
    r = start(web, pid, "777")  # вторая вкладка с тем же номером
    assert r.status_code == 409 and "уже есть в приложении" in r.json()["detail"], r.text
    # состояние живой строки – подписью, как во вкладке, а не служебным именем
    assert "состояние «чтение из Hub»" in r.json()["detail"] and "import_reading" not in r.json()["detail"], r.text
    r = start(web, pid, "778 777")  # всё или ничего: 778 тоже не поставлен
    assert r.status_code == 409 and len(import_rows(db, pid)) == 1
    # живая строка дефекта приложения с тем же номером в Hub
    row = db.hub_defect_insert(pid, kind="SAST", number=1, summary="ID1 - x (SAST)", anchor_hub_id="510003",
                               targets=[], number_keys=[], command_text="t", hub_url=HUB, app_id=APP_ID)
    db.hub_defect_update(row["id"], hub_defect_id="900", state="done")
    assert start(web, pid, "900").status_code == 409
    # то же число в другом приложении и в другом Hub – другой дефект
    db.update_project(pid, hub_app_id=8)
    assert start(web, pid, "777 900").status_code == 200
    db.set_settings({"hub_url": "https://hub2.example.org"})
    db.update_project(pid, hub_app_id=APP_ID)
    assert start(web, pid, "777").status_code == 200
    assert len(import_rows(db, pid)) == 4


def test_imported_defect_is_live_for_another_project_of_the_same_hub_and_app(web):
    """«Живая строка» (ADR-0124 п. 9) – в любом проекте: дефект №777 занесён в первом проекте, «Занести» №777 во втором
    проекте того же Hub и приложения – 409 «уже есть в приложении»; во втором ни строки, ни операции."""
    first = project(web)
    db = web.app.state.db
    row = imported(web, first)
    second = project(web)
    ops = len(db.hub_ops_list(limit=10000))
    r = start(web, second, "777")
    assert r.status_code == 409 and "уже есть в приложении" in r.json()["detail"], r.text
    assert f"строка {row['id']}" in r.json()["detail"] and "состояние «создан»" in r.json()["detail"], r.text
    assert import_rows(db, second) == [] and len(db.hub_ops_list(limit=10000)) == ops
    read_only(db)


def test_hub_target_is_checked_in_the_transaction_of_start_and_accept(web, monkeypatch):
    """KIMI-12 для занесения: приложение проекта сменили в другой вкладке между чтением маршрутом и транзакцией –
    начало не ставит ни строк, ни операций; «Занести» не меняет строку."""
    pid = project(web)
    db = web.app.state.db
    row = preview_of(web, pid)
    fields = accept_fields(web, pid, row["id"])
    original_start, original_accept = db.hub_defect_import_start, hub_defects.accept_import

    def racing_start(*args, **kwargs):
        db.update_project(pid, hub_app_id=8)
        return original_start(*args, **kwargs)

    def racing_accept(*args, **kwargs):
        db.update_project(pid, hub_app_id=8)
        return original_accept(*args, **kwargs)

    monkeypatch.setattr(db, "hub_defect_import_start", racing_start)
    ops = len(db.hub_ops_list())
    r = start(web, pid, "778")
    assert r.status_code == 400 and "чтение не поставлено" in r.json()["detail"], r.text
    assert len(import_rows(db, pid)) == 1 and len(db.hub_ops_list()) == ops
    db.update_project(pid, hub_app_id=APP_ID)
    monkeypatch.setattr(hub_defects, "accept_import", racing_accept)
    r = accept(web, pid, row["id"], fields)
    assert r.status_code == 400 and "изменились после чтения" in r.json()["detail"], r.text
    assert db.hub_defect(row["id"])["state"] == "import_preview" and db.hub_defect(row["id"])["number"] is None


def test_failed_a_then_started_b_then_retry_a_is_refused(web):
    pid = project(web)
    db = web.app.state.db
    assert start(web, pid, "777").status_code == 200
    answer(web, status=500, text='{"errorMessage": "Internal"}')
    tab(web, pid)
    first = import_rows(db, pid)[0]
    assert first["state"] == "failed" and "чтение не удалось – повторите" in first["error"]
    assert 'id="hub-import-retry-form-%d"' % first["id"] in tab(web, pid)
    assert start(web, pid, "777").status_code == 200
    # у B живая строка того же дефекта: «Повторить чтение» строки A не показывается (ADR-0124 п. 9), маршрут откажет
    assert 'id="hub-import-retry-form-%d"' % first["id"] not in tab(web, pid)
    r = web.client.post(f"/projects/{pid}/hub/defects/{first['id']}/import-retry", headers=AS_JSON)
    assert r.status_code == 409 and "уже есть в приложении" in r.json()["detail"], r.text
    assert db.hub_defect(first["id"])["state"] == "failed"
    # B тоже не удалось – живой строки нет: «Повторить чтение» снова видна у обеих
    answer(web, status=500, text='{"errorMessage": "Internal"}')
    page = tab(web, pid)
    second = [x for x in import_rows(db, pid) if x["id"] != first["id"]][0]
    assert db.hub_defect(second["id"])["state"] == "failed"
    assert all('id="hub-import-retry-form-%d"' % i in page for i in (first["id"], second["id"]))
    read_only(db)


# ============================================================================ ответ чтения


@pytest.mark.parametrize("status, body, text, words", [
    (404, None, '{"errorMessage": "Not Found"}', "нет в Hub (404)"),
    (500, None, "{}", "чтение не удалось – повторите"),
    (200, None, "не JSON", "не разобран"),
    (200, defect_body(778), None, "другой дефект"),
    (200, defect_body(app_id=8), None, "не из приложения Hub проекта"),
    (200, {k: v for k, v in defect_body().items() if k != "appId"}, None, "не из приложения Hub проекта"),
    (200, {k: v for k, v in defect_body().items() if k != "linkedIssues"}, None, "состав не прочитан"),
])
def test_answer_checks_fail_the_row(web, status, body, text, words):
    pid = project(web)
    db = web.app.state.db
    assert start(web, pid, "777").status_code == 200
    answer(web, status=status, body=body, text=text)
    page = tab(web, pid)
    row = import_rows(db, pid)[0]
    assert row["state"] == "failed" and words in row["error"], row
    assert row["import_json"] == "" and row["targets_json"] == "[]" and row["number"] is None
    assert words in page and "Повторить чтение" in page
    read_only(db)


def test_empty_composition_is_accepted_and_kind_comes_from_the_title(web):
    pid = project(web)
    row = preview_of(web, pid, body=defect_body(links=(), summary="ID5 - x (SCA)"))
    snap = json.loads(row["import_json"])
    assert snap["kind"] == "SCA" and snap["linked"] == [] and snap["accepted"] == []
    row = imported(web, pid, "778", defect_body(778, links=(), summary="ID6 - x (SAST)"))
    assert row["kind"] == "SAST" and json.loads(row["targets_json"]) == [] and row["number"] == 6
    row = preview_of(web, pid, "779", defect_body(779, links=(), summary="без вида"))
    assert 'id="hub-import-accept-form-%d"' % row["id"] not in tab(web, pid)
    r = accept(web, pid, row["id"], {"op": str(row["read_op_id"]), "shown": text_hash(row["import_json"])})
    assert r.status_code == 409 and "вид не определён" in r.json()["detail"]
    read_only(web.app.state.db)


def test_redelivery_late_delivery_cancel_and_expired_lease_change_nothing(web):
    pid = project(web)
    db = web.app.state.db
    # повторная доставка уже применённого ответа
    assert start(web, pid, "777").status_code == 200
    job = take(web)
    deliver(web, job, body=defect_body())
    row = import_rows(db, pid)[0]
    assert row["state"] == "import_preview"
    assert deliver(web, job, body=defect_body(links=()))["outcome"] == "duplicate"
    assert db.hub_defect(row["id"]) == row
    # поздняя доставка после истечения аренды: строка «не принят», ответ ничего не меняет
    assert start(web, pid, "778").status_code == 200
    job = take(web)
    db.hub_expire_leases(now="2999-01-01T00:00:00+00:00")
    tab(web, pid)
    late = [r for r in import_rows(db, pid) if r["hub_defect_id"] == "778"][0]
    assert late["state"] == "failed" and "чтение не удалось – повторите" in late["error"]
    assert deliver(web, job, body=defect_body(778))["outcome"] == "late"
    assert db.hub_defect(late["id"])["state"] == "failed"
    # отмена операции до выдачи исполнителю
    assert start(web, pid, "779").status_code == 200
    cancelled = [r for r in import_rows(db, pid) if r["hub_defect_id"] == "779"][0]
    assert db.hub_cancel(cancelled["read_op_id"])
    tab(web, pid)
    cancelled = db.hub_defect(cancelled["id"])
    assert cancelled["state"] == "failed" and "операция отменена" in cancelled["error"]
    # «Повторить чтение» – новая операция, снова предпросмотр
    r = web.client.post(f"/projects/{pid}/hub/defects/{cancelled['id']}/import-retry", headers=AS_JSON)
    assert r.status_code == 200, r.text
    again = db.hub_defect(cancelled["id"])
    assert again["state"] == "import_reading" and again["read_op_id"] != cancelled["read_op_id"]
    answer(web, body=defect_body(779))
    tab(web, pid)
    assert db.hub_defect(cancelled["id"])["state"] == "import_preview"
    read_only(db)


# ============================================================================ предпросмотр


def test_preview_composition_conflicts_versions_and_hints(web):
    pid = project(web)
    db = web.app.state.db
    # 510003 – уже цель дефекта приложения в работе
    holder = db.hub_defect_insert(pid, kind="SAST", number=2, summary="ID2 - x (SAST)", anchor_hub_id="510003",
                                  targets=[{"hub_id": "510003", "issue_id": 510003, "issue_type": "SAST"}],
                                  number_keys=[], command_text="t", hub_url=HUB, app_id=APP_ID)
    row = preview_of(web, pid, body=defect_body(links=((510001, "SAST"), (510003, "SAST"), (599999, "SAST"),
                                                         (73001, "SAST"))))
    snap = json.loads(row["import_json"])
    assert snap["kind"] == "SAST" and snap["number"] == 5 and snap["command_text"] == COMMAND
    assert [a["hub_id"] for a in snap["accepted"]] == ["510001"]
    assert [a["hub_id"] for a in snap["absent"]] == ["73001", "599999"]  # 73001 – находка SCA, тип не совпал
    assert [(c["hub_id"], c["row"]) for c in snap["conflicts"]] == [("510003", holder["id"])]
    assert "незавершённой операции" in snap["conflicts"][0]["why"]
    assert snap["hints"] and "510002" in snap["hints"][0]  # 510002 назван в блоке Hub, но не в составе
    page = tab(web, pid)
    for part in (f'id="hub-import-preview-{row["id"]}"', "Предпросмотр занесения: дефект №777", "занесён из Hub",
                 f'id="hub-import-accepted-{row["id"]}"', f'id="hub-import-conflicts-{row["id"]}"',
                 f'id="hub-import-absent-{row["id"]}"', f'id="hub-import-hints-{row["id"]}"',
                 f'id="hub-import-accept-{row["id"]}"', f'id="hub-import-cancel-{row["id"]}"'):
        assert part in page, part
    assert "Тестовая команда" not in snap["command_text"]
    assert f'id="hub-import-form-problems-{row["id"]}"' in page  # первая строка – не фраза команды из «Настроек»
    # обычный предпросмотр – прежнее состояние строки: «проверьте предпросмотр», тон не задан
    assert hub_defects.view(row)["tone"] == "" and "проверьте предпросмотр" in hub_defects.view(row)["text"]
    # SAST и SCA_L при выгрузке только SAST – не поддерживается, «Занести» нет; строка – «занесение недоступно»
    other = preview_of(web, pid, "778", defect_body(778, links=((510001, "SAST"), (74001, "SCA_L"))))
    snap = json.loads(other["import_json"])
    assert snap["kind"] == "" and any("не поддерживается" in w for w in snap["warnings"])
    page = tab(web, pid)
    assert f'id="hub-import-accept-form-{other["id"]}"' not in page
    state = hub_defects.view(other)
    assert state["tone"] == "warn" and state["final"], state
    assert state["text"] == (f"Дефект №778 прочитан из Hub, занесение недоступно: {snap['kind_note']} – нажмите "
                             "«Отменить».")
    status = re.search(rf'<span [^>]*id="hub-import-status-{other["id"]}"[^>]*>(.*?)</span>', page, re.S)
    assert status and "text-warn" in status.group(0) and "занесение недоступно: вид не поддерживается" in status.group(1)
    assert "нажмите «Отменить»" in status.group(1) and "проверьте предпросмотр" not in status.group(1)
    # SCA разных версий – предупреждение
    sca = preview_of(web, pid, "779", defect_body(779, links=((73001, "SCA_S"), (73003, "SCA_S")), summary="ID7 - x (SCA)"))
    snap = json.loads(sca["import_json"])
    assert snap["kind"] == "SCA" and any(w.startswith("находки разных версий: example-parser 1.4.2, demo-xml 2.0.0")
                                         for w in snap["warnings"])
    # нет совпадений: ни одной находки из выгрузки – принимаемых нет, занести можно
    none = preview_of(web, pid, "780", defect_body(780, links=((599998, "SAST"),)))
    assert json.loads(none["import_json"])["accepted"] == []
    read_only(db)


def test_ambiguous_id_and_no_hub_block_are_warnings(web):
    pid = project(web)
    row = preview_of(web, pid, body=defect_body(summary="ID5 - x, ID6 (SAST)", description="<p>Только текст</p>"))
    snap = json.loads(row["import_json"])
    # 31.10: описание без блока Hub – текст дефекта целиком, не предупреждение
    assert snap["number"] is None and snap["command_text"] == "Только текст"
    assert any("неоднозначен" in w for w in snap["warnings"]) and not any("нет строки" in w for w in snap["warnings"])
    row = imported(web, pid, "778", defect_body(778, summary="ID5 - x, ID6 (SAST)"))
    assert row["number"] is None and web.app.state.db.next_defect_number(pid) == 1


def test_preview_author_login_and_update_ts_like_the_real_answer(web):
    """Структура ответа как у настоящего DefectDto (значения выдуманы): author – объект (берётся login), updateTs и
    createTs – целые миллисекунды эпохи, в linkedIssues – статус и прочие поля. «Изменён в Hub» – из updateTs, в ISO UTC
    и через фильтр времени; createTs запасным для «изменён» не служит, хранится полем «создан»."""
    pid = project(web)
    linked = [{"id": 510001, "appId": APP_ID, "type": "SAST", "status": "Open", "severity": 3, "isDeleted": False,
               "category": "SQL Injection", "lastScanTs": 1_699_500_000_000, "cwes": [{"id": "89", "link": ""}]}]
    body = defect_body(linkedIssues=linked, status="Registered", isActive=True, createTs=1_699_000_000_000,
                       updateTs=1_700_000_000_000, syncStatus="NOT_SYNCED", withIssues=True,
                       author={"id": 11, "login": "i.testov", "firstName": "Иван", "lastName": "Тестов"},
                       priority={"name": "Высокий", "rank": 2}, severity={"name": "High", "rank": 2})
    row = preview_of(web, pid, body=body)
    snap = json.loads(row["import_json"])
    assert snap["author"] == "i.testov"
    assert snap["modified"] == "2023-11-14T22:13:20+00:00" and snap["created"] == "2023-11-03T08:26:40+00:00"
    assert [a["hub_id"] for a in snap["accepted"]] == ["510001"]
    meta = re.search(rf'<p [^>]*id="hub-import-meta-{row["id"]}".*?</p>', tab(web, pid), re.S).group(0)
    assert "Автор в Hub: i.testov" in meta
    assert 'Изменён в Hub: <time datetime="2023-11-14T22:13:20+00:00">2023-11-14 22:13 UTC</time>' in meta, meta
    # только время создания – «изменён» пуст; не целое время – пропускается
    snap = json.loads(preview_of(web, pid, "778", defect_body(778, createTs=1_699_000_000_000))["import_json"])
    assert snap["modified"] == "" and snap["created"] == "2023-11-03T08:26:40+00:00"
    snap = json.loads(preview_of(web, pid, "779", defect_body(779, updateTs=True, updatedAt="вчера"))["import_json"])
    assert snap["modified"] == ""
    assert hub_defects.epoch_ms_iso(10 ** 30) == "" and hub_defects.epoch_ms_iso("1700000000000") == ""


# ============================================================================ «Занести»


def test_accept_reserves_the_number_and_protects_targets_without_marks(web):
    pid = project(web)
    db = web.app.state.db
    row = imported(web, pid, body=defect_body(links=((510001, "SAST"), (510002, "SAST"))))
    assert (row["origin"], row["kind"], row["number"], row["summary"]) == ("import", "SAST", 5,
                                                                            "ID5 - Внедрение SQL-кода (SAST)")
    assert row["command_text"] == COMMAND and row["confirm_op_id"] == row["read_op_id"] and row["effects_done"] == 1
    assert [t["hub_id"] for t in json.loads(row["targets_json"])] == ["510001", "510002"]
    assert row["number_keys_json"] == "[]" and row["anchor_hub_id"] == "510001" and row["closed_at"]
    assert json.loads(row["import_json"])["accepted"][0]["hub_id"] == "510001"
    # номер – резерв: новые дефекты приложения его не получат; ключам находок номер не записан
    assert db.next_defect_number(pid) == 6 and db.defect_number(pid, "sast:510001") is None
    assert db.hub_defect_bound(pid, "510001")["id"] == row["id"] and db.hub_defect_bound(pid, "510003") is None
    assert hub_defects.view(row)["final"] and hub_defects.view(row)["tone"] == "ok"
    card = web.client.get(f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510001')['id']}").text
    assert "занесён из Hub" in card and "ID5" in card and 'id="hub-defect-recheck-form"' not in card
    assert 'id="hub-defect-decision-changed"' not in card
    # повторное «Занести» той же строки – отказ, ничего не меняется
    r = accept(web, pid, row["id"], {"op": str(row["read_op_id"]), "shown": text_hash(row["import_json"])})
    assert r.status_code == 409
    read_only(db)


def test_accept_keeps_a_taken_number_with_a_note(web):
    pid = project(web)
    db = web.app.state.db
    app_row = db.hub_defect_insert(pid, kind="SAST", number=5, summary="ID5 - y (SAST)", anchor_hub_id="510003",
                                   targets=[], number_keys=[], command_text="t", hub_url=HUB, app_id=APP_ID)
    row = preview_of(web, pid)
    assert f'id="hub-import-number-{row["id"]}"' in tab(web, pid)
    r = accept(web, pid, row["id"])
    assert r.status_code == 200, r.text
    row = db.hub_defect(row["id"])
    assert row["number"] == 5 and "номер ID5 уже занят" in row["error"] and f"строка {app_row['id']}" in row["error"]
    assert "номер ID5 уже занят" in tab(web, pid)


def test_number_of_an_own_target_key_is_not_taken_by_another_sast(web):
    """Номер ID<n> за ключом собственной находки строки (заданный до занесения) – не «занят другим»: в предпросмотре
    предупреждения нет, после «Занести» пояснения нет и тон не warn. Номер за ключом посторонней находки – пояснение
    остаётся. Занесение ключам номер не пишет: таблица defects – та же."""
    pid = project(web)
    db = web.app.state.db
    db.set_defect_number(pid, "sast:510001", 5)  # своя находка дефекта №777 (ID5)
    db.set_defect_number(pid, "sast:510003", 6)  # посторонняя находка с номером дефекта №778 (ID6)
    before = defects_state(db)
    row = preview_of(web, pid)
    assert f'id="hub-import-number-{row["id"]}"' not in tab(web, pid)
    assert accept(web, pid, row["id"]).status_code == 200
    row = db.hub_defect(row["id"])
    assert row["number"] == 5 and row["error"] == "" and hub_defects.view(row)["tone"] == "ok", row["error"]
    other = preview_of(web, pid, "778", defect_body(778, links=((510002, "SAST"),), summary="ID6 - x (SAST)"))
    taken = re.search(rf'<p [^>]*id="hub-import-number-{other["id"]}"[^>]*>(.*?)</p>', tab(web, pid), re.S)
    assert taken and "номер ID6 уже занят" in taken.group(1) and "sast:510003" in taken.group(1)
    assert accept(web, pid, other["id"]).status_code == 200
    other = db.hub_defect(other["id"])
    assert "номер ID6 уже занят" in other["error"] and "sast:510003" in other["error"]
    assert hub_defects.view(other)["tone"] == "warn"
    read_only(db, before)


def test_number_of_an_own_target_key_is_not_taken_by_another_sca(web):
    """То же для SCA: ключ собственной находки – ключ её набора, как его пишет карточка (routes.sca.set_key; у отдельного
    набора – «#<номер>»); номер за ключом набора другого пакета – пояснение."""
    from app.db import NEW_SET
    from app.models import Finding
    from app.routes import sca as sca_card
    pid = project(web)
    db = web.app.state.db
    parser = Finding.from_dict(db.get_finding_by_hub_id(pid, "73001")["data"])  # example-parser 1.4.2, как и 73002
    db.move_sca_member(pid, db.sca_snapshot(pid, "73001").input_ref, "73001", NEW_SET, "", {0: 0})
    own_key = sca_card.set_key(parser, 1)
    assert own_key.endswith("#1") and hub_defects.own_number_keys(db, {"project_id": pid, "id": 0}, [{"hub_id": "73001"}]) == {own_key}
    db.set_defect_number(pid, own_key, 7)
    db.set_defect_number(pid, sca_card.set_key(parser, 0), 8)  # набор по умолчанию того же пакета – другой дефект
    before = defects_state(db)
    row = preview_of(web, pid, "779", defect_body(779, links=((73001, "SCA_S"),), summary="ID7 - x (SCA)"))
    assert json.loads(row["import_json"])["kind"] == "SCA"
    assert f'id="hub-import-number-{row["id"]}"' not in tab(web, pid)
    # номер за ключом другого набора того же пакета – занят другим
    note = hub_defects.number_note(db, row, 8, hub_defects.own_number_keys(db, {"project_id": pid, "id": 0}, [{"hub_id": "73001"}]))
    assert "номер ID8 уже занят" in note and sca_card.set_key(parser, 0) in note
    assert accept(web, pid, row["id"]).status_code == 200
    row = db.hub_defect(row["id"])
    assert row["number"] == 7 and row["error"] == "" and hub_defects.view(row)["tone"] == "ok", row["error"]
    other = preview_of(web, pid, "780", defect_body(780, links=((73003, "SCA_S"),), summary="ID8 - x (SCA)"))
    assert f'id="hub-import-number-{other["id"]}"' in tab(web, pid)
    assert accept(web, pid, other["id"]).status_code == 200
    other = db.hub_defect(other["id"])
    assert "номер ID8 уже занят" in other["error"] and sca_card.set_key(parser, 0) in other["error"]
    assert hub_defects.view(other)["tone"] == "warn"
    read_only(db, before)


def test_number_of_a_linked_finding_gone_from_the_export_is_own(web):
    """Находка, связанная в Hub с этим дефектом, которой не было в выгрузке на момент чтения, – тоже своя: номер ID<n>
    за её ключом не «занят другим» ни в предпросмотре, ни после «Занести», ни у «Применить» сверки. Посторонняя
    находка с тем же номером – пояснение, в нём только её ключ; запись снимка другого типа, с другой причиной или на
    находку, которой нет в базе, – не своя. Таблица defects – та же."""
    pid = project(web)
    db = web.app.state.db
    db.set_defect_number(pid, "sast:510001", 5)
    db.set_defect_number(pid, "sast:510002", 5)  # та же панель «Дефект для Hub», находка пропала из выгрузки
    with db._tx() as c:
        c.execute("UPDATE findings SET missing = 1 WHERE project_id = ? AND hub_id = ?", (pid, "510002"))
    before = defects_state(db)
    body = defect_body(links=((510001, "SAST"), (510002, "SAST")))
    row = preview_of(web, pid, body=body)
    snap = json.loads(row["import_json"])
    assert [a["hub_id"] for a in snap["absent"]] == ["510002"] and [a["hub_id"] for a in snap["accepted"]] == ["510001"]
    assert f'id="hub-import-number-{row["id"]}"' not in tab(web, pid)
    assert accept(web, pid, row["id"]).status_code == 200
    row = db.hub_defect(row["id"])
    assert row["number"] == 5 and row["error"] == "" and hub_defects.view(row)["tone"] == "ok", row["error"]
    read_only(db, before)
    # «Применить» сверки: пропавшая связанная находка – своя, посторонняя с тем же номером – в пояснении одна
    db.set_defect_number(pid, "sast:510003", 5)
    before = defects_state(db)
    assert sync(web, pid, row["id"]).status_code == 200
    answer(web, body=body)
    tab(web, pid)
    sync_state = json.loads(db.hub_defect(row["id"])["sync_json"])
    assert sync_state["matches"]
    unchanged = db.hub_defect(row["id"])
    assert "sast:510003" in unchanged["error"] and "sast:510002" not in unchanged["error"]
    assert "sast:510001" not in unchanged["error"]
    # Реальное изменение поля оставляет доступной проверку применения и прежних ключей номера.
    body["stage"] = "TEST"
    assert sync(web, pid, row["id"]).status_code == 200
    answer(web, body=body)
    tab(web, pid)
    sync_state = json.loads(db.hub_defect(row["id"])["sync_json"])
    assert [a["hub_id"] for a in sync_state["not_added"]] == ["510002"]
    assert apply_sync(web, pid, row["id"]).status_code == 200
    applied = db.hub_defect(row["id"])
    assert "номер ID5 уже занят" in applied["error"] and "sast:510003" in applied["error"], applied["error"]
    assert "sast:510002" not in applied["error"] and "sast:510001" not in applied["error"]
    read_only(db, before)
    # запись снимка: тип не тот – не своя; тот же тип – своя; другая причина («уже в другой строке») и находки нет в
    # базе – не своя; цель этой же строки (510001) другой строкой не считается – своя
    other = {"project_id": pid, "id": 0}
    gone = {"hub_id": "510002", "why": hub_defects.NOT_IN_EXPORT}
    assert hub_defects.own_number_keys(db, other, [], [{**gone, "issue_type": "SCA_S"}]) == set()
    assert hub_defects.own_number_keys(db, other, [], [{**gone, "issue_type": "SAST"}]) == {"sast:510002"}
    held = "уже в другой строке"
    assert hub_defects.own_number_keys(db, other, [], [{**gone, "issue_type": "SAST", "why": held}]) == set()
    assert hub_defects.own_number_keys(db, other, [], [{**gone, "hub_id": "599999", "issue_type": "SAST"}]) == set()
    mine = [{**gone, "hub_id": "510001", "issue_type": "SAST"}]
    assert hub_defects.own_number_keys(db, row, [], mine) == {"sast:510001"}


def test_linked_finding_back_in_the_export_after_the_preview_is_still_own(web):
    """Предпросмотр снят, когда связанная находка пропала из выгрузки, а к «Занести» новая выгрузка её вернула
    (missing = 0): по снимку чтения она связана в Hub с этим дефектом – номер за её ключом свой, пояснения нет ни в
    предпросмотре, ни после «Занести». Целью она не становится (цели – принимаемые находки снимка)."""
    pid = project(web)
    db = web.app.state.db
    db.set_defect_number(pid, "sast:510001", 5)
    db.set_defect_number(pid, "sast:510002", 5)
    with db._tx() as c:
        c.execute("UPDATE findings SET missing = 1 WHERE project_id = ? AND hub_id = ?", (pid, "510002"))
    before = defects_state(db)
    row = preview_of(web, pid, body=defect_body(links=((510001, "SAST"), (510002, "SAST"))))
    assert [a["hub_id"] for a in json.loads(row["import_json"])["absent"]] == ["510002"]
    with db._tx() as c:
        c.execute("UPDATE findings SET missing = 0 WHERE project_id = ? AND hub_id = ?", (pid, "510002"))
    assert f'id="hub-import-number-{row["id"]}"' not in tab(web, pid)
    assert accept(web, pid, row["id"]).status_code == 200
    row = db.hub_defect(row["id"])
    assert row["error"] == "" and hub_defects.view(row)["tone"] == "ok", row["error"]
    assert [t["hub_id"] for t in json.loads(row["targets_json"])] == ["510001"]
    read_only(db, before)


def test_number_of_a_linked_sca_finding_gone_from_the_export_is_own(web):
    """То же для SCA: связанная находка в отдельном наборе, пропавшая из выгрузки, – ключ её набора («#<номер>») свой:
    пояснения нет ни в предпросмотре, ни после «Занести». Таблица defects – та же."""
    from app.db import NEW_SET
    from app.models import Finding
    from app.routes import sca as sca_card
    pid = project(web)
    db = web.app.state.db
    parser = Finding.from_dict(db.get_finding_by_hub_id(pid, "73001")["data"])  # example-parser 1.4.2, как и 73002
    db.move_sca_member(pid, db.sca_snapshot(pid, "73001").input_ref, "73001", NEW_SET, "", {0: 0})
    db.set_defect_number(pid, sca_card.set_key(parser, 1), 7)
    with db._tx() as c:
        c.execute("UPDATE findings SET missing = 1 WHERE project_id = ? AND hub_id = ?", (pid, "73001"))
    before = defects_state(db)
    row = preview_of(web, pid, "779", defect_body(779, links=((73001, "SCA_S"), (73002, "SCA_S")),
                                                  summary="ID7 - x (SCA)"))
    snap = json.loads(row["import_json"])
    assert snap["kind"] == "SCA" and [a["hub_id"] for a in snap["absent"]] == ["73001"], snap
    assert [a["hub_id"] for a in snap["accepted"]] == ["73002"]
    assert f'id="hub-import-number-{row["id"]}"' not in tab(web, pid)
    assert accept(web, pid, row["id"]).status_code == 200
    row = db.hub_defect(row["id"])
    assert row["number"] == 7 and row["error"] == "" and hub_defects.view(row)["tone"] == "ok", row["error"]
    read_only(db, before)


def test_gone_linked_finding_held_by_another_row_is_not_own(web):
    """Пропавшую из выгрузки связанную находку держит другая строка дефекта – она не своя: номер за её ключом занят
    другим и в предпросмотре, и после «Занести»."""
    pid = project(web)
    db = web.app.state.db
    holder = db.hub_defect_insert(pid, kind="SAST", number=2, summary="ID2 - x (SAST)", anchor_hub_id="510002",
                                  targets=[{"hub_id": "510002", "issue_id": 510002, "issue_type": "SAST"}],
                                  number_keys=[], command_text="t", hub_url=HUB, app_id=APP_ID)
    db.set_defect_number(pid, "sast:510002", 5)
    with db._tx() as c:
        c.execute("UPDATE findings SET missing = 1 WHERE project_id = ? AND hub_id = ?", (pid, "510002"))
    before = defects_state(db)
    row = preview_of(web, pid, body=defect_body(links=((510001, "SAST"), (510002, "SAST"))))
    assert [a["hub_id"] for a in json.loads(row["import_json"])["absent"]] == ["510002"]
    assert db.hub_defect_holder(pid, "510002", exclude_id=row["id"])["id"] == holder["id"]
    taken = re.search(rf'<p [^>]*id="hub-import-number-{row["id"]}"[^>]*>(.*?)</p>', tab(web, pid), re.S)
    assert taken and "номер ID5 уже занят" in taken.group(1) and "sast:510002" in taken.group(1)
    assert accept(web, pid, row["id"]).status_code == 200
    row = db.hub_defect(row["id"])
    assert "номер ID5 уже занят" in row["error"] and "sast:510002" in row["error"], row["error"]
    assert hub_defects.view(row)["tone"] == "warn"
    read_only(db, before)


def test_accept_refuses_changed_composition_stale_snapshot_and_other_op(web):
    pid = project(web)
    db = web.app.state.db
    row = preview_of(web, pid, body=defect_body(links=((510001, "SAST"), (510002, "SAST"))))
    fields = accept_fields(web, pid, row["id"])
    for bad, words in (({**fields, "shown": "0" * 64}, "Предпросмотр изменился"),
                       ({**fields, "op": str(int(fields["op"]) + 999)}, "изменился в другой вкладке")):
        r = accept(web, pid, row["id"], bad)
        assert r.status_code == 409 and words in r.json()["detail"], r.text
    # находка заняла строка дефекта приложения после предпросмотра
    db.hub_defect_insert(pid, kind="SAST", number=1, summary="ID1 - x (SAST)", anchor_hub_id="510002",
                         targets=[{"hub_id": "510002", "issue_id": 510002, "issue_type": "SAST"}], number_keys=[],
                         command_text="t", hub_url=HUB, app_id=APP_ID)
    r = accept(web, pid, row["id"], fields)
    assert r.status_code == 409 and "Состав изменился – обновите предпросмотр" in r.json()["detail"], r.text
    assert "510002" in r.json()["detail"]
    assert db.hub_defect(row["id"])["state"] == "import_preview" and db.hub_defect(row["id"])["number"] is None
    # приложение проекта сменили после чтения: дефект не заносится
    db.update_project(pid, hub_app_id=8)
    r = accept(web, pid, row["id"], fields)
    assert r.status_code == 400 and "изменились после чтения" in r.json()["detail"], r.text
    # «Отменить» – строка отменена, тот же номер заносится заново
    r = web.client.post(f"/projects/{pid}/hub/defects/{row['id']}/import-cancel", headers=AS_JSON)
    assert r.status_code == 200 and db.hub_defect(row["id"])["state"] == "cancelled"
    db.update_project(pid, hub_app_id=APP_ID)
    assert start(web, pid, "777").status_code == 200
    read_only(db)


def test_failure_in_the_middle_of_accept_changes_nothing(web):
    pid = project(web)
    db = web.app.state.db
    row = preview_of(web, pid)

    def boom(c) -> None:
        c.execute("UPDATE hub_defects SET summary = 'частично' WHERE id = ?", (row["id"],))
        raise sqlite3.OperationalError("disk I/O error")

    with pytest.raises(sqlite3.OperationalError):
        hub_defects.accept_import(db, row, op_id=int(row["read_op_id"]), shown=text_hash(row["import_json"]),
                                  target_check=boom)
    assert db.hub_defect(row["id"]) == row and db.next_defect_number(pid) == 1
    assert hub_defects.accept_import(db, row, op_id=int(row["read_op_id"]),
                                     shown=text_hash(row["import_json"]))["number"] == 5
    assert db.next_defect_number(pid) == 6


def test_recheck_of_an_imported_defect_is_refused_with_the_sync_hint(web):
    """«Проверить в Hub» (ADR-0121 п. 6) к занесённому дефекту не применяется (ADR-0124 п. 9): маршрут отказывает 409 с
    подсказкой «Pull из Hub» – и из карточки, и из вкладки; операция чтения не ставится, строка не меняется."""
    pid = project(web)
    db = web.app.state.db
    row = imported(web, pid)
    ops = len(db.hub_ops_list(limit=10000))
    for data in ({}, {"back": "defects"}):
        r = web.client.post(f"/projects/{pid}/hub/defects/{row['id']}/recheck", data=data, headers=AS_JSON)
        assert r.status_code == 409, r.text
        assert "у занесённого дефекта – «Pull из Hub» во вкладке «Дефекты»" in r.json()["detail"], r.text
    assert len(db.hub_ops_list(limit=10000)) == ops and take(web) is None
    fresh = db.hub_defect(row["id"])
    assert (fresh["state"], fresh["verify_op_id"], fresh["verify_json"]) == ("done", None, row["verify_json"])
    read_only(db)


# ============================================================================ защита и группа


def test_imported_targets_are_guarded_and_group_gets_no_second_defect(web):
    pid = pair_project(web)  # 510001 и 510005 – одна группа «та же строка, категория и код»
    db = web.app.state.db
    row = imported(web, pid, body=defect_body(links=((510001, "SAST"),)))
    # ADR-0121: смена решения находки занесённого дефекта – только с подтверждением
    fid = db.get_finding_by_hub_id(pid, "510001")["id"]
    card = web.client.get(f"/projects/{pid}/findings/{fid}").text
    data = {"finding_version": re.search(r'name="finding_version" value="([^"]*)"', card).group(1),
            "verdict_id": re.search(r'name="verdict_id" value="([^"]*)"', card).group(1),
            "review_revision": re.search(r'name="review_revision" value="(\d+)"', card).group(1),
            "decision": "true_positive", "final_verdict": "", "comment": REASON, "fix": FIX, "reviewed": "1",
            "action": "save"}
    r = web.client.post(f"/projects/{pid}/findings/{fid}/review", headers=AS_JSON, data=data)
    assert r.status_code == 409 and r.json()["reason"] == "defect" and "№777 (ID5)" in r.json()["detail"], r.text
    # новая находка группы: «Привязать» к занесённому не предлагается, второй дефект – отказ с подсказкой
    url, _ = save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    card = web.client.get(url).text
    assert 'id="hub-defect-link-form"' not in card and 'id="hub-defect-form"' in card
    r = blank(web, url)
    assert r.status_code == 400, r.text
    assert ("(занесён из Hub): привяжите находку к нему в Hub и нажмите «Pull из Hub» во вкладке «Дефекты» – находка "
            "добавится" in r.json()["detail"]), r.text
    assert "№777 (ID5)" in r.json()["detail"] and "Отменить предпросмотр" not in r.json()["detail"]
    # серверный «Привязать» к занесённому – отказ, ничего не ставится
    r = web.client.post(f"{url}/hub-defect-link", headers=AS_JSON,
                        data={**shown(web, url), "defect": str(row["id"]), "targets": "510005"})
    assert r.status_code == 400 and "Дефект группы изменился" in r.json()["detail"], r.text
    assert not [o for o in db.hub_ops_list() if o["purpose"] in ("defect_blank", "defect_link")]
    read_only(db)


def test_create_from_preview_with_an_imported_group_defect_tells_to_cancel_the_preview_first(web):
    """Отказ второго дефекта по группе с занесённым при открытом предпросмотре: сначала «Отменить предпросмотр» (он
    держит находку целью – сверка её не добавит), затем привязать находку в Hub и «Pull из Hub»; предпросмотр цел,
    POST создания не поставлен."""
    pid = pair_project(web)  # 510001 и 510005 – одна группа «та же строка, категория и код»
    db = web.app.state.db
    url_b, _ = save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    row_b = to_preview(web, pid, url_b)
    imported(web, pid, body=defect_body(links=((510001, "SAST"),)))
    r = create(web, pid, row_b["id"])
    assert r.status_code == 400, r.text
    detail = r.json()["detail"]
    assert ("(занесён из Hub): нажмите «Отменить предпросмотр», затем привяжите находку к нему в Hub и нажмите «Pull из "
            "Hub» во вкладке «Дефекты» – находка добавится" in detail), detail
    assert "№777 (ID5)" in detail
    assert db.hub_defect(row_b["id"])["state"] == "preview"
    assert not [o for o in db.hub_ops_list() if o["purpose"] in ("defect_create", "defect_link")]


# ============================================================================ «Pull из Hub»


def test_sync_adds_only_and_keeps_the_row_done(web):
    pid = project(web)
    db = web.app.state.db
    row = imported(web, pid, body=defect_body(links=((510001, "SAST"),)))
    r = sync(web, pid, row["id"])
    assert r.status_code == 200, r.text
    syncing = db.hub_defect(row["id"])
    assert syncing["sync_op_id"] and syncing["state"] == "done" and syncing["targets_json"] == row["targets_json"]
    assert db.hub_defect_bound(pid, "510001")["id"] == row["id"]  # защита на время сверки сохраняется
    assert not hub_defects.view(syncing)["final"] and "Сверяю с Hub" in hub_defects.view(syncing)["text"]
    assert sync(web, pid, row["id"]).status_code == 409  # вторая сверка не ставится
    assert 'data-poll="/projects/%d/hub/defects/%d"' % (pid, row["id"]) in tab(web, pid)
    answer(web, body=defect_body(summary="ID9 - Внедрение SQL-кода (SAST)",
                                 links=((510002, "SAST"), (73001, "SCA_S"), (599999, "SAST"))))
    tab(web, pid)
    after = db.hub_defect(row["id"])
    assert after["sync_op_id"] is None and after["state"] == "done" and after["number"] == 5
    state = json.loads(after["sync_json"])
    assert [a["hub_id"] for a in state["added"]] == ["510002"]
    assert [(e["hub_id"], e["why"]) for e in state["incompatible"]] == [("73001", "несовместима с видом дефекта")]
    assert [e["hub_id"] for e in state["not_added"]] == ["599999"]
    assert [(e["hub_id"], e["why"]) for e in state["unobserved"]] == [
        ("510001", "в Hub больше не связана с дефектом (или её статус не Open) – уберётся из состава")]
    assert state["number_changed"] and state["read"]["number"] == 9
    page = tab(web, pid)
    assert f'id="hub-sync-preview-{row["id"]}"' in page and f'id="hub-sync-unobserved-{row["id"]}"' in page
    # повторный запуск после результата – новый предпросмотр
    assert sync(web, pid, row["id"]).status_code == 200 and db.hub_defect(row["id"])["sync_json"] == ""
    answer(web, body=defect_body(summary="ID9 - Внедрение SQL-кода (SAST)",
                                 links=((510001, "SAST"), (510002, "SAST"))))
    tab(web, pid)
    r = apply_sync(web, pid, row["id"])
    assert r.status_code == 200, r.text
    applied = db.hub_defect(row["id"])
    assert [t["hub_id"] for t in json.loads(applied["targets_json"])] == ["510001", "510002"]
    assert applied["number"] == 9 and applied["summary"].startswith("ID9") and applied["sync_json"] == ""
    assert db.next_defect_number(pid) == 10 and db.hub_defect_bound(pid, "510002")["id"] == row["id"]
    r = apply_sync(web, pid, row["id"], text_hash(after["sync_json"]))  # повторное «Применить» – отказ
    assert r.status_code == 409 and "Применять нечего" in r.json()["detail"]
    read_only(db)


def test_sync_apply_does_not_count_own_target_keys_as_taken(web):
    """«Применить» сверки: номер ID<n> за ключом добавляемой находки или прежней цели – свой, пояснения нет; за ключом
    посторонней находки – пояснение, в нём только чужой ключ."""
    pid = project(web)
    db = web.app.state.db
    row = imported(web, pid, body=defect_body(links=((510001, "SAST"),)))
    db.set_defect_number(pid, "sast:510001", 9)  # прежняя цель
    db.set_defect_number(pid, "sast:510002", 9)  # придёт добавляемой
    before = defects_state(db)
    assert sync(web, pid, row["id"]).status_code == 200
    answer(web, body=defect_body(summary="ID9 - Внедрение SQL-кода (SAST)", links=((510001, "SAST"), (510002, "SAST"))))
    tab(web, pid)
    assert [a["hub_id"] for a in json.loads(db.hub_defect(row["id"])["sync_json"])["added"]] == ["510002"]
    assert apply_sync(web, pid, row["id"]).status_code == 200
    applied = db.hub_defect(row["id"])
    assert applied["number"] == 9 and applied["error"] == "" and hub_defects.view(applied)["tone"] == "ok", applied
    read_only(db, before)
    # посторонняя находка с тем же номером – пояснение при следующем «Применить»
    db.set_defect_number(pid, "sast:510003", 9)
    before = defects_state(db)
    assert sync(web, pid, row["id"]).status_code == 200
    answer(web, body=defect_body(summary="ID9 - Внедрение SQL-кода (SAST)", links=((510001, "SAST"), (510002, "SAST"))))
    tab(web, pid)
    assert json.loads(db.hub_defect(row["id"])["sync_json"])["matches"]
    applied = db.hub_defect(row["id"])
    assert "номер ID9 уже занят" in applied["error"] and "sast:510003" in applied["error"], applied["error"]
    assert "sast:510001" not in applied["error"] and "sast:510002" not in applied["error"]
    assert hub_defects.view(applied)["tone"] == "warn"
    read_only(db, before)


def test_sync_lease_expiry_cancel_and_stale_apply(web):
    pid = project(web)
    db = web.app.state.db
    row = imported(web, pid, body=defect_body(links=((510001, "SAST"),)))
    assert sync(web, pid, row["id"]).status_code == 200
    job = take(web)
    db.hub_expire_leases(now="2999-01-01T00:00:00+00:00")
    tab(web, pid)
    after = db.hub_defect(row["id"])
    assert after["sync_op_id"] is None and after["state"] == "done" and after["targets_json"] == row["targets_json"]
    assert "чтение не удалось – повторите" in json.loads(after["sync_json"])["error"]
    assert "сверка с Hub: чтение не удалось" in tab(web, pid)
    assert deliver(web, job, body=defect_body(links=((510002, "SAST"),)))["outcome"] == "late"
    assert db.hub_defect(row["id"])["sync_json"] == after["sync_json"]
    # предпросмотр, «Отменить» – sync_json пуст, применять нечего
    assert sync(web, pid, row["id"]).status_code == 200
    answer(web, body=defect_body(links=((510001, "SAST"), (510002, "SAST"))))
    tab(web, pid)
    shown_value = text_hash(db.hub_defect(row["id"])["sync_json"])
    assert cancel_fields(web, pid, row["id"]) == {"shown": shown_value}  # форма «Отменить» передаёт показанный снимок
    r = cancel_sync(web, pid, row["id"], shown_value)
    assert r.status_code == 200 and db.hub_defect(row["id"])["sync_json"] == ""
    assert apply_sync(web, pid, row["id"], shown_value).status_code == 409
    # добавляемая находка занята после сверки – «Применить» отказывает, цели прежние
    assert sync(web, pid, row["id"]).status_code == 200
    answer(web, body=defect_body(links=((510001, "SAST"), (510002, "SAST"))))
    tab(web, pid)
    db.hub_defect_insert(pid, kind="SAST", number=1, summary="ID1 - x (SAST)", anchor_hub_id="510002",
                         targets=[{"hub_id": "510002", "issue_id": 510002, "issue_type": "SAST"}], number_keys=[],
                         command_text="t", hub_url=HUB, app_id=APP_ID)
    r = apply_sync(web, pid, row["id"])
    assert r.status_code == 409 and "Состав изменился после сверки" in r.json()["detail"], r.text
    assert db.hub_defect(row["id"])["targets_json"] == row["targets_json"]
    read_only(db)


def test_sync_cancel_from_an_old_tab_keeps_the_newer_preview(web):
    """«Отменить» сверки – по показанному снимку: вкладка A показала S1, вкладка B запустила сверку заново и получила
    S2 – «Отменить» из A отказывает, S2 цел; «Отменить» из B – предпросмотр снят."""
    pid = project(web)
    db = web.app.state.db
    row = imported(web, pid, body=defect_body(links=((510001, "SAST"),)))
    assert sync(web, pid, row["id"]).status_code == 200
    answer(web, body=defect_body(links=((510001, "SAST"), (510002, "SAST"))))
    shown_a = cancel_fields(web, pid, row["id"])["shown"]  # вкладка A
    assert sync(web, pid, row["id"]).status_code == 200  # вкладка B
    answer(web, body=defect_body(summary="ID9 - Внедрение SQL-кода (SAST)", links=((510001, "SAST"), (510002, "SAST"))))
    shown_b = cancel_fields(web, pid, row["id"])["shown"]
    s2 = db.hub_defect(row["id"])["sync_json"]
    assert s2 and shown_b == text_hash(s2) != shown_a
    for stale in (shown_a, ""):  # старая вкладка и форма без поля shown
        r = cancel_sync(web, pid, row["id"], stale)
        assert r.status_code == 409 and "Предпросмотр изменился" in r.json()["detail"], r.text
        assert db.hub_defect(row["id"])["sync_json"] == s2
    assert apply_sync(web, pid, row["id"], shown_a).status_code == 409  # и «Применить» из A – тоже
    assert cancel_sync(web, pid, row["id"], shown_b).status_code == 200
    after = db.hub_defect(row["id"])
    assert after["sync_json"] == "" and after["state"] == "done" and after["targets_json"] == row["targets_json"]
    read_only(db)


def test_retry_and_sync_buttons_only_when_a_read_can_be_queued(web):
    """«Повторить чтение» и «Pull из Hub» во вкладке – только когда чтение можно поставить: нет блокировки отправки и
    строка того же Hub и приложения, что сейчас у проекта (иначе маршрут всё равно откажет)."""
    pid = project(web)
    db = web.app.state.db
    done = imported(web, pid, body=defect_body(links=((510001, "SAST"),)))
    assert start(web, pid, "778").status_code == 200
    answer(web, status=500, text="{}")
    tab(web, pid)
    failed = [r for r in import_rows(db, pid) if r["hub_defect_id"] == "778"][0]
    assert failed["state"] == "failed"
    buttons = (f'id="hub-sync-form-{done["id"]}"', f'id="hub-import-retry-form-{failed["id"]}"')
    page = tab(web, pid)
    assert all(b in page for b in buttons)
    changes = (("другое приложение", lambda: db.update_project(pid, hub_app_id=8),
                lambda: db.update_project(pid, hub_app_id=APP_ID)),
               ("другой адрес Hub", lambda: db.set_settings({"hub_url": "https://hub2.example.org"}),
                lambda: db.set_settings({"hub_url": HUB})),
               ("адрес Hub не задан", lambda: db.set_settings({"hub_url": ""}),
                lambda: db.set_settings({"hub_url": HUB})))
    for what, change, undo in changes:
        change()
        page = tab(web, pid)
        assert not any(b in page for b in buttons), what
        assert 'id="hub-import-numbers"' not in page, "формы номеров нет (0.10.0.dev13)"
        undo()
        assert all(b in tab(web, pid) for b in buttons), what


@pytest.mark.parametrize("change", ["app", "hub"])
@pytest.mark.parametrize("action", ["retry", "sync", "apply"])
def test_hub_target_is_checked_in_the_transaction_of_retry_sync_and_apply(web, monkeypatch, action, change):
    """KIMI-12 для «Повторить чтение», «Pull из Hub» и «Применить»: маршрут сверил приложение и адрес Hub строки, их
    сменили в другой вкладке до транзакции – отказ 400 из hub_target_check; строка и очередь не изменились."""
    pid = project(web)
    db = web.app.state.db
    shown_value = ""
    if action == "retry":
        assert start(web, pid, "777").status_code == 200
        answer(web, status=500, text="{}")
        tab(web, pid)
        row = import_rows(db, pid)[0]
        assert row["state"] == "failed"
        name = "retry_import"

        def post():
            return web.client.post(f"/projects/{pid}/hub/defects/{row['id']}/import-retry", headers=AS_JSON)
    else:
        row = imported(web, pid, body=defect_body(links=((510001, "SAST"),)))
        name = "start_import_sync"
        if action == "apply":
            assert sync(web, pid, row["id"]).status_code == 200
            answer(web, body=defect_body(links=((510001, "SAST"), (510002, "SAST"))))
            tab(web, pid)
            name, shown_value = "apply_import_sync", text_hash(db.hub_defect(row["id"])["sync_json"])

        def post():
            return (apply_sync(web, pid, row["id"], shown_value) if action == "apply" else sync(web, pid, row["id"]))
    original = getattr(hub_defects, name)

    def racing(*args, **kwargs):
        if change == "app":
            db.update_project(pid, hub_app_id=8)
        else:
            db.set_settings({"hub_url": "https://hub2.example.org"})
        return original(*args, **kwargs)

    monkeypatch.setattr(hub_defects, name, racing)
    before, ops = db.hub_defect(row["id"]), len(db.hub_ops_list())
    r = post()
    assert r.status_code == 400 and "изменились после" in r.json()["detail"], r.text
    assert db.hub_defect(row["id"]) == before and len(db.hub_ops_list()) == ops
    read_only(db)


def test_import_routes_need_hub_settings_and_an_import_row(web):
    pid = prepared(web)
    page = tab(web, pid)
    assert 'id="hub-import-form"' not in page, "формы номеров нет (0.10.0.dev13), маршрут остаётся для прежних строк"
    r = start(web, pid, "777")
    assert r.status_code == 400 and "Адрес Hub не задан" in r.json()["detail"]
    hub_settings(web, pid)
    assert 'id="hub-import-form"' not in tab(web, pid) and 'id="hub-sync-start"' in tab(web, pid)
    db = web.app.state.db
    app_row = db.hub_defect_insert(pid, kind="SAST", number=1, summary="ID1 - x (SAST)", anchor_hub_id="510001",
                                   targets=[], number_keys=[], command_text="t", hub_url=HUB, app_id=APP_ID)
    for action in ("import", "import-cancel", "import-retry", "sync", "sync-apply", "sync-cancel"):
        r = web.client.post(f"/projects/{pid}/hub/defects/{app_row['id']}/{action}", headers=AS_JSON)
        assert r.status_code == 404, (action, r.text)
    # без скрипта – возврат во вкладку с сообщением
    r = web.client.post(f"/projects/{pid}/defects/import", data={"numbers": "777"}, headers=ORIGIN,
                        follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/projects/{pid}/defects?ok=hub_import_queued"


def test_single_sync_brings_the_composition_to_hub(web):
    """Принятый объект Hub уже без находки, а состав приложения – с ней; «Pull из Hub»
    не говорит «совпадает», «Применить» убирает находку из состава с пометкой «выбыла из дефекта» (принцип
    «источник истины – Hub»); повторная сверка – совпадает."""
    pid = project(web)
    db = web.app.state.db
    row = imported(web, pid, body=defect_body(links=((510001, "SAST"), (510002, "SAST"))))
    obj = json.loads(row["confirmed_object_json"])
    obj["linkedIssues"] = [link for link in obj["linkedIssues"] if link["id"] != 510001]
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET confirmed_object_json=? WHERE id=?", (json.dumps(obj), row["id"]))
    assert sync(web, pid, row["id"]).status_code == 200
    answer(web, body=defect_body(links=((510002, "SAST"),)))
    page = tab(web, pid)
    state = json.loads(db.hub_defect(row["id"])["sync_json"])
    assert not state.get("matches") and [e["hub_id"] for e in state["unobserved"]] == ["510001"]
    assert f'id="hub-sync-unobserved-{row["id"]}"' in page and "Уберутся из состава" in page
    assert apply_sync(web, pid, row["id"]).status_code == 200
    applied = db.hub_defect(row["id"])
    assert [t["hub_id"] for t in json.loads(applied["targets_json"])] == ["510002"]
    info = db.get_review(pid, "510001")["dropped_info"]
    assert info["via"] == "sync" and info["defect_id"] == applied["id"]
    assert not (db.get_review(pid, "510002") or {}).get("dropped_info")
    assert sync(web, pid, row["id"]).status_code == 200
    answer(web, body=defect_body(links=((510002, "SAST"),)))
    tab(web, pid)
    assert json.loads(db.hub_defect(row["id"])["sync_json"]).get("matches")


def test_single_sync_removal_keeps_type_number_and_anchor(web):
    """Ревью 31.10, круг 1: выбывшая находка снимает номер прежнего ID<n>, даже если Hub сменил номер; ушедшая связь
    другого типа с тем же номером не помечает локальную находку; якорь – из нового состава; «номер занят» не пишется."""
    pid = project(web)
    db = web.app.state.db
    row = imported(web, pid, body=defect_body(links=((510001, "SAST"), (510002, "SAST"))))
    with db._tx() as c:  # как после подтверждённого обновления: номер ID5 у ключей, другая связь SCA_S:510002
        c.execute("UPDATE hub_defects SET number_keys_json=?, anchor_hub_id='510001' WHERE id=?",
                  (json.dumps(["sast:510001", "sast:510002"]), row["id"]))
        targets = json.loads(row["targets_json"]) + [{"hub_id": "510002", "issue_id": 510002, "issue_type": "SCA_S"}]
        c.execute("UPDATE hub_defects SET targets_json=? WHERE id=?", (json.dumps(targets), row["id"]))
    db.set_defect_number(pid, "sast:510001", 5)
    db.set_defect_number(pid, "sast:510002", 5)
    assert sync(web, pid, row["id"]).status_code == 200
    answer(web, body=defect_body(summary="ID9 - Внедрение SQL-кода (SAST)", links=((510002, "SAST"),)))
    tab(web, pid)
    assert apply_sync(web, pid, row["id"]).status_code == 200
    applied = db.hub_defect(row["id"])
    assert [(t["hub_id"], t["issue_type"]) for t in json.loads(applied["targets_json"])] == [("510002", "SAST")]
    assert applied["anchor_hub_id"] == "510002" and applied["number"] == 9
    assert db.defect_number(pid, "sast:510001") is None, "номер ID5 выбывшей снят по прежнему номеру"
    assert json.loads(applied["number_keys_json"]) == ["sast:510002"]
    assert "занят" not in str(applied.get("error") or "")
    assert db.get_review(pid, "510001")["dropped_info"]["via"] == "sync"
    assert not (db.get_review(pid, "510002") or {}).get("dropped_info"), "ушла связь SCA_S:510002, SAST:510002 в составе"


def test_card_releases_a_stuck_number_only_by_the_operator(web):
    """Номер ID5 остался за ключом находки вне состава дефекта – карточка называет его и
    снимает только по кнопке оператора; номер своей находки остаётся."""
    from test_web import ORIGIN
    pid = project(web)
    db = web.app.state.db
    row = imported(web, pid, body=defect_body(links=((510002, "SAST"),)))
    db.set_defect_number(pid, "sast:510001", 5)  # остался от выбывшей находки
    db.set_defect_number(pid, "sast:510002", 5)  # своя
    card = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    assert 'id="defect-foreign-number"' in card and "находка 510001" in card and "находка 510002" not in card
    assert db.defect_number(pid, "sast:510001") == 5, "без кнопки номер не снимается"
    stamp = {r["defect_key"]: r["assigned_at"] for r in db._all("SELECT defect_key, assigned_at FROM defects")}
    assert f'name="assigned_at" value="{stamp["sast:510001"]}"' in card and 'name="releases" value="0"' in card
    stale = web.client.post(f"/projects/{pid}/defects/{row['id']}/release-number", headers=ORIGIN,
                            data={"number": "6", "key": "sast:510001", "assigned_at": stamp["sast:510001"], "releases": "0"},
                            follow_redirects=False)
    assert stale.status_code == 409 and db.defect_number(pid, "sast:510001") == 5
    own = web.client.post(f"/projects/{pid}/defects/{row['id']}/release-number", headers=ORIGIN,
                          data={"number": "5", "key": "sast:510002", "assigned_at": stamp["sast:510002"], "releases": "0"},
                          follow_redirects=False)
    assert own.status_code == 409 and db.defect_number(pid, "sast:510002") == 5, "свой ключ не снимается"
    other = web.client.post(f"/projects/{pid}/defects/{row['id']}/release-number", headers=ORIGIN,
                            data={"number": "5", "key": "sast:510001", "assigned_at": "2000-01-01T00:00:00Z", "releases": "0"},
                            follow_redirects=False)
    assert other.status_code == 409 and db.defect_number(pid, "sast:510001") == 5, "другое назначение не снимается"
    done = web.client.post(f"/projects/{pid}/defects/{row['id']}/release-number", headers=ORIGIN,
                           data={"number": "5", "key": "sast:510001", "assigned_at": stamp["sast:510001"], "releases": "0"},
                           follow_redirects=False)
    assert done.status_code == 303 and "number_released" in done.headers["location"]
    # ревью 31.10, круг 4: номер выдан заново в ту же секунду – повтор старой формы всё равно отказ
    with db._tx() as c:
        c.execute("INSERT INTO defects(project_id, defect_key, number, updated_at, assigned_at) VALUES (?,?,5,?,?)",
                  (pid, "sast:510001", stamp["sast:510001"], stamp["sast:510001"]))
    replay = web.client.post(f"/projects/{pid}/defects/{row['id']}/release-number", headers=ORIGIN,
                             data={"number": "5", "key": "sast:510001", "assigned_at": stamp["sast:510001"], "releases": "0"},
                             follow_redirects=False)
    assert replay.status_code == 409 and db.defect_number(pid, "sast:510001") == 5
    # отменённый предпросмотр ключ не держит: новая форма снимает
    with db._tx() as c:
        c.execute("INSERT INTO hub_defects(project_id,kind,state,origin,hub_url,app_id,number_keys_json,created_at,updated_at)"
                  " SELECT project_id,kind,'cancelled','app',hub_url,app_id,?,created_at,updated_at FROM hub_defects WHERE id=?",
                  ('["sast:510001"]', row["id"]))
    fresh = web.client.get(f"/projects/{pid}/defects/{row['id']}").text
    assert 'name="releases" value="1"' in fresh
    again = web.client.post(f"/projects/{pid}/defects/{row['id']}/release-number", headers=ORIGIN,
                            data={"number": "5", "key": "sast:510001", "assigned_at": stamp["sast:510001"], "releases": "1"},
                            follow_redirects=False)
    assert again.status_code == 303 and db.defect_number(pid, "sast:510001") is None
    assert db.defect_number(pid, "sast:510001") is None and db.defect_number(pid, "sast:510002") == 5
    assert 'id="defect-foreign-number"' not in web.client.get(f"/projects/{pid}/defects/{row['id']}").text


def test_single_sync_after_renumbering_and_with_other_type_link_releases_the_number(web):
    """Ревью 31.10, круг 2: Hub перенумеровал дефект (ID5 → ID9) первой сверкой, второй убрал находку – её прежний
    номер ID5 снимается; оставшаяся связь другого типа (SCA_S:X) не держит ключ локальной SAST-находки X."""
    pid = project(web)
    db = web.app.state.db
    row = imported(web, pid, body=defect_body(links=((510001, "SAST"), (510002, "SAST"))))
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET number_keys_json=? WHERE id=?",
                  (json.dumps(["sast:510001", "sast:510002"]), row["id"]))
    db.set_defect_number(pid, "sast:510001", 5)
    db.set_defect_number(pid, "sast:510002", 5)
    renamed = defect_body(summary="ID9 - Внедрение SQL-кода (SAST)", links=((510001, "SAST"), (510002, "SAST")))
    assert sync(web, pid, row["id"]).status_code == 200
    answer(web, body=renamed)
    tab(web, pid)
    assert apply_sync(web, pid, row["id"]).status_code == 200 and db.hub_defect(row["id"])["number"] == 9
    assert db.defect_number(pid, "sast:510001") == 9, "ключи записи догоняют перенумерацию"
    db.set_defect_number(pid, "sast:510003", 12)  # ручной номер другой находки не трогается
    assert sync(web, pid, row["id"]).status_code == 200
    answer(web, body=defect_body(summary="ID9 - Внедрение SQL-кода (SAST)", links=((510002, "SAST"), (510001, "SCA_S"))))
    tab(web, pid)
    assert apply_sync(web, pid, row["id"]).status_code == 200
    assert db.defect_number(pid, "sast:510001") is None, "номер выбывшей снят и после перенумерации"
    assert db.defect_number(pid, "sast:510003") == 12
    assert json.loads(db.hub_defect(row["id"])["number_keys_json"]) == ["sast:510002"]


def test_removal_keeps_a_number_reassigned_by_hand(web):
    """Ревью 31.10, круг 3: ключу выбывающей находки после выдачи номера дефекта вручную выдали другой номер (ID12) –
    «Применить» его не снимает: снимается только номер этого дефекта."""
    pid = project(web)
    db = web.app.state.db
    row = imported(web, pid, body=defect_body(links=((510001, "SAST"), (510002, "SAST"))))
    with db._tx() as c:
        c.execute("UPDATE hub_defects SET number_keys_json=? WHERE id=?",
                  (json.dumps(["sast:510001", "sast:510002"]), row["id"]))
    db.set_defect_number(pid, "sast:510001", 12)
    db.set_defect_number(pid, "sast:510002", 5)
    assert sync(web, pid, row["id"]).status_code == 200
    answer(web, body=defect_body(links=((510002, "SAST"),)))
    tab(web, pid)
    assert apply_sync(web, pid, row["id"]).status_code == 200
    assert db.defect_number(pid, "sast:510001") == 12 and db.defect_number(pid, "sast:510002") == 5
