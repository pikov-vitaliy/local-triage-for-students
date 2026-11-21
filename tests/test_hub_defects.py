"""Дефект в Hub из карточки (ADR-0120): тело дефекта из заготовки (HTML-экранирование, заголовок, приоритет), цепочка
операций на поддельном исполнителе (заготовка → создание → чтение; чтение без привязки → привязка → чтение), отметка
«Внесено в Hub» части «тело дефекта» только по подтверждению чтением, сверка «результата неизвестен» по списку
дефектов, состав группы SAST с причинами исключения, дефект набора SCA, отказы, вкладка «Дефекты», схема 26.
Данные, адреса и номера выдуманы."""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlsplit

import pytest

from app import hub_defects
from hub_fixtures import SAST_ROWS, make_hub_xlsx
from test_defect import save_sast
from test_hub_status_routes import AS_JSON, HUB, worker_headers
from test_sca import sca_text_ready
from test_sca_package_decision import UPD, post_package
from test_web import ORIGIN, create_project, prepared, start_run, upload, wait_run, web  # noqa: F401

REASON = "Подтверждено: owner из запроса подставляется в SQL-запрос конкатенацией."
FIX = "Параметризовать запрос."
TITLE = "ID1 - Внедрение SQL-кода (SAST)"
HUB_DESCRIPTION = "<p>Информация об объекте сканирования:</p><p>demo</p>"
BLANK = {"summary": "заготовка Hub", "description": HUB_DESCRIPTION, "priority": {"name": "Major", "rank": 2},
         "severity": {"name": "Medium", "rank": 2}, "source": "Tool", "stage": "DEV", "type": "Software",
         "status": "Registered", "linkedIssues": [{"id": 510001, "type": "SAST"}]}
SERVICE = {"statuses": [{"name": "Registered", "rank": 0}, {"name": "Open", "rank": 1}],
           "priorities": [{"name": "Blocker", "rank": 0}, {"name": "Critical", "rank": 1}, {"name": "Major", "rank": 2},
                          {"name": "Minor", "rank": 3}, {"name": "Info", "rank": 4}]}


# ============================================================================ помощники


def hello(web, login: str = "user1") -> None:
    r = web.client.post("/api/hub/worker/hello", headers=worker_headers(web), content=json.dumps(
        {"worker_id": "w1", "hub_url": HUB, "hub_user": "Иван Тестов", "hub_login": login, "roles": ["DEVELOPER"]}))
    assert r.status_code == 200, r.text


def hub_job(web, status: int = 200, body: dict | None = None, error: str = "", headers: dict | None = None, raw: bool = False,
            match_blank: bool = False) -> dict:
    """Поддельный исполнитель: забирает одно задание и отвечает (с worker_id – для записи «кто создал»)."""
    job = web.client.get("/api/hub/jobs", params={"worker_id": "w1", "hub_url": HUB, "wait": 0},
                         headers=worker_headers(web)).json()["job"]
    assert job is not None, "в очереди нет задания"
    if match_blank:
        query = parse_qs(urlsplit(job["path"]).query)
        body = {**BLANK, "linkedIssues": [{"id": int(i), "type": query["type"][0]}
                                          for i in query["issueIds"][0].split(",")]}
    # Схема 29 подтверждает также текст: обычный ответ стенда содержит полный текст дефекта.
    # raw=True оставляет ответ намеренно неполным для отрицательных сценариев.
    if not raw and job["purpose"] == "defect_read" and isinstance(body, dict) and body.get("id"):
        body = {"appId": job["app_id"], **body}
    if not raw and job["purpose"] == "defect_read" and isinstance(body, dict) and body.get("id") and "description" not in body:
        row = web.app.state.db._one("SELECT * FROM hub_defects WHERE hub_defect_id = ? ORDER BY id DESC LIMIT 1",
                                    (str(body["id"]),))
        if row:
            body = {"summary": row["summary"], "description": row["body_html"] or
                    hub_defects.description_html(row["command_text"], HUB_DESCRIPTION), **body}
    r = web.client.post(f"/api/hub/jobs/{job['attempt_id']}/result", headers=worker_headers(web), content=json.dumps(
        {"lease_token": job["lease_token"], "worker_id": "w1", "status": status, "headers": headers or {},
         "body_text": json.dumps(body or {}, ensure_ascii=False), "error": error}))
    assert r.status_code == 200, r.text
    return job


def no_job(web) -> None:
    job = web.client.get("/api/hub/jobs", params={"worker_id": "w1", "hub_url": HUB, "wait": 0},
                         headers=worker_headers(web)).json()["job"]
    assert job is None, job


def hub_settings(web, pid: int) -> None:
    db = web.app.state.db
    db.set_settings({"team_name": "Платформа", "hub_url": HUB})
    db.update_project(pid, hub_app_id=7)


def sast_ready(web) -> tuple[int, str]:
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    hub_settings(web, pid)
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    return pid, url


def shown(web, url: str) -> dict:
    card = web.client.get(url).text
    return {"review_revision": re.search(r'name="review_revision" value="(\d+)"', card).group(1),
            "text_hash": re.search(r'id="hub-defect-text-hash" value="([^"]*)"', card).group(1)}


def blank(web, url: str, fields: dict | None = None, **override):
    """Заготовка из карточки; fields – редакция и отпечаток, показанные карточкой (по умолчанию читаются сейчас)."""
    return web.client.post(f"{url}/hub-defect", data={**(fields or shown(web, url)), **override}, headers=AS_JSON)


def create(web, pid: int, defect_id: int, priority: str = "", severity: str = ""):
    return web.client.post(f"/projects/{pid}/hub/defects/{defect_id}/create",
                           data={"priority": priority, "severity": severity}, headers=AS_JSON)


def verify(web, pid: int, defect_id: int):
    return web.client.post(f"/projects/{pid}/hub/defects/{defect_id}/verify", headers=AS_JSON)


def cancel(web, pid: int, defect_id: int):
    return web.client.post(f"/projects/{pid}/hub/defects/{defect_id}/cancel", headers=AS_JSON)


def to_preview(web, pid: int, url: str, blank_body: dict | None = None, service: bool = True) -> dict:
    """Заготовка (и справочник – при первом обращении) на поддельном исполнителе; возвращает строку дефекта в состоянии
    «предпросмотр»."""
    r = blank(web, url)
    assert r.status_code == 200, r.text
    answer = r.json()
    assert not answer["done"] and "заготовка" in answer["message"]
    job = hub_job(web, body=blank_body, match_blank=blank_body is None)
    assert job["purpose"] == "defect_blank" and job["path"].startswith("/defects/blank?appId=7&issueIds=")
    if service:
        info = hub_job(web, body=SERVICE)
        assert info["purpose"] == "read" and info["path"] == "/defects/serviceInfo"
    else:
        no_job(web)  # справочник прочитан раньше и переиспользуется
    state = web.client.get(answer["status_url"]).json()
    assert state["done"] and state["reload"]
    row = web.app.state.db.hub_defect(answer["defect_id"])
    assert row["state"] == "preview", row
    return row


# ============================================================================ тело дефекта


def test_command_html_escapes_and_lists():
    text = ("После анализа команда «Платформа» приняла решение.\n\nОбоснование:\n<b>owner</b> & \"id\" из запроса\n"
            "вторая строка\n\nРекомендация:\n1) Использовать PreparedStatement.\n2) Белый список имён таблиц.")
    out = hub_defects.command_html(text)
    assert out.startswith("<p>После анализа команда «Платформа» приняла решение.</p>")
    assert "<p>Обоснование:<br>&lt;b&gt;owner&lt;/b&gt; &amp; &quot;id&quot; из запроса<br>вторая строка</p>" in out
    assert out.endswith("<p>Рекомендация:<br>1) Использовать PreparedStatement.<br>2) Белый список имён таблиц.</p>")
    assert "<b>" not in out and "style" not in out and "<script" not in hub_defects.command_html("<script>x</script>")
    assert hub_defects.command_html("1) один\n2) два") == "<p>1) один<br>2) два</p>"
    assert "<ol>" not in out  # нумерация «1)» видна в Hub текстом (S1)
    assert hub_defects.command_html("") == ""


def test_description_and_create_body_keep_blank_fields_and_apply_edits():
    description = hub_defects.description_html("Текст команды.", HUB_DESCRIPTION)
    assert description == "<p>Текст команды.</p>\n" + HUB_DESCRIPTION
    assert hub_defects.description_html("Текст команды.", "") == "<p>Текст команды.</p>"
    body = hub_defects.create_body({**BLANK, "id": 1}, 7, TITLE, description, {"name": "Critical", "rank": 1}, None)
    assert "id" not in body and body["appId"] == 7 and body["summary"] == TITLE and body["description"] == description
    assert body["priority"] == {"name": "Critical", "rank": 1} and body["severity"] == BLANK["severity"]
    assert body["status"] == "Registered" and body["linkedIssues"] == BLANK["linkedIssues"]
    assert hub_defects.level_names(SERVICE["priorities"]) == ["Blocker", "Critical", "Major", "Minor", "Info"]
    assert hub_defects.level_names(["Low", "High", "Low"]) == ["Low", "High"]
    assert hub_defects.pick_level(SERVICE["priorities"], "Minor", BLANK["priority"]) == {"name": "Minor", "rank": 3}
    assert hub_defects.pick_level(None, "Minor", BLANK["priority"]) == BLANK["priority"]
    assert hub_defects.pick_level(SERVICE["priorities"], "", BLANK["priority"]) == BLANK["priority"]
    try:
        hub_defects.pick_level(SERVICE["priorities"], "Urgent", BLANK["priority"])
    except ValueError as e:
        assert "не из списка" in str(e)
    else:
        raise AssertionError("значение не из списка должно отклоняться")


def test_answer_parsing_and_matching():
    assert hub_defects.parse_defect_id({"body_text": json.dumps({"id": 555})}) == "555"
    assert hub_defects.parse_defect_id({"body_text": json.dumps({"defectId": "556"})}) == "556"
    assert hub_defects.parse_defect_id({"body_text": "", "headers": {"location": "/hub/rest/defects/557"}}) == "557"
    assert hub_defects.parse_defect_id({"body_text": json.dumps({"ok": True}), "headers": {}}) == ""
    targets = [{"issue_id": 101, "issue_type": "SAST"}, {"issue_id": 102, "issue_type": "SAST"}]
    defect = {"linkedIssues": [{"id": 101, "type": "SAST"}, {"id": "7", "type": "SCA_S"}]}
    assert [t["issue_id"] for t in hub_defects.missing_targets(defect, targets)] == [102]
    assert hub_defects.missing_targets({"linkedIssues": None}, targets) == targets
    row = {"summary": TITLE, "targets_json": json.dumps(targets[:1]), "command_text": "Обоснование:\nтекст\n\n1) мера", "create_op_id": 1}
    good = {"summary": " ID1 - Внедрение SQL-кода (SAST)", "linkedIssues": [{"id": 101, "type": "SAST"}],
            "description": hub_defects.description_html(row["command_text"], HUB_DESCRIPTION)}
    assert hub_defects.candidate_matches(good, row)
    assert not hub_defects.candidate_matches({**good, "summary": "другой"}, row)
    assert not hub_defects.candidate_matches({**good, "linkedIssues": []}, row)
    assert not hub_defects.candidate_matches({**good, "description": "<p>другой текст</p>"}, row)
    assert hub_defects.brief_matches({"summary": TITLE, "author": "user1"}, TITLE, "user1")
    assert not hub_defects.brief_matches({"summary": TITLE, "author": {"login": "user2"}}, TITLE, "user1")
    assert hub_defects.brief_matches({"summary": TITLE}, TITLE, "user1")
    link = hub_defects.link_request("555", targets, None)
    assert link["body"] == {"defectId": 555, "issueIds": [101, 102], "issueType": "SAST", "groupId": None}
    assert hub_defects.blank_request(7, targets, "SAST")["path"] == "/defects/blank?appId=7&issueIds=101,102&type=SAST"
    assert hub_defects.list_request(7, 2)["path"] == "/defects?appId=7&pageIndex=2&pageSize=50"
    assert hub_defects.view(None)["final"] and not hub_defects.view(None)["text"]
    assert hub_defects.view({"state": "unknown", "error": "ответа нет", "hub_defect_id": ""})["verify"]


# ============================================================================ цепочка SAST



@pytest.mark.parametrize("tail,state", [("", "done"), ("<p>Чужой комментарий</p>", "unconfirmed")])
def test_create_sends_only_text_and_hub_appended_blank_block_is_confirmed(web, tail, state):
    """dev30: при создании уходят текст и блок заготовки; описание в Hub равно отправленному – дефект создан;
    иной хвост – не подтверждено, отметок нет."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    hello(web)
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"], priority="Critical").status_code == 200
    job = hub_job(web, body={"id": 555})
    assert job["body"]["description"].endswith("\n" + HUB_DESCRIPTION), "dev30: текст и блок заготовки"
    hub_job(web, body={"id": 555, "summary": TITLE, "linkedIssues": [{"id": 510001, "type": "SAST"}],
                       "description": job["body"]["description"] + ("\n" + tail if tail else "")})
    current = db.hub_defect(row["id"])
    assert current["state"] == state, current
    assert bool(db.get_review(pid, "510001")["entered_hub"]) == (state == "done")
    if state == "done":  # блок ниже текста – часть описания Hub, расхождением не называется
        owner = current.get("draft_owner_id") or current["id"]
        page = web.client.get(f"/projects/{pid}/defects/{owner}").text
        assert 'id="defect-hub-extra"' not in page and "заменит описание текстом из приложения" not in page

def test_sast_defect_chain_blank_create_read(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    hello(web)
    card = web.client.get(url).text
    assert 'id="hub-defect-form"' in card and 'id="hub-defect-button"' in card
    fields = shown(web, url)
    body_hash = fields["text_hash"]  # отпечаток тела дефекта, который показала карточка
    row = to_preview(web, pid, url)
    assert row["summary"] == TITLE and row["number"] == 1 and json.loads(row["targets_json"])[0]["hub_id"] == "510001"
    assert json.loads(row["blank_json"])["_targets"] == [510001]
    assert hub_defects.saved_blank_fits(row)
    changed = {**row, "targets_json": json.dumps([{"issue_id": 510002}])}
    assert not hub_defects.saved_blank_fits(changed)
    card = web.client.get(url).text
    assert 'id="hub-defect-preview"' in card and TITLE in card and 'id="hub-defect-create"' in card
    assert '<option value="Critical"' in card and '<option value="Major" selected' in card
    assert 'id="hub-defect-severity" value="Medium" readonly' in card  # серьёзностей справочник не дал
    assert "Будут привязаны находки (1): " in card and "510001" in card
    # повторная заготовка – только после «Отменить предпросмотр»; начатый дефект – вне блока
    # «только при „Подтверждаю дефект“», виден при любом выбранном решении (круг 4 Codex)
    assert 'id="hub-defect-cancel"' in card and 'id="hub-defect-form"' not in card
    assert card.index('id="hub-defect-current"') < card.index('id="hub-defect-cancel"')
    r = create(web, pid, row["id"], priority="Critical")
    assert r.status_code == 200, r.text
    job = hub_job(web, body={"id": 555})
    assert job["purpose"] == "defect_create" and job["method"] == "POST" and job["path"] == "/defects"
    body = job["body"]
    assert body["summary"] == TITLE and body["appId"] == 7 and body["priority"] == {"name": "Critical", "rank": 1}
    assert body["severity"] == BLANK["severity"] and body["linkedIssues"] == BLANK["linkedIssues"]
    assert body["status"] == "Registered" and body["source"] == "Tool"
    assert body["description"].startswith("<p>После тщательного анализа уязвимости команда Платформа приняла решение")
    assert "<p>Рекомендация:<br>1) Параметризовать запрос.</p>" in body["description"]
    # dev30: следом за текстом – блок заготовки Hub как есть
    assert body["description"].endswith("\n" + HUB_DESCRIPTION)
    assert db.get_review(pid, "510001")["entered_hub"] == 0, "успешный POST ничего не завершает"
    state = web.client.get(f"/projects/{pid}/hub/defects/{row['id']}").json()
    assert not state["done"] and "проверяю привязку" in state["text"]["hub-defect-status"]
    read = hub_job(web, body={"id": 555, "summary": TITLE, "linkedIssues": [{"id": 510001, "type": "SAST"}],
                              "description": body["description"]})
    assert read["purpose"] == "defect_read" and read["path"] == "/defects/555"
    no_job(web)
    row = db.hub_defect(row["id"])
    assert row["state"] == "done" and row["hub_defect_id"] == "555" and row["created_by"] == "user1"
    assert row["hub_link"].startswith(HUB) and "555" in row["hub_link"] and row["priority"] == "Critical"
    review = db.get_review(pid, "510001")
    assert review["entered_hub"] == 1 and review["entered_decision_hash"] == body_hash
    parts = json.loads(review["entered_parts"])
    assert parts["defect"] == 1 and "fix" in parts and "team" in parts
    assert db.defect_number(pid, "sast:510001") == 1
    assert db.hub_ops_list(states=("queued", "taken", "unknown")) == []
    assert not [o for o in db.hub_ops_list() if o["purpose"] == "status"], "статусы находок не менялись"
    card = web.client.get(url).text
    assert 'id="hub-defect-done"' in card and "№555" in card and 'id="hub-defect-form"' not in card
    assert 'id="entered-badge" hidden' not in card and "дефект создан в Hub" in card
    assert 'id="entered-changed"' not in card, "отпечаток отметки – тот же текст, что сверяет карточка"
    page = web.client.get(f"/projects/{pid}/defects").text
    assert 'id="hub-defects"' in page and 'data-state="done"' in page and "№555" in page and f'href="{url}' in page
    assert "user1" in page and "ID1" in page
    assert re.search(r'href="/projects/%d/defects"[^>]*>Дефекты <span class="tab-count">1</span>' % pid, page)
    # повторно из той же карточки – дефект уже создан (формы в карточке нет, поля – прежние)
    again = blank(web, url, fields)
    assert again.status_code == 400 and "уже создан" in again.json()["detail"]


def test_read_without_links_goes_through_link_and_second_read(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, body={}, headers={"location": "/hub/rest/defects/556"})  # номер – из Location
    first = hub_job(web, body={"id": 556, "linkedIssues": []})
    assert first["path"] == "/defects/556"
    row = db.hub_defect(row["id"])
    assert row["state"] == "linking" and row["hub_defect_id"] == "556"
    link = hub_job(web, body={})
    assert link["purpose"] == "defect_link" and link["method"] == "POST" and link["path"] == "/defects/556/link"
    assert link["body"] == {"defectId": 556, "issueIds": [510001], "issueType": "SAST", "groupId": None}
    assert db.get_review(pid, "510001")["entered_hub"] == 0
    second = hub_job(web, body={"id": 556, "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    assert second["purpose"] == "defect_read" and second["path"] == "/defects/556"
    row = db.hub_defect(row["id"])
    assert row["state"] == "done" and db.get_review(pid, "510001")["entered_hub"] == 1
    assert hub_defects.VERIFY_NOTE_DONE in row["error"]
    # привязка не помогла – «создан, привязка неполная», без третьей попытки. Тот же дефект с тем же текстом второй раз
    # не создаётся (ключ операции записи), поэтому решение сохраняется заново с другим обоснованием
    pid2, url2 = pid, url
    db.hub_defect_update(row["id"], state="cancelled")
    save_sast(web, pid2, "510001", "true_positive", "", REASON + " Дополнение.", FIX)
    assert db.get_review(pid2, "510001")["entered_hub"] == 0
    row = to_preview(web, pid2, url2, service=False)
    assert create(web, pid2, row["id"]).status_code == 200
    hub_job(web, body={"id": 557})
    hub_job(web, body={"id": 557, "linkedIssues": []})
    hub_job(web, body={})
    hub_job(web, body={"id": 557, "linkedIssues": []})
    row = db.hub_defect(row["id"])
    assert row["state"] == "mismatch" and "510001" in row["error"]
    no_job(web)
    assert db.get_review(pid2, "510001")["entered_hub"] == 0


def test_unknown_create_is_verified_by_defect_list(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    hello(web)
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, status=0, error="timeout")
    row = db.hub_defect(row["id"])
    assert row["state"] == "unknown" and db.hub_op(row["create_op_id"])["state"] == "unknown"
    card = web.client.get(url).text
    assert 'id="hub-defect-verify-form" class="actions" data-ajax data-busy="Ставлю сверку…">' in card
    assert "Результат неизвестен" in card
    r = verify(web, pid, row["id"])
    assert r.status_code == 200 and "Сверка поставлена" in r.json()["message"], r.text
    assert r.json()["done"] is False, "сверка идёт – карточка продолжает опрос"
    assert web.client.get(r.json()["status_url"]).json()["done"] is False
    assert verify(web, pid, row["id"]).status_code == 409  # вторая сверка, пока идёт первая
    listing = hub_job(web, body={"filteredEntities": [{"id": 700, "summary": "другой дефект", "author": "user1"},
                                                      {"id": 701, "summary": TITLE, "author": "user2"},
                                                      {"id": 777, "summary": TITLE, "author": "user1"}],
                                 "totalEntitiesCount": 3})
    assert listing["purpose"] == "read" and listing["path"] == "/defects?appId=7&pageIndex=0&pageSize=50"
    candidate = hub_job(web, body={"id": 777, "summary": TITLE, "linkedIssues": [{"id": 510001, "type": "SAST"}],
                                   "description": hub_defects.description_html(row["command_text"], HUB_DESCRIPTION)})
    assert candidate["purpose"] == "defect_read" and candidate["path"] == "/defects/777"
    no_job(web)
    row = db.hub_defect(row["id"])
    assert row["state"] == "done" and row["hub_defect_id"] == "777"
    assert db.hub_op(row["create_op_id"])["state"] == "done"
    assert db.get_review(pid, "510001")["entered_hub"] == 1


def test_unknown_stays_unknown_when_no_candidate_matches(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, status=503, body={"errorMessage": "Service Unavailable"})
    assert db.hub_defect(row["id"])["state"] == "unknown"
    assert verify(web, pid, row["id"]).status_code == 200
    hub_job(web, body={"filteredEntities": [{"id": 777, "summary": TITLE}], "totalEntitiesCount": 60})
    hub_job(web, body={"id": 777, "summary": TITLE, "linkedIssues": [{"id": 999, "type": "SAST"}], "description": "<p>x</p>"})
    page2 = hub_job(web, body={"filteredEntities": [], "totalEntitiesCount": 60})
    assert page2["path"] == "/defects?appId=7&pageIndex=1&pageSize=50"
    no_job(web)
    row = db.hub_defect(row["id"])
    assert row["state"] == "unknown" and row["error"] == hub_defects.VERIFY_NOTE_NONE
    assert hub_defects.view(row)["final"] and hub_defects.view(row)["verify"], "сверка закончилась – снова «Сверить»"
    assert db.get_review(pid, "510001")["entered_hub"] == 0
    assert db.hub_op(row["create_op_id"])["state"] == "unknown"
    # у дефекта с известным номером «Сверить» – чтение снова
    db.hub_defect_update(row["id"], hub_defect_id="778")
    assert verify(web, pid, row["id"]).status_code == 200
    read = hub_job(web, body={"id": 778, "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    assert read["purpose"] == "defect_read" and read["path"] == "/defects/778"
    assert db.hub_defect(row["id"])["state"] == "done"


def test_unreadable_candidate_is_not_reported_as_absent(web):
    """Ответ чтения кандидата не разобран: «дефекта нет» сказать нельзя (ревью dev4, круг 9)."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, status=503, body={"errorMessage": "Service Unavailable"})
    assert verify(web, pid, row["id"]).status_code == 200
    hub_job(web, body={"filteredEntities": [{"id": 777, "summary": TITLE}], "totalEntitiesCount": 1})
    hub_job(web, body={"oops": True})
    fresh = db.hub_defect(row["id"])
    assert fresh["state"] == "unknown" and fresh["error"] == hub_defects.VERIFY_NOTE_FAILED


def test_expired_lease_is_reflected_on_poll(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    answer = blank(web, url).json()
    job = web.client.get("/api/hub/jobs", params={"worker_id": "w1", "hub_url": HUB, "wait": 0},
                         headers=worker_headers(web)).json()["job"]
    assert job["purpose"] == "defect_blank"
    db.hub_expire_leases(now="2099-01-01T00:00:00+00:00")
    state = web.client.get(answer["status_url"]).json()
    assert state["done"] and "заготовка не получена" in state["text"]["hub-defect-status"]
    assert db.hub_defect(answer["defect_id"])["state"] == "failed"
    card = web.client.get(url).text
    assert 'id="hub-defect-form"' in card and "Hub не принял" in card  # можно попробовать ещё раз


def test_refusals(web):
    pid, url = sast_ready(web)
    db = web.app.state.db
    fields = shown(web, url)
    r = blank(web, url, review_revision="999")
    assert r.status_code == 400 and "в другой вкладке" in r.json()["detail"]
    r = blank(web, url, text_hash="0" * 32)
    assert r.status_code == 400 and "Текст для Hub изменился" in r.json()["detail"]
    r = blank(web, url, text_hash="")
    assert r.status_code == 400 and "не показала текст" in r.json()["detail"]
    db.set_settings({"hub_url": ""})
    r = blank(web, url, fields)  # без адреса Hub карточка формы не показывает (#hub-defect-blocker)
    assert r.status_code == 400 and "Адрес Hub не задан" in r.json()["detail"]
    assert 'id="hub-defect-blocker"' in web.client.get(url).text
    db.set_settings({"hub_url": HUB})
    db.update_project(pid, hub_app_id=None)
    r = blank(web, url, fields)
    assert r.status_code == 400 and "Номер приложения" in r.json()["detail"]
    db.update_project(pid, hub_app_id=7)
    assert db.hub_ops_list() == [] and db.hub_defects(pid) == []
    # ложное срабатывание – дефекта нет
    fp_url, _ = save_sast(web, pid, "510002", "false_positive", "", "Ложное срабатывание: вывод экранируется.")
    r = web.client.post(f"{fp_url}/hub-defect", data={**fields, "review_revision": re.search(
        r'name="review_revision" value="(\d+)"', web.client.get(fp_url).text).group(1)}, headers=AS_JSON)
    assert r.status_code == 400 and "Подтверждаю дефект" in r.json()["detail"]
    # открытая операция – вторая заготовка не ставится (формы в карточке нет: состояние опрашивается); создание не из
    # предпросмотра – отказ
    assert blank(web, url, fields).status_code == 200
    assert 'id="hub-defect-form"' not in web.client.get(url).text
    r = blank(web, url, fields)
    assert r.status_code == 409 and "уже идёт" in r.json()["detail"]
    row = db.hub_defects(pid)[0]
    r = create(web, pid, row["id"])
    assert r.status_code == 409 and "Предпросмотра нет" in r.json()["detail"]
    assert web.client.get(f"/projects/{pid}/hub/defects/{row['id'] + 100}").status_code == 404
    hub_job(web, body=BLANK)
    hub_job(web, body=SERVICE)
    r = create(web, pid, row["id"], priority="Urgent")
    assert r.status_code == 400 and "не из списка" in r.json()["detail"]
    # сверка нужна только «результату неизвестен»
    r = verify(web, pid, row["id"])
    assert r.status_code == 400 and "неизвестен" in r.json()["detail"]
    # открытый предпросмотр не заменяется: повторная заготовка – отказ; «Отменить предпросмотр» – и заново
    # (справочник второй раз не читается)
    r = blank(web, url, {"review_revision": "1", "text_hash": "x"})
    assert r.status_code == 409 and "Отменить предпросмотр" in r.json()["detail"]
    assert db.hub_defect(row["id"])["state"] == "preview"
    r = cancel(web, pid, row["id"])
    assert r.status_code == 200 and r.json()["reload"] is True
    assert db.hub_defect(row["id"])["state"] == "cancelled"
    assert cancel(web, pid, row["id"]).status_code == 409, "отменённый предпросмотр второй раз не отменяется"
    assert blank(web, url).status_code == 200
    job = hub_job(web, body=BLANK)
    assert job["purpose"] == "defect_blank"
    no_job(web)


def pair_project(web) -> int:
    """Две находки SAST той же строки и категории с одинаковым кодом (одна группа) – дефект из группы."""
    pid = create_project(web.client)
    second = dict(SAST_ROWS[0], **{"Issue id": "510005"})
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "pair.xlsx", sast=[SAST_ROWS[0], second],
                                                  practices="auto", severities="auto")).status_code == 303
    r = web.client.post(f"/projects/{pid}/repos", data={"repos_dir": "team"}, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303, r.text
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    hub_settings(web, pid)
    return pid


def test_group_members_with_same_text_join_and_others_are_listed(web):
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    save_sast(web, pid, "510005", "true_positive", "", REASON, "Другая рекомендация.")
    row = to_preview(web, pid, url)
    assert [t["hub_id"] for t in json.loads(row["targets_json"])] == ["510001"]
    left = json.loads(row["left_out_json"])
    assert left == [{"hub_id": "510005", "why": "другой текст решения (обоснование или рекомендация)"}]
    card = web.client.get(url).text
    assert 'id="hub-defect-left-out"' in card and "другой текст решения" in card
    db.hub_defect_update(row["id"], state="cancelled")
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    row = to_preview(web, pid, url, service=False)
    assert [t["hub_id"] for t in json.loads(row["targets_json"])] == ["510001", "510005"]
    assert json.loads(row["left_out_json"]) == []
    assert db.hub_op(row["blank_op_id"])["request_json"].count("issueIds=510001,510005") == 1
    # сосед видит тот же предпросмотр в своей карточке (дефект общий для подгруппы)
    sibling = f"/projects/{pid}/findings/{db.get_finding_by_hub_id(pid, '510005')['id']}"
    sibling_card = web.client.get(sibling).text
    assert 'id="hub-defect-preview"' in sibling_card and f'/hub/defects/{row["id"]}/create' in sibling_card
    rows = db.hub_defects(pid)
    assert rows[0]["id"] == row["id"]
    assert create(web, pid, rows[0]["id"]).status_code == 200
    hub_job(web, body={"id": 600})
    hub_job(web, body={"id": 600, "linkedIssues": [{"id": 510001, "type": "SAST"}, {"id": 510005, "type": "SAST"}]})
    assert db.hub_defect(rows[0]["id"])["state"] == "done"
    assert db.get_review(pid, "510001")["entered_hub"] == 1 and db.get_review(pid, "510005")["entered_hub"] == 1
    assert db.defect_number(pid, "sast:510005") == db.defect_number(pid, "sast:510001") == 1
    # редакция соседа изменилась после постановки – отметка ему не ставится при повторной доставке; находка в
    # созданном дефекте меняет решение только с подтверждением (ADR-0121)
    save_sast(web, pid, "510005", "true_positive", "", REASON + " Уточнено.", FIX, defect_confirm="1")
    assert db.get_review(pid, "510005")["entered_hub"] == 0


def test_changed_sibling_revision_before_create_is_refused(web):
    pid = pair_project(web)
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    row = to_preview(web, pid, url)
    save_sast(web, pid, "510005", "true_positive", "", REASON + " Дополнение.", FIX)
    r = create(web, pid, row["id"])
    assert r.status_code == 400 and "510005" in r.json()["detail"]
    assert web.app.state.db.hub_defect(row["id"])["state"] == "preview"


def test_poll_between_link_and_second_read_keeps_the_chain(web):
    """Круг 1 Codex (находка 2): опрос карточки между ответом на привязку и вторым чтением цепочку не ломает; повторная
    доставка первого чтения во время привязки не ставит «привязка неполная»."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    answer = create(web, pid, row["id"]).json()
    hub_job(web, body={"id": 556})
    hub_job(web, body={"id": 556, "linkedIssues": []})
    first_read = db.hub_op(db.hub_defect(row["id"])["read_op_id"])
    hub_defects.after_op(db, first_read)  # повторная доставка первого чтения, пока идёт привязка
    assert db.hub_defect(row["id"])["state"] == "linking"
    link = hub_job(web, body={})
    assert link["purpose"] == "defect_link"
    for _ in range(2):  # опросы карточки до ответа на второе чтение
        assert web.client.get(answer["status_url"]).json()["done"] is False
    middle = db.hub_defect(row["id"])
    assert middle["state"] == "created" and middle["read_op_id"] != first_read["id"]
    hub_defects.after_op(db, db.hub_op(middle["link_op_id"]))  # повторная доставка привязки – без второго чтения
    hub_job(web, body={"id": 556, "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    no_job(web)
    assert db.hub_defect(row["id"])["state"] == "done"


def test_duplicate_read_delivery_keeps_a_later_manual_mark(web):
    """Круг 1 Codex (находка 3): после «done» человек снял отметку и поставил свою (другой текст, та же редакция);
    повторная доставка подтверждающего чтения её не перетирает."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, body={"id": 555})
    hub_job(web, body={"id": 555, "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    row = db.hub_defect(row["id"])
    assert row["state"] == "done"
    review = db.get_review(pid, "510001")
    db.mark_entered(pid, "510001", False, revision=review["revision"], entered_hash="", entered_parts="")
    db.mark_entered(pid, "510001", True, revision=review["revision"], entered_hash="поздняя-ручная", entered_parts="{}")
    hub_defects.after_op(db, db.hub_op(row["read_op_id"]))
    assert db.get_review(pid, "510001")["entered_text_hash"] == "поздняя-ручная"
    # номер ID<n>, назначенный позже человеком, повторное применение тоже не перезаписывает
    db.set_defect_number(pid, "sast:510001", 42)
    hub_defects.after_op(db, db.hub_op(row["read_op_id"]))
    assert db.defect_number(pid, "sast:510001") == 42
    assert "не записан" in db.hub_defect(row["id"])["error"]
    # конфликт номера виден (круг 2 Codex, находка 7): в карточке и во вкладке «Дефекты»
    assert "не записан" in web.client.get(url).text
    assert "не записан" in web.client.get(f"/projects/{pid}/defects").text


def test_second_create_of_one_preview_is_refused(web):
    """Круг 1 Codex (находка 1): «Создать» из второй вкладки по тому же предпросмотру второй POST не ставит."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    r = create(web, pid, row["id"], priority="Minor")
    assert r.status_code == 409, r.text
    assert len([o for o in db.hub_ops_list() if o["purpose"] == "defect_create"]) == 1


def test_cancelled_preview_frees_the_number_for_a_new_one(web):
    """Круги 1–3 Codex (находки «обновление заготовки»): предпросмотр не заменяется; после
    «Отменить предпросмотр» новая заготовка собирает тех же участников с тем же номером."""
    pid = pair_project(web)
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    save_sast(web, pid, "510005", "true_positive", "", REASON, FIX)
    first = to_preview(web, pid, url)
    assert [t["hub_id"] for t in json.loads(first["targets_json"])] == ["510001", "510005"]
    assert cancel(web, pid, first["id"]).status_code == 200
    second = to_preview(web, pid, url, service=False)
    assert second["id"] != first["id"] and db.hub_defect(first["id"])["state"] == "cancelled"
    assert [t["hub_id"] for t in json.loads(second["targets_json"])] == ["510001", "510005"]
    assert json.loads(second["left_out_json"]) == [] and second["number"] == first["number"]


def test_open_defects_reserve_their_numbers(web):
    """Круг 1 Codex (находка 6): два предпросмотра разных дефектов до завершения первого получают разные номера;
    строку с занятым номером транзакция не запишет."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    first = to_preview(web, pid, url)
    assert first["number"] == 1 and db.next_defect_number(pid) == 2
    with __import__("pytest").raises(ValueError, match="Номер ID1 уже занят"):
        db.hub_defect_start(pid, items=[], kind="SAST", number=1, summary="ID1 - x (SAST)", anchor_hub_id="510002",
                            targets=[{"hub_id": "510002"}], number_keys=["sast:510002"], command_text="x",
                            hub_url=HUB, app_id=7)
    with __import__("pytest").raises(ValueError, match="510001 уже в другом дефекте"):
        db.hub_defect_start(pid, items=[], kind="SAST", number=2, summary="ID2 - x (SAST)", anchor_hub_id="510001",
                            targets=[{"hub_id": "510001"}], number_keys=["sast:510001"], command_text="x",
                            hub_url=HUB, app_id=7)
    db.hub_defect_update(first["id"], state="failed")  # отклонённый Hub дефект номер не держит
    assert db.next_defect_number(pid) == 1


def test_verified_unknown_link_closes_the_link_operation(web):
    """Круг 1 Codex (находка 8): привязка с неизвестным исходом, «Сверить» читает дефект – все находки привязаны:
    дефект подтверждён, операция привязки закрыта, блокировок в очереди не остаётся; опрос идёт до итога."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, body={"id": 556})
    hub_job(web, body={"id": 556, "linkedIssues": []})
    hub_job(web, status=0, error="timeout")  # привязка: исход неизвестен
    row = db.hub_defect(row["id"])
    assert row["state"] == "unknown" and db.hub_op(row["link_op_id"])["state"] == "unknown"
    r = verify(web, pid, row["id"])
    assert r.status_code == 200 and r.json()["done"] is False, r.text
    hub_job(web, body={"id": 556, "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    row = db.hub_defect(row["id"])
    assert row["state"] == "done" and db.hub_op(row["link_op_id"])["state"] == "done"
    assert db.hub_ops_list(states=("queued", "taken", "unknown")) == []
    assert db.get_review(pid, "510001")["entered_hub"] == 1


def test_expired_lease_during_verification_returns_the_verify_button(web):
    """Круг 2 Codex (находка 1): исполнитель забрал страницу сверки и пропал – после истечения аренды карточка не
    опрашивает бесконечно: сверка закончена, кнопка «Сверить» снова видна."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, status=0, error="timeout")
    answer = verify(web, pid, row["id"]).json()
    assert answer["done"] is False
    job = web.client.get("/api/hub/jobs", params={"worker_id": "w1", "hub_url": HUB, "wait": 0},
                         headers=worker_headers(web)).json()["job"]
    assert job["purpose"] == "read" and "pageIndex=0" in job["path"]
    db.hub_expire_leases(now="2099-01-01T00:00:00+00:00")
    state = web.client.get(answer["status_url"]).json()
    assert state["done"] is True and "hub-defect-verify-form" in state["show"], state
    row = db.hub_defect(row["id"])
    assert row["state"] == "unknown" and row["verify_op_id"] is None and row["error"] == hub_defects.VERIFY_NOTE_FAILED
    assert verify(web, pid, row["id"]).status_code == 200, "сверку можно начать снова"


def test_redelivered_list_while_candidate_pending_keeps_verifying(web):
    """Круг 2 Codex (находка 2): страница списка доставлена повторно, пока читается кандидат, – ничего не меняется,
    сверка идёт и заканчивается по ответу кандидата."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    hello(web)
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, status=0, error="timeout")
    answer = verify(web, pid, row["id"]).json()
    hub_job(web, body={"filteredEntities": [{"id": 777, "summary": TITLE, "author": "user1"}], "totalEntitiesCount": 1})
    listing = [o for o in db.hub_ops_list() if o["purpose"] == "read" and "pageIndex=0" in o["request_json"]][-1]
    pending = db.hub_defect(row["id"])
    assert pending["verify_op_id"] != listing["id"]
    hub_defects.after_op(db, db.hub_op(listing["id"]))  # повторная доставка той же страницы
    after = db.hub_defect(row["id"])
    assert after["state"] == "unknown" and after["verify_op_id"] == pending["verify_op_id"]
    assert after["error"] != hub_defects.VERIFY_NOTE_NONE
    assert web.client.get(answer["status_url"]).json()["done"] is False
    hub_job(web, body={"id": 777, "summary": TITLE, "linkedIssues": [{"id": 510001, "type": "SAST"}],
                       "description": hub_defects.description_html(row["command_text"], HUB_DESCRIPTION)})
    assert db.hub_defect(row["id"])["state"] == "done"


def test_stale_first_read_after_link_does_not_spoil_the_chain(web):
    """Круг 2 Codex (находка 3): обработчик, взявший строку до привязки, продолжает с первым чтением, когда строка уже
    снова «создан» со вторым чтением, – ничего не меняет (шаг сверяет операцию в транзакции)."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, body={"id": 556})
    snapshot = db.hub_defect(row["id"])  # «опрос» взял строку: created, первое чтение
    assert snapshot["state"] == "created"
    hub_job(web, body={"id": 556, "linkedIssues": []})
    hub_job(web, body={})  # привязка
    middle = db.hub_defect(row["id"])
    assert middle["state"] == "created" and middle["read_op_id"] != snapshot["read_op_id"]
    hub_defects._on_read(db, snapshot, db.hub_op(snapshot["read_op_id"]))  # устаревший обработчик продолжил
    assert db.hub_defect(row["id"])["state"] == "created"
    hub_job(web, body={"id": 556, "linkedIssues": [{"id": 510001, "type": "SAST"}]})
    assert db.hub_defect(row["id"])["state"] == "done"


def test_number_held_by_a_foreign_key_is_refused(web):
    """Круг 2 Codex (находка 4): номер выдан и своему, и чужому ключу – строка с ним не записывается."""
    pid, _ = sast_ready(web)
    db = web.app.state.db
    db.set_defect_number(pid, "sast:510001", 5)
    db.set_defect_number(pid, "sast:510099", 5)
    with __import__("pytest").raises(ValueError, match="Номер ID5 уже занят"):
        db.hub_defect_start(pid, items=[], kind="SAST", number=5, summary="ID5 - x (SAST)", anchor_hub_id="510001",
                            targets=[{"hub_id": "510001"}], number_keys=["sast:510001"], command_text="x",
                            hub_url=HUB, app_id=7)


def test_sca_open_preview_is_kept_and_cancel_gives_a_new_one(web):
    """Круг 3 Codex (важная): у набора SCA без закреплённого номера повторная заготовка при открытом предпросмотре не
    губит его – отказ с подсказкой; после «Отменить предпросмотр» – новая заготовка с тем же номером."""
    pid = prepared(web)
    db = web.app.state.db
    hub_settings(web, pid)
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    url = f"/projects/{pid}/sca/findings/{db.get_finding_by_hub_id(pid, '73001')['id']}"
    sca_text_ready(web, url)
    fields = shown(web, url)
    assert blank(web, url, fields).status_code == 200
    hub_job(web, body={**BLANK, "linkedIssues": []})
    hub_job(web, body=SERVICE)
    first = db.hub_defects(pid)[0]
    assert first["state"] == "preview" and first["number"] == 1
    card = web.client.get(url).text
    assert 'id="hub-defect-cancel"' in card and 'id="hub-defect-form"' not in card
    r = blank(web, url, fields)
    assert r.status_code == 409 and "Отменить предпросмотр" in r.json()["detail"]
    assert db.hub_defect(first["id"])["state"] == "preview"
    assert cancel(web, pid, first["id"]).status_code == 200
    assert blank(web, url).status_code == 200
    hub_job(web, body={**BLANK, "linkedIssues": []})
    second = db.hub_defects(pid)[0]
    assert second["id"] != first["id"] and second["state"] == "preview" and second["number"] == 1


def test_crash_after_the_confirming_read_is_finished_on_view(web, monkeypatch):
    """Круг 3 Codex (мелкая): настоящее подтверждающее чтение, сбой при входе в последствия после записи итога – показ
    карточки доводит отметку и номер; поздняя ручная отметка, поставленная до показа, не перетирается."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, body={"id": 555})

    def crash(*args, **kwargs):
        raise RuntimeError("сбой после записи итога")

    monkeypatch.setattr(hub_defects, "_apply_effects", crash)
    job = web.client.get("/api/hub/jobs", params={"worker_id": "w1", "hub_url": HUB, "wait": 0},
                         headers=worker_headers(web)).json()["job"]
    assert job["purpose"] == "defect_read"
    try:
        status = web.client.post(f"/api/hub/jobs/{job['attempt_id']}/result", headers=worker_headers(web),
                                 content=json.dumps({"lease_token": job["lease_token"], "worker_id": "w1", "status": 200,
                                                     "body_text": json.dumps({"id": 555, "appId": 7, "summary": row["summary"],
                                                         "description": hub_defects.description_html(row["command_text"], HUB_DESCRIPTION), "linkedIssues": [
                                                         {"id": 510001, "type": "SAST"}]}), "error": ""})).status_code
    except RuntimeError:
        status = 500
    assert status == 500
    monkeypatch.undo()
    row = db.hub_defect(row["id"])
    assert row["state"] == "done" and row["effects_done"] == 0 and row["confirm_op_id"] == row["read_op_id"]
    assert db.get_review(pid, "510001")["entered_hub"] == 0 and db.defect_number(pid, "sast:510001") is None
    web.client.get(url)  # показ карточки доводит последствия
    row = db.hub_defect(row["id"])
    assert row["effects_done"] == 1 and db.get_review(pid, "510001")["entered_hub"] == 1
    assert db.defect_number(pid, "sast:510001") == 1


# ============================================================================ SCA


def test_sca_set_defect_chain(web):
    pid = prepared(web)
    db = web.app.state.db
    hub_settings(web, pid)
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    url = f"/projects/{pid}/sca/findings/{db.get_finding_by_hub_id(pid, '73001')['id']}"
    sca_text_ready(web, url)
    card = web.client.get(url).text
    sig = re.search(r'id="hub-defect-text-hash" value="([^"]*)"', card).group(1)
    assert sig and 'id="hub-defect-button"' in card
    sca_blank = {**BLANK, "linkedIssues": [{"id": 73001, "type": "SCA_S"}, {"id": 73002, "type": "SCA_S"}]}
    r = blank(web, url)
    assert r.status_code == 200, r.text
    job = hub_job(web, body=sca_blank)
    assert job["path"] == "/defects/blank?appId=7&issueIds=73001,73002&type=SCA_S"
    hub_job(web, body=SERVICE)
    row = db.hub_defects(pid)[0]
    assert row["state"] == "preview" and row["kind"] == "SCA" and row["summary"].endswith("(SCA)")
    assert "example-parser | Component version: 1.4.2" in row["summary"]
    targets = json.loads(row["targets_json"])
    assert [t["hub_id"] for t in targets] == ["73001", "73002"] and all(t["decision_hash"] == sig and not t["entered_hash"] for t in targets)
    assert create(web, pid, row["id"], priority="Minor").status_code == 200
    created = hub_job(web, body={"id": 900})
    assert created["body"]["summary"] == row["summary"] and "<p>Описание<br>" in created["body"]["description"]
    hub_job(web, body={"id": 900, "linkedIssues": sca_blank["linkedIssues"]})
    row = db.hub_defect(row["id"])
    assert row["state"] == "done" and row["hub_defect_id"] == "900"
    seen = json.loads(row["import_json"])
    from app.db import dumps, text_hash
    content_hash = text_hash(dumps({"summary": seen["summary"], "command_text": seen["command_text"]}))
    for hub_id in ("73001", "73002"):
        review = db.get_review(pid, hub_id)
        assert review["entered_hub"] == 1 and review["entered_decision_hash"] == sig
        assert review["entered_text_hash"] == content_hash and content_hash != sig
    assert 'id="hub-defect-done"' in web.client.get(url).text


def test_sca_text_change_after_preview_refuses_create(web):
    """Круг 1 Codex (находка 4): текст набора SCA изменился после предпросмотра – «Создать» отказывает, POST не
    ставится; новая заготовка соберёт новый текст."""
    pid = prepared(web)
    db = web.app.state.db
    hub_settings(web, pid)
    assert post_package(web, pid, "73001", ["73001", "73002"], **UPD).status_code == 200
    url = f"/projects/{pid}/sca/findings/{db.get_finding_by_hub_id(pid, '73001')['id']}"
    sca_text_ready(web, url)
    assert blank(web, url).status_code == 200
    hub_job(web, body={**BLANK, "linkedIssues": []})
    hub_job(web, body=SERVICE)
    row = db.hub_defects(pid)[0]
    assert row["state"] == "preview" and row["source_fingerprint"]
    sca_text_ready(web, url, target="9.9.10")  # другая вкладка: новая целевая версия
    r = create(web, pid, row["id"])
    assert r.status_code == 400 and "Набор SCA изменился" in r.json()["detail"], r.text
    assert db.hub_defect(row["id"])["state"] == "preview"
    assert not [o for o in db.hub_ops_list() if o["purpose"] == "defect_create"]


def test_sca_not_ready_is_refused(web):
    pid = prepared(web)
    db = web.app.state.db
    hub_settings(web, pid)
    url = f"/projects/{pid}/sca/findings/{db.get_finding_by_hub_id(pid, '73001')['id']}"
    card = web.client.get(url).text
    revision = re.search(r'name="review_revision" value="(\d+)"', card).group(1)
    r = web.client.post(f"{url}/hub-defect", data={"review_revision": revision, "text_hash": "x"}, headers=AS_JSON)
    assert r.status_code == 400, r.text
    assert db.hub_defects(pid) == [] and db.hub_ops_list() == []


# ============================================================================ вкладка и схема


def test_defects_tab_empty_and_tab_counts(web):
    pid = prepared(web)
    page = web.client.get(f"/projects/{pid}/defects")
    assert page.status_code == 200
    assert "Дефектов из приложения ещё нет" in page.text and 'id="hub-defects"' not in page.text
    assert re.search(r'href="/projects/%d/defects"[^>]*>Дефекты <span class="tab-count">0</span></a>' % pid, page.text)
    overview = web.client.get(f"/projects/{pid}").text
    assert f'href="/projects/{pid}/defects"' in overview and "Дефекты" in overview
    assert web.client.get("/projects/999/defects").status_code == 404
    assert web.app.state.db.count_findings(pid)["defects"] == 0


def test_create_answer_without_number_starts_search_at_once(web):
    """31.10: Hub отвечает на POST /defects кодом 201 без тела и без Location – номер ищется сразу тем же чтением,
    что и «Сверить», без нажатия; повторного создания нет."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    hello(web)
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, status=201, body=None)
    row = db.hub_defect(row["id"])
    assert row["state"] == "unknown" and row["verify_op_id"]
    # переход и постановка поиска – одной транзакцией: повторная доставка того же ответа ничего не меняет
    before = db._scalar("SELECT count(*) FROM hub_ops")
    hub_defects.sync(db, db.hub_defect(row["id"]))
    assert db._scalar("SELECT count(*) FROM hub_ops") == before
    listing = hub_job(web, body={"filteredEntities": [{"id": 777, "summary": TITLE, "author": "user1"}],
                                 "totalEntitiesCount": 1})
    assert listing["purpose"] == "read" and listing["path"] == "/defects?appId=7&pageIndex=0&pageSize=50"
    candidate = hub_job(web, body={"id": 777, "summary": TITLE, "linkedIssues": [{"id": 510001, "type": "SAST"}],
                                   "description": hub_defects.description_html(row["command_text"], HUB_DESCRIPTION)})
    assert candidate["path"] == "/defects/777"
    no_job(web)
    row = db.hub_defect(row["id"])
    assert row["state"] == "done" and row["hub_defect_id"] == "777"
    assert db._scalar("SELECT count(*) FROM hub_ops WHERE purpose='defect_create'") == 1


def test_create_answer_without_number_keeps_button_when_queue_refuses(web, monkeypatch):
    """Отказ очереди при постановке поиска – «неизвестен» с кнопкой «Сверить», как раньше."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    hello(web)
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    original = db.hub_defect_advance

    def refusing(defect_id, **kwargs):
        if kwargs.get("op_field") == "verify_op_id":
            raise ValueError("очередь занята")
        return original(defect_id, **kwargs)

    monkeypatch.setattr(db, "hub_defect_advance", refusing)
    hub_job(web, status=201, body=None)
    row = db.hub_defect(row["id"])
    assert row["state"] == "unknown" and not row["verify_op_id"] and row["error"] == "Hub ответил без номера дефекта"
    assert hub_defects.view(row)["verify"]


def test_failed_attempt_offers_retry_and_is_marked_when_superseded(web):
    """Попытка, которую Hub не принял, – «Подготовить заново» в карточке и в списке; после
    создания того же номера другой строкой – «заменена» со ссылкой на созданный дефект."""
    pid, url = sast_ready(web)
    db = web.app.state.db
    hello(web)
    row = to_preview(web, pid, url)
    assert create(web, pid, row["id"]).status_code == 200
    hub_job(web, status=400, body={"errorMessage": "Invalid priority code null"}, error="Hub ответил кодом 400")
    failed = db.hub_defect(row["id"])
    assert failed["state"] == "failed"
    card = web.client.get(f"/projects/{pid}/defects/{failed['id']}").text
    assert 'id="hub-defect-retry"' in card and 'id="hub-defect-superseded"' not in card
    listing = web.client.get(f"/projects/{pid}/defects").text
    assert f'id="hub-defect-retry-{failed["id"]}"' in listing
    def attempt(state, number="", app_id=None):  # следующая попытка того же номера
        with db._tx() as c:
            c.execute("INSERT INTO hub_defects(project_id,kind,number,summary,state,origin,hub_url,app_id,"
                      "hub_defect_id,targets_json,created_at,updated_at) SELECT project_id,kind,number,summary,?,"
                      "origin,hub_url,COALESCE(?,app_id),?,targets_json,created_at,updated_at FROM hub_defects"
                      " WHERE id=?", (state, app_id, number, failed["id"]))
            c.execute("UPDATE hub_defects SET draft_owner_id=id WHERE draft_owner_id IS NULL")

    # незавершённая попытка и созданный дефект другого приложения Hub – не замена (ревью dev12)
    attempt("creating")
    attempt("unknown")
    attempt("done", "9001", app_id=8)
    card = web.client.get(f"/projects/{pid}/defects/{failed['id']}").text
    assert 'id="hub-defect-superseded"' not in card and 'id="hub-defect-retry"' in card
    attempt("done", "90091")
    card = web.client.get(f"/projects/{pid}/defects/{failed['id']}").text
    assert 'id="hub-defect-superseded"' in card and "№90091 в Hub" in card and 'id="hub-defect-retry"' not in card
    assert "Можно попробовать ещё раз" not in card
    listing = web.client.get(f"/projects/{pid}/defects").text
    assert f'id="hub-defect-superseded-{failed["id"]}"' in listing and ">заменена<" in listing
    assert "Можно попробовать ещё раз" not in listing


def test_old_list_markup_and_numbers_as_text_across_versions():
    """Ревью dev14: дефект, созданный до 0.9.26.dev14 со списком `<ol>`, узнаётся сверкой создания по тексту «1) …»;
    подтверждение «Push в Hub» не принимает прежний `<ol>` за дошедшие пункты текстом и наоборот."""
    text = "Обоснование:\nтекст\n\nРекомендация:\n1) А\n2) Б"
    old = "<p>Обоснование:<br>текст</p><p>Рекомендация:</p><ol><li>А</li><li>Б</li></ol>"
    new = hub_defects.command_html(text)
    assert "<ol>" not in new and "1) А" in new
    assert hub_defects.description_matches(old, text) and hub_defects.description_matches(new, text)
    assert not hub_defects.description_matches("<p>Другое</p>", text)
    assert not hub_defects.update_content_new({"summary": "T", "description": old}, {"summary": "T", "description": new})
    # отправленный до обновления `<ol>` прочитан пунктами текстом – нормализация, подтверждается (ревью dev14, круг 2)
    assert hub_defects.update_content_new({"summary": "T", "description": new}, {"summary": "T", "description": old})
    assert hub_defects.update_content_new({"summary": "T", "description": new}, {"summary": "T", "description": new})
    assert hub_defects.update_content_new({"summary": "T", "description": "<p>1) А<br />2) Б</p>"},
                                          {"summary": "T", "description": "<p>1) А<br>2) Б</p>"}), "нормализация HTML"
