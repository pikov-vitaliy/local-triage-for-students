"""Замечания оператора (план dev9, часть 2): значок тестового кода, заготовка обоснования, пометки карточки,
главные кнопки, отбор и заготовка SCA. Данные выдуманы, сети нет."""

from __future__ import annotations

import re

import pytest

from app import defect_fields
from app.models import CodeContext, Finding
from app.routes import findings as card_routes
from app.view import is_test_path
from fake_ollama import verdict_answer
from test_findings_ui import analysed, card_of
from test_hub_defect_update import FIX, REASON, hub_settings, prepared, ready, save_sast
from test_hub_status_routes import fid, project, sast
from test_web import ORIGIN, start_run, wait_run, web  # noqa: F401


@pytest.mark.parametrize("path, expected", [
    ("src/test/java/Foo.java", True),
    ("tests/test_x.py", True),
    ("app/Tests/Foo.cs", True),
    ("a\\tests\\b.py", True),
    ("test/x", True),
    ("/opt/repo/test/x.py", True),
    ("contest/x.py", False),
    ("latest/x.py", False),
    ("src/testing/x.py", False),
    ("src/mytests/x.py", False),
    ("test_x.py", False),
    ("src/tests", False),  # имя файла, а не каталог
    ("src/test.py", False),
    ("", False),
    (None, False),
])
def test_is_test_path(path, expected):
    assert is_test_path(path) is expected


def test_badge_in_card_and_list_only_for_test_dirs(web):
    """Только показ: отбор не меняется, обычная находка без значка."""
    pid = project(web, [Finding(hub_id="101", kind="SAST", rule="Внедрение SQL", cwe=["CWE-89"], codebase="demo",
                                file="src/test/demo.py", line=2, snippet="x = 1", severity="high"), sast("102")])
    badge = 'test-code-badge'
    assert badge in web.client.get(f"/projects/{pid}/findings/{fid(web, pid, '101')}").text
    assert badge not in web.client.get(f"/projects/{pid}/findings/{fid(web, pid, '102')}").text
    page = web.client.get(f"/projects/{pid}/findings").text
    assert page.count(badge) == 1 and "тестовый код" in page


# ---------------------------------------------------------------------------- п. 10: главная кнопка у дефекта

def _row(**fields) -> dict:
    return {"summary": "ID5 - s", "draft_summary": "ID5 - s", "command_text": "a  b\nc", "draft_command_text": "a  b\nc",
            "origin": "app", **fields}


@pytest.mark.parametrize("fields, expected", [
    ({}, False),
    ({"draft_summary": "ID5 - другое"}, True),
    ({"draft_command_text": "a b\nc\n"}, False),  # у дефекта приложения форма строк правкой не считается
    ({"draft_command_text": "a b\nc\n", "origin": "import"}, True),  # у занесённого – точное сравнение
    ({"draft_command_text": "a  b\nc d"}, True),
    ({"draft_revision": 9}, False),  # рост редакции сам по себе не правка
])
def test_unsent_edit_of_text_and_title(monkeypatch, fields, expected):
    monkeypatch.setattr(defect_fields, "local_changes", lambda row: {})
    assert defect_fields.unsent_edit(_row(**fields)) is expected


def test_unsent_edit_of_fields_and_unknown_basis(monkeypatch):
    monkeypatch.setattr(defect_fields, "local_changes", lambda row: {"priority": "High"})
    assert defect_fields.unsent_edit(_row()) is True

    def unknown(row):
        raise ValueError("основа неизвестна")
    monkeypatch.setattr(defect_fields, "local_changes", unknown)
    with pytest.raises(ValueError):
        defect_fields.unsent_edit(_row())
    assert defect_fields.unsent_edit(_row(draft_summary="другое")) is True, "правка текста видна и без основы полей"


def _push_button(page: str) -> str:
    return re.search(r'<button class="([^"]*)" type="submit" id="defect-update-prepare"', page).group(1)


def test_push_is_main_only_with_unsent_edit(web):
    pid, row = ready(web, build=False)
    url = f"/projects/{pid}/defects/{row['id']}"
    assert "btn-primary" not in _push_button(web.client.get(url).text), "правки нет – обычная кнопка"
    saved = web.app.state.db.hub_defect(row["id"])
    answer = web.client.post(url + "/fields", headers=ORIGIN, data={
        "draft_revision": str(saved["draft_revision"]), "summary": "ID5 - Ручная правка (SAST)",
        "command_text": saved["draft_command_text"]})
    assert answer.status_code == 200, answer.text
    assert "btn-primary" in _push_button(web.client.get(url).text), "неотправленная правка – главная"


# ---------------------------------------------------------------------------- п. 1: заготовка обоснования и решение

FP_TEXT = "Ложное срабатывание: значение приводится к числу до подстановки в запрос."


@pytest.mark.parametrize("text, verdict, expected", [
    (FP_TEXT, "true_positive", "false_positive"),
    ("  ложное срабатывание – число", "true_positive", "false_positive"),
    (FP_TEXT, "false_positive", "false_positive"),
    (FP_TEXT, "uncertain", "false_positive"),
    ("Подтверждено: запрос собирается из параметра.", "true_positive", "true_positive"),
    ("Не ложное срабатывание: запрос собирается из параметра.", "true_positive", "true_positive"),
    ("", "true_positive", "true_positive"),
])
def test_model_comment_verdict(text, verdict, expected):
    assert card_routes.model_comment_verdict(text, verdict) == expected


def _model_comment(page: str) -> tuple[str, str]:
    field = re.search(r'<textarea name="comment" id="comment"[^>]*>(.*?)</textarea>', page, re.S).group(1)
    return field, re.search(r'data-model-comment-for="([^"]*)"', page).group(1)


def test_fp_text_of_true_positive_verdict_is_not_prefilled_and_is_stale_for_defect(web):
    pid = analysed(web, verdict_answer("true_positive", 85, hub_comment=FP_TEXT))
    fid_, page = card_of(web, pid, "510001")
    assert _model_comment(page) == ("", "false_positive"), "свежая карточка: поле пустое, текст относится к ложному срабатыванию"
    assert re.search(r'id="comment-stale" hidden', page), "до решения предупреждения нет"
    db = web.app.state.db
    case = db.get_case(pid, "510001")
    assert card_routes.comment_origin(db, case, None, FP_TEXT, project_id=pid, hub_id="510001") == "false_positive"
    db.save_review(pid, "510001", decision="agree", final_verdict="true_positive", final_comment=FP_TEXT, reviewed=True)
    _, page = card_of(web, pid, "510001")
    assert not re.search(r'id="comment-stale" hidden', page), "сохранённый текст о ложном срабатывании у дефекта подсвечен"
    assert card_routes.model_suggestion(Finding.from_dict(db.get_finding(pid, fid_)["data"]), case)["comment"] == ""


@pytest.mark.parametrize("verdict, start", [("false_positive", "Ложное срабатывание:"), ("true_positive", "Подтверждено:")])
def test_ordinary_model_texts_are_prefilled_as_before(web, verdict, start):
    pid = analysed(web, verdict_answer(verdict, 85))
    _, page = card_of(web, pid, "510001")
    assert _model_comment(page)[0].startswith(start) and _model_comment(page)[1] == verdict


# ---------------------------------------------------------------------------- п. 2: строка срабатывания скрыта

@pytest.mark.parametrize("line, rule, expected", [
    ("<SECRET_abc123>", "Жёстко заданный пароль", True),
    ('    "<SECRET_abc123>",', "Hardcoded password", True),
    ('    "<SECRET_abc123>";', "Hardcoded password", True),
    ('DB_PASSWORD = "<SECRET_abc123>";', "Hardcoded password", False),  # имя видно: строка не скрыта целиком
    ("x = 1", "Hardcoded password", False),
    ("<SECRET_abc123>", "Внедрение SQL", False),  # не находка о секрете
    ("", "Hardcoded password", False),
])
def test_target_line_hidden(line, rule, expected):
    f = Finding(hub_id="1", kind="SAST", rule=rule, cwe=[])
    ctx = CodeContext(file="a.py", status="ok", language="python", start_line=5, end_line=6, target_line=6, lines=["x = 2", line])
    assert card_routes.target_line_hidden(f, ctx) is expected
    assert card_routes.target_line_hidden(f, None) is False


def test_hidden_line_note_in_verdict_panel(web, monkeypatch):
    pid = analysed(web)
    db = web.app.state.db
    case = db.get_case(pid, "510001")
    context = dict(case["context"])
    context["lines"] = [("<SECRET_abc123>" if context["start_line"] + k == context["target_line"] else line)
                        for k, line in enumerate(context["lines"])]
    _, page = card_of(web, pid, "510001")
    assert 'id="target-line-hidden"' not in page
    assert db.save_case(pid, "510001", case["case_hash"], context, case["verdict_id"])
    monkeypatch.setattr(card_routes, "is_credential_finding", lambda rule, cwe: True)
    _, page = card_of(web, pid, "510001")
    note = "Строка срабатывания скрыта меткой, вердикт модели по такой находке ненадёжен: сверьте с фрагментом выгрузки и с кодом в Hub."
    assert note in page
    assert page.index('id="verdict-title"') < page.index('id="target-line-hidden"') < page.index('id="step-3"'), "в панели вердикта"


# ---------------------------------------------------------------------------- п. 3: панель дефекта

MANUAL = "Создайте дефект в Hub вручную"


def _tp_card(web, with_hub: bool) -> str:
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    if with_hub:
        hub_settings(web, pid)
    save_sast(web, pid, "510001", "true_positive", "", REASON, FIX)
    return card_of(web, pid, "510001")[1]


def test_panel_with_hub_offers_creation_instead_of_manual_phrase(web):
    page = _tp_card(web, True)
    assert MANUAL not in page and 'id="defect-auto-hint"' in page
    assert 'id="go-create" href="#hub-defect"' in page and "Дефект готов: нажмите «Создать дефект»" in page
    assert "hub-group-reminder" not in page


def test_panel_without_hub_stays_as_before(web):
    page = _tp_card(web, False)
    assert MANUAL in page and 'id="defect-auto-hint"' not in page and 'id="go-create"' not in page
    assert "Дефект: текст – в описание дефекта в Hub" in page


# ---------------------------------------------------------------------------- п. 11: отбор по статусу Hub

def _rows(page: str) -> list[str]:
    return re.findall(r'<tr id="finding-(\d+)"', page)


def test_hub_status_filter_joins_other_filters_and_keeps_in_card(web):
    pid = project(web, [Finding(hub_id="101", kind="SAST", rule="r", file="a.py", line=1, severity="high", status="Open"),
                        Finding(hub_id="102", kind="SAST", rule="r", file="a.py", line=2, severity="high", status="Open"),
                        Finding(hub_id="103", kind="SAST", rule="r", file="a.py", line=3, severity="high", status="Fixed"),
                        Finding(hub_id="104", kind="SAST", rule="r", file="a.py", line=4, severity="high", status="")])
    db = web.app.state.db
    assert db.finding_statuses(pid) == ["Fixed", "Open"]
    db.save_review(pid, "102", decision="disagree", final_verdict="true_positive", final_comment="Текст.", reviewed=False)
    first, second, third = fid(web, pid, "101"), fid(web, pid, "102"), fid(web, pid, "103")
    base = f"/projects/{pid}/findings"
    page = web.client.get(base).text
    assert "Статус Hub" in page and "Статус Hub (из выгрузки)" not in page and "Вердикт модели" in page
    assert _rows(web.client.get(base + "?hub_status=Open").text) == [str(first), str(second)]
    assert _rows(web.client.get(base + "?hub_status=Fixed").text) == [str(third)]
    assert _rows(web.client.get(base + "?hub_status=Open&decision=none").text) == [str(first)]
    assert _rows(web.client.get(base + "?hub_status=Open&decision=none&verdict=none").text) == [str(first)]
    assert _rows(web.client.get(base + "?hub_status=Open&decision=none&verdict=true_positive").text) == []
    assert "Под фильтр ничего не попало" in web.client.get(base + "?hub_status=Нет такого").text
    # карточка ведёт по той же выборке и называет её
    card = web.client.get(f"{base}/{first}?hub_status=Open").text
    assert "статус Hub: Open" in card and f'id="nav-next" href="{base}/{second}?hub_status=Open"' in card
    assert "Проверено 0 из 2" in card


def test_no_status_group_without_statuses(web):
    pid = project(web, [sast("101")])
    assert "Статус Hub (из выгрузки)" not in web.client.get(f"/projects/{pid}/findings").text
