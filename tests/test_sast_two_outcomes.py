"""SAST: два решения и группа «та же строка и категория» (ADR-0089, 0.9.6).

Проверяются: пункты рекомендации дефекта, обязательное обоснование, отметки «Внесено в Hub» прежних форматов,
номер дефекта группы (большая группа и находка, пропавшая из выгрузки) и отказы при разном решении или тексте
у находок группы.
"""

from __future__ import annotations

import re

import pytest

from app import defect
from app.db import Database, text_hash
from app.hub_import import group_key2 as group_key  # ключ группы второй редакции (ADR-0095)
from app.models import Finding
from app.prompts import hub_text_v1, hub_text_v2
from app.routes.findings import saved_hub_text_v1, saved_hub_text_v2
from app.triage import order_findings
from hub_fixtures import INVOICE, MITRE, SAST_BASE, SAST_ROWS, SCA_ROWS, SQL_LINE, make_hub_xlsx
from test_web import ORIGIN, create_project, hidden_fields, prepared, start_run, upload, wait_run, web  # noqa: F401

AS_JSON = {**ORIGIN, "Accept": "application/json"}
# близнец находки 510001: та же категория, тот же файл и та же строка – в Hub это один дефект
TWIN = dict(SAST_BASE, **{"Issue id": "510011", "Severity": "High", "Category": "Внедрение SQL-кода", "File": INVOICE,
                          "Line number": "58", "Source code": f"{SQL_LINE} : 58", "CWE ID": "89",
                          "CWE link": MITRE.format(89)})


def card_url(web, pid: int, hub_id: str) -> str:  # noqa: F811
    return f"/projects/{pid}/findings/{web.app.state.db.get_finding_by_hub_id(pid, hub_id)['id']}"


def fields(web, url: str) -> dict:  # noqa: F811
    card = web.client.get(url).text
    return {name: re.search(rf'name="{name}" value="([^"]*)"', card).group(1)
            for name in ("finding_version", "verdict_id", "review_revision", "code_hash", "code_chars")}


def review(web, url: str, decision: str, comment: str, fix: str = "", action: str = "save"):  # noqa: F811
    return web.client.post(f"{url}/review", headers=AS_JSON, data={
        **fields(web, url), "decision": decision, "final_verdict": "", "comment": comment, "fix": fix,
        "reviewed": "1", "action": action})


def issue_defect(web, url: str, number: str = ""):  # noqa: F811
    return web.client.post(f"{url}/defect", headers=AS_JSON, data={"number": number, "confirm": "1"})


@pytest.fixture
def group(web):  # noqa: F811
    """Проект, где у находки 510001 есть близнец 510011 с тем же ключом группы."""
    pid = create_project(web.client)
    path = make_hub_xlsx(web.tmp / "group.xlsx", sast=[*SAST_ROWS, TWIN], sca=SCA_ROWS, practices="auto")
    assert upload(web.client, pid, path).status_code == 303
    r = web.client.post(f"/projects/{pid}/repos", data={"repos_dir": "team"}, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303, r.text
    web.app.state.db.set_settings({"team_name": "Платформа"})
    return pid


# ============================================================================ текст дефекта и обоснование

def test_fix_items_splits_plain_and_numbered_lines():
    """Каждая строка рекомендации – отдельный пункт: маркер в начале строки снимается, текст остаётся."""
    assert defect.fix_items("Первый шаг\n2) Второй шаг\nТретий шаг") == ["Первый шаг", "Второй шаг", "Третий шаг"]
    assert defect.fix_items("   \n\n") == []


def test_false_positive_reason_cannot_be_only_the_lead_in(web):  # noqa: F811
    """Одно вводное «Ложное срабатывание:» обоснованием не считается: без своих слов решение не сохраняется. С
    0.10.0.dev21 (ADR-0149) в Hub уходит комментарий как написан, вместе с вводным словом."""
    pid = prepared(web)
    url = card_url(web, pid, "510001")
    r = review(web, url, "false_positive", "Ложное срабатывание:")
    assert r.status_code == 400 and "почему срабатывание ложное" in r.json()["detail"], r.text
    assert web.app.state.db.get_review(pid, "510001") is None
    ok = review(web, url, "false_positive", "Ложное срабатывание: имя таблицы берётся из заранее заданной строки.")
    assert ok.status_code == 200 and ok.json()["hub_text"] == (
        "Ложное срабатывание: имя таблицы берётся из заранее заданной строки.")


def test_true_positive_reason_is_required(web):  # noqa: F811
    pid = prepared(web)
    url = card_url(web, pid, "510001")
    r = review(web, url, "true_positive", "   ", fix="Параметризовать запрос.")
    assert r.status_code == 400 and "обоснование дефекта" in r.json()["detail"].lower(), r.text


# ============================================================================ отметки прежних форматов

@pytest.mark.parametrize("legacy", ["v1", "v2"])
def test_entered_marks_of_old_formats_are_recognised(web, legacy):  # noqa: F811
    """Отметка «Внесено в Hub» по тексту до 0.9.0 (v1) и по тексту 0.9.0–0.9.5 (v2): карточка говорит «формат
    обновился», а не «текст изменился»."""
    pid = prepared(web)
    db = web.app.state.db
    url = card_url(web, pid, "510001")
    saved = review(web, url, "false_positive", "Параметр приводится к числу.").json()
    row = db.get_finding_by_hub_id(pid, "510001")
    f = Finding.from_dict(row["data"])
    stored = db.get_review(pid, "510001")
    status_map = web.settings.with_stored(db.get_settings()).hub_status_map
    old_text = (saved_hub_text_v1 if legacy == "v1" else saved_hub_text_v2)(f, stored, status_map)
    assert old_text and old_text != "Параметр приводится к числу."
    db.mark_entered(pid, "510001", True, revision=int(saved["revision"]), entered_hash=text_hash(old_text))
    card = web.client.get(url).text
    assert 'id="entered-format-updated"' in card
    assert 'id="entered-changed"' not in card
    # а текст, которого вообще не было, – это именно изменение текста
    db.mark_entered(pid, "510001", True, revision=int(db.get_review(pid, "510001")["revision"]),
                    entered_hash=text_hash("совсем другой текст"))
    card = web.client.get(url).text
    assert 'id="entered-changed"' in card and 'id="entered-format-updated"' not in card


def test_old_format_texts_differ_from_the_new_one():
    """Контроль: тексты v1 и v2 действительно другие – иначе проверка форматов ничего не значит."""
    f = Finding(hub_id="1", kind="SAST", rule="Внедрение SQL-кода", file="src/A.java", line=42, cwe=["CWE-89"])
    assert hub_text_v1(f, "false_positive", "x", None) != hub_text_v2(f, "false_positive", "x", None)
    assert "Статус:" in hub_text_v2(f, "false_positive", "x", None)


# ============================================================================ номер дефекта группы

def sast_row(hub_id: str, codebase: str = "svc") -> Finding:
    return Finding(hub_id=hub_id, kind="SAST", rule="Внедрение SQL-кода", file="src/A.java", line=42,
                   cwe=["CWE-89"], codebase=codebase)


def test_group_number_is_found_in_a_large_group(tmp_path):
    """Находок в группе больше, чем показывает карточка (50): номер дефекта всё равно находится – даже у последней."""
    db = Database(tmp_path / "t.db")
    pid = db.create_project("p")
    rows = [sast_row(f"5100{n:02d}") for n in range(1, 61)]
    db.save_import(pid, "a.xlsx", "xlsx", [], {}, [], order_findings(rows))
    key = group_key(rows[0])
    assert db.group_count(pid, key, "510001") == 59
    shown = db.group_siblings(pid, key, "510001")
    assert len(shown) == 50, "список карточки ограничен"
    assert "510060" not in {s["hub_id"] for s in shown}, "последняя находка в список карточки не попала"
    db.set_defect_number(pid, defect.defect_key_sast("510060"), 7)
    from app.routes.findings import group_number_plan
    assert group_number_plan(db.group_rows(pid, key, "510001"), None)[0] == 7, "рабочий путь маршрута"
    db.close()


def test_group_number_of_a_missing_finding_is_offered(web, group):  # noqa: F811
    """Находка группы пропала из выгрузки, но дефект в Hub остался: её номер предлагается соседке."""
    db = web.app.state.db
    first = card_url(web, group, "510001")
    assert review(web, first, "true_positive", "Значение из запроса попадает в SQL.",
                  fix="Параметризовать запрос.").status_code == 200
    assert issue_defect(web, first).json()["number"] == 1
    # новая выгрузка без 510001
    rows = [Finding.from_dict(r["data"]) for r in db.findings_data(group) if r["hub_id"] != "510001"]
    db.save_import(group, "again.xlsx", "xlsx", [], {}, [], order_findings(rows))
    assert db.get_finding_by_hub_id(group, "510001")["missing"] == 1
    twin = card_url(web, group, "510011")
    card = web.client.get(twin).text
    assert 'id="defect-number" value="1"' in card, "номер дефекта группы предлагается, хотя находки уже нет"


# ============================================================================ одно решение и один текст на группу

def test_group_refuses_a_different_outcome_or_text(web, group):  # noqa: F811
    db = web.app.state.db
    first, twin = card_url(web, group, "510001"), card_url(web, group, "510011")
    assert review(web, first, "false_positive", "Имя таблицы берётся из заранее заданной строки.").status_code == 200
    # другой текст у соседки: короткий комментарий не копируется
    other_text = review(web, twin, "false_positive", "Проверено, всё хорошо.", action="copy")
    assert other_text.status_code == 400 and "другой текст" in other_text.json()["detail"], other_text.text
    assert "hub_text" not in other_text.json()
    # тот же текст – копируется
    same = review(web, twin, "false_positive", "Имя таблицы берётся из заранее заданной строки.", action="copy")
    assert same.status_code == 200 and same.json()["copy_allowed"] is True, same.text
    # другое решение у соседки: тоже отказ
    assert review(web, first, "true_positive", "Значение из запроса попадает в SQL.",
                  fix="Параметризовать запрос.").status_code == 200
    other_outcome = review(web, twin, "false_positive", "Имя таблицы берётся из заранее заданной строки.",
                           action="copy")
    assert other_outcome.status_code == 400 and "другое решение" in other_outcome.json()["detail"]
    assert db.get_review(group, "510011")["decision"] in ("agree", "disagree")


def test_group_refuses_a_defect_with_another_text_or_number(web, group):  # noqa: F811
    first, twin = card_url(web, group, "510001"), card_url(web, group, "510011")
    assert review(web, first, "true_positive", "Значение из запроса попадает в SQL.",
                  fix="Параметризовать запрос.").status_code == 200
    issued = issue_defect(web, first)
    assert issued.status_code == 200 and issued.json()["number"] == 1
    # у соседки другая рекомендация: дефект не выдаётся
    assert review(web, twin, "true_positive", "Значение из запроса попадает в SQL.",
                  fix="Переписать запрос.").status_code == 200
    conflict = issue_defect(web, twin)
    assert conflict.status_code == 409 and "другой текст" in conflict.json()["detail"], conflict.text
    # тот же текст, но чужой номер – тоже отказ, с подсказкой нужного номера
    assert review(web, twin, "true_positive", "Значение из запроса попадает в SQL.",
                  fix="Параметризовать запрос.").status_code == 200
    wrong_number = issue_defect(web, twin, number="ID9")
    assert wrong_number.status_code == 400 and "ID1" in wrong_number.json()["detail"], wrong_number.text
    # номер группы – тот же самый, и это не ошибка, а подсказка
    ok = issue_defect(web, twin, number="ID1")
    assert ok.status_code == 200 and ok.json()["number"] == 1
    assert "один дефект" in ok.json()["note"]


def test_defect_needs_team_name(web, group):  # noqa: F811
    """Без названия команды стандартная фраза дефекта неполна: выдача отклоняется со ссылкой на «Настройки»
    (ADR-0092 п. 11)."""
    db = web.app.state.db
    db.set_settings({"team_name": ""})
    first = card_url(web, group, "510001")
    assert review(web, first, "true_positive", "Значение из запроса попадает в SQL.",
                  fix="Параметризовать запрос.").status_code == 200
    refused = issue_defect(web, first)
    assert refused.status_code == 409 and "название команды" in refused.json()["detail"], refused.text
    db.set_settings({"team_name": "Платформа"})
    issued = issue_defect(web, first)
    assert issued.status_code == 200 and "команда Платформа приняла" in issued.json()["body"]
