"""Ключ группы второй редакции (ADR-0095) через маршруты карточки и выдачи: слившаяся группа – номера не сводятся,
гонки между проверкой и записью, собственный номер другой подгруппы; переимпорт после миграции не трогает подписи.
Выгрузка и код – выдуманные демо-данные."""

from __future__ import annotations

import re

from app import defect
from hub_fixtures import SAST_ROWS, make_hub_xlsx
from test_defect import save_sast
from test_sca import AS_JSON
from test_web import ORIGIN, create_project, start_run, upload, wait_run, web  # noqa: F401

REASON = "Подтверждено: owner из запроса попадает в SQL без параметров."
IDS = ("520001", "520002", "520003", "520004")


def merged_project(web, holders: dict[str, int]) -> tuple[int, str]:  # noqa: F811
    """Четыре находки той же строки и категории; у 520002 и 520004 CWE в другом порядке – прежние ключи разные, ключ
    второй редакции общий. Решения «Подтверждаю дефект» с одним текстом, номера holders, факт слияния – как после шага 20."""
    rows = []
    for n, hub_id in enumerate(IDS):
        cwe = "564, 89" if n % 2 else "89, 564"
        rows.append(dict(SAST_ROWS[0], **{"Issue id": hub_id, "CWE ID": cwe}))
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "merged.xlsx", sast=rows)).status_code == 303
    r = web.client.post(f"/projects/{pid}/repos", data={"repos_dir": "team"}, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    db = web.app.state.db
    db.set_settings({"team_name": "Платформа"})
    for hub_id in IDS:
        save_sast(web, pid, hub_id, "true_positive", "", REASON)
    for hub_id, number in holders.items():
        db.set_defect_number(pid, defect.defect_key_sast(hub_id), number)
    key = db._one("SELECT group_key2 FROM findings WHERE project_id = ? AND hub_id = ?", (pid, IDS[0]))["group_key2"]
    assert key and {r["group_key2"] for r in db._all("SELECT group_key2 FROM findings WHERE project_id = ?"
                                                     " AND kind = 'SAST' AND hub_id IN (?, ?, ?, ?)", (pid, *IDS))} == {key}
    numbers = sorted(set(holders.values()))
    with db._tx() as c:
        c.execute("INSERT INTO sast_group_merges(project_id, group_key2, old_keys_json, numbers_json, merged_at)"
                  " VALUES (?, ?, '[\"a\",\"b\"]', ?, '2026-10-23T14:00:00+00:00')", (pid, key, str(numbers)))
    return pid, key


def card_url(web, pid: int, hub_id: str) -> str:  # noqa: F811
    return f"/projects/{pid}/findings/{web.app.state.db.get_finding_by_hub_id(pid, hub_id)['id']}"


def issue(web, pid: int, hub_id: str, number: int | None):  # noqa: F811
    url = card_url(web, pid, hub_id)
    page = web.client.get(url).text
    shown = re.search(r'name="number_shown" value="([^"]*)"', page).group(1)
    return web.client.post(f"{url}/defect", headers=AS_JSON, data={
        "number": "" if number is None else str(number), "number_shown": shown})


def test_card_warns_and_each_holder_issues_its_own_number(web):  # noqa: F811
    pid, _ = merged_project(web, {"520001": 10, "520002": 20})
    page = web.client.get(card_url(web, pid, "520001")).text
    assert 'id="group-merge-notice"' in page and "Группа объединена при обновлении" in page
    assert "В Hub могли быть два дефекта" in page and "к какому дефекту относится каждая находка" in page
    assert "отметьте только находки этого дефекта" in page, "панель дефекта не предлагает отметить всю группу"
    assert 'id="defect-number" value="10"' in page
    assert issue(web, pid, "520001", 10).status_code == 200
    assert issue(web, pid, "520002", 20).status_code == 200
    got = issue(web, pid, "520003", 20)
    assert got.status_code == 200, got.text  # находка без номера – любой из исторических
    refused = issue(web, pid, "520004", 30)
    assert refused.status_code in (400, 409) and "выберите один из них" in refused.json()["detail"]
    db = web.app.state.db
    assert db.defect_number(pid, defect.defect_key_sast("520004")) is None, "отказ – ничего не записано"


def test_own_number_outside_history_keeps_its_form_in_sync(web):  # noqa: F811
    """Держатель номера вне исторических (30) при двух исторических: предлагается исторический, а number_shown –
    сохранённый 30: выдача с историческим номером проходит, без бесконечного «номер изменили в другой вкладке»."""
    pid, _ = merged_project(web, {"520001": 10, "520002": 20, "520003": 30})
    db = web.app.state.db
    with db._tx() as c:
        c.execute("UPDATE sast_group_merges SET numbers_json = '[10,20]' WHERE project_id = ?", (pid,))
    page = web.client.get(card_url(web, pid, "520003")).text
    assert re.search(r'name="number_shown" value="30"', page)
    got = issue(web, pid, "520003", 10)
    assert got.status_code == 200, got.text
    assert db.defect_number(pid, defect.defect_key_sast("520003")) == 10


def test_race_number_became_inadmissible_is_refused_in_the_transaction(web, monkeypatch):  # noqa: F811
    pid, _ = merged_project(web, {"520001": 10, "520002": 20})
    db = web.app.state.db
    original = db.set_defect_number_checked

    def other_tab_first(*args, **kwargs):
        db.set_defect_number(pid, defect.defect_key_sast("520002"), 10)  # в подгруппе остался один исторический
        return original(*args, **kwargs)

    monkeypatch.setattr(db, "set_defect_number_checked", other_tab_first)
    refused = issue(web, pid, "520003", 20)
    assert refused.status_code in (400, 409), refused.text
    assert "ID10" in refused.json()["detail"], "отказ – по правилу номера в транзакции (остался один исторический)"
    assert db.defect_number(pid, defect.defect_key_sast("520003")) is None


def test_race_holders_changed_but_number_still_admissible_passes(web, monkeypatch):  # noqa: F811
    pid, _ = merged_project(web, {"520001": 10, "520002": 20, "520004": 20})
    db = web.app.state.db
    original = db.set_defect_number_checked

    def other_tab_first(*args, **kwargs):
        db.set_defect_number(pid, defect.defect_key_sast("520004"), 10)  # держатели сменились, kept = {10, 20}
        return original(*args, **kwargs)

    monkeypatch.setattr(db, "set_defect_number_checked", other_tab_first)
    got = issue(web, pid, "520003", 10)
    assert got.status_code == 200, got.text
    assert db.defect_number(pid, defect.defect_key_sast("520003")) == 10


def test_reimport_over_http_keeps_the_decision_reviewed(web):  # noqa: F811
    """Переимпорт той же выгрузки через загрузку (ключ второй редакции пересчитывается): решение остаётся
    проверенным, подпись решения не меняется."""
    from test_web import prepared
    pid = prepared(web)
    assert wait_run(web, start_run(web, pid))["state"] == "done"
    db = web.app.state.db
    url, _ = save_sast(web, pid, "510001", "false_positive", "", "Значение берётся из константы, подстановки нет.")
    before = db.get_review(pid, "510001")
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "again.xlsx")).status_code == 303
    after = db.get_review(pid, "510001")
    assert after["reviewed"] == 1 and after["finding_sig"] == before["finding_sig"]
    assert 'id="reviewed-badge"' in web.client.get(url).text


def test_card_shows_near_category_hint(web):  # noqa: F811
    rows = [dict(SAST_ROWS[0], **{"Issue id": "530001"}),
            dict(SAST_ROWS[0], **{"Issue id": "530002", "Line number": "60", "Source code": SAST_ROWS[0]["Source code"]})]
    pid = create_project(web.client)
    assert upload(web.client, pid, make_hub_xlsx(web.tmp / "near.xlsx", sast=rows)).status_code == 303
    page = web.client.get(card_url(web, pid, "530001")).text
    assert 'id="near-category"' in page and "Рядом та же категория: 1" in page and "530002" in page


def test_merged_group_with_two_numbers_has_no_whole_group_reminder(web):  # noqa: F811
    """Слившаяся группа с разными номерами: напоминание «создайте дефект из всех находок группы» не показывается –
    оно противоречило бы указанию панели отметить только находки своего дефекта."""
    pid, _ = merged_project(web, {IDS[0]: 10, IDS[1]: 20})
    page = web.client.get(card_url(web, pid, IDS[2])).text
    assert "отметьте только находки этого дефекта" in page
    assert "hub-group-reminder" not in page
    assert "из списка «Та же строка, та же категория и тот же код» и создайте из них дефект" not in page, "справка шага 7"
    assert "отметьте галочкой только находки этого дефекта" in page
