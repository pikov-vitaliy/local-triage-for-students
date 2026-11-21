"""Таблица групп находок и SCA (план dev7, раздел 3): находка попадает ровно в один столбец, сумма равна «Находок»,
«Внесено в Hub» считается отдельно; у компонентов столбец прежний. Данные выдуманы."""

from __future__ import annotations

import re

import pytest

from app import worklists
from test_web import prepared, web  # noqa: F401

BUCKET_KEYS = [b[0] for b in worklists.BUCKETS]


@pytest.mark.parametrize("decision, verdict, bound, expected", [
    ("", "", False, "undecided"),
    ("later", "true_positive", False, "undecided"),
    ("disagree", "uncertain", False, "undecided"),
    ("agree", "", False, "undecided"),
    ("agree", "false_positive", False, "false_positive"),
    ("disagree", "false_positive", False, "false_positive"),
    ("risk_accepted", "", False, "risk_accepted"),
    ("disagree", "true_positive", False, "no_defect"),
    ("disagree", "true_positive", True, "in_defect"),
    ("agree", "false_positive", True, "in_defect"),
    ("", "", True, "in_defect"),
])
def test_finding_goes_to_exactly_one_column(decision, verdict, bound, expected):
    assert worklists.finding_bucket(decision, verdict, bound) == expected


def rows_with(buckets_list):
    return [{"hub_id": str(n), "kind": "SAST", "data": {"rule": "R"}, "rule": "R", "buckets": b, "entered": e, "findings": sum(b.values())}
            for n, (b, e) in enumerate(buckets_list)]


def test_group_sums_rows():
    rows = rows_with([({"in_defect": 1}, 1), ({"false_positive": 2, "undecided": 1}, 1), ({"no_defect": 1}, 0)])
    w = worklists.table(rows, {"group_by": "family"}, path="/x", kind="findings")
    group = w["groups"][0]
    assert group["buckets"] == {"in_defect": 1, "false_positive": 2, "risk_accepted": 0, "no_defect": 1, "undecided": 1}
    assert sum(group["buckets"].values()) == group["findings"] == 5 and group["entered"] == 2


def group_cells(page: str) -> list[dict]:
    """Строки обзора групп: {«Находок»: число, столбец: число}."""
    out = []
    table = page.split("worklist-groups", 1)[1].split("</table>", 1)[0]
    for row in re.findall(r"<tr>\s*<td>.*?</tr>", table, re.S):
        cells = dict(re.findall(r'data-bucket="(\w+)">([^<]*)<', row))
        counts = {k: 0 if v == "–" else int(v) for k, v in cells.items()}
        numbers = re.findall(r"</td><td>(\d+)</td>(?=<td class=\"group-count\")", row)
        out.append({"findings": int(numbers[-1]), **counts})
    return out


def assert_sums(page: str) -> list[dict]:
    rows = group_cells(page)
    assert rows, "обзор групп пуст"
    for row in rows:
        assert sum(row[k] for k in BUCKET_KEYS) == row["findings"], row
    return rows


@pytest.mark.parametrize("path", ["findings?kind=SAST&group_by=family", "sca?group_by=family"])
def test_page_columns_sum_to_findings(web, path):
    pid = prepared(web)
    page = web.client.get(f"/projects/{pid}/{path}").text
    for label in ("В дефекте", "Ложные", "Риск принят", "Подтверждено, без дефекта", "Без решения", "Внесено в Hub"):
        assert f">{label}</th>" in page
    assert ">С решением</th>" not in page
    assert_sums(page)


def test_decision_moves_finding_between_columns(web):
    from test_defect import save_sast
    pid = prepared(web)
    before = assert_sums(web.client.get(f"/projects/{pid}/findings?kind=SAST&group_by=family").text)
    save_sast(web, pid, "510001", "disagree", "true_positive", "Данные из запроса попадают в SQL без параметров.")
    after = assert_sums(web.client.get(f"/projects/{pid}/findings?kind=SAST&group_by=family").text)
    assert sum(r["undecided"] for r in after) == sum(r["undecided"] for r in before) - 1
    assert sum(r["no_defect"] for r in after) == sum(r["no_defect"] for r in before) + 1
    assert sum(r["findings"] for r in after) == sum(r["findings"] for r in before)


def test_entered_column_follows_current_hub_target(web):
    """Отметка статуса под другим адресом Hub: столбец считает как список и фильтр – только текущее назначение."""
    from test_hub_status_routes import decide, project, run_worker, sast, send
    pid = project(web, [sast("101")])
    decide(web, pid, "101")
    assert send(web, pid, "101").status_code == 200
    run_worker(web, body={"id": 1, "status": "False Positive"})
    db = web.app.state.db
    assert db.get_review(pid, "101")["entered_hub"] == 1
    url = f"/projects/{pid}/findings?group_by=family"
    assert sum(r["entered"] for r in group_cells(web.client.get(url).text)) == 1
    with db._tx() as c:
        c.execute("UPDATE projects SET hub_app_id = hub_app_id + 1000 WHERE id = ?", (pid,))
    assert sum(r["entered"] for r in group_cells(web.client.get(url).text)) == 0


def test_sca_entered_count_is_not_overwritten(web, monkeypatch):
    """Счётчик версии считает база по всем находкам. Неполная карта отметок его не портит: столбец показывает внесённые,
    полностью внесённая версия не попадает в отбор «Не внесены в Hub»."""
    from app.routes import sca as route
    pid = prepared(web)
    db = web.app.state.db
    with db._tx() as c:
        for hub_id in ("73001", "73002"):
            c.execute("INSERT INTO reviews(project_id, hub_id, decision, reviewed, entered_hub, updated_at) VALUES (?, ?, 'later', 1, 1, '2026-11-05')"
                      " ON CONFLICT(project_id, hub_id) DO UPDATE SET entered_hub = 1", (pid, hub_id))
    monkeypatch.setattr(route, "_finding_marks", lambda db, project_id: {})
    rows = assert_sums(web.client.get(f"/projects/{pid}/sca?group_by=family").text)
    assert sum(r["entered"] for r in rows) == 2, rows
    not_entered = web.client.get(f"/projects/{pid}/sca?show=not_entered").text
    assert "example-parser" not in not_entered.split("worklist", 1)[-1], "версия внесена полностью"
    assert route.MARKS_LIMIT > 200_000, "предел отметок не меньше предела выгрузки"


def test_components_keep_their_column(web):
    pid = prepared(web)
    page = web.client.get(f"/projects/{pid}/components?group_by=family").text
    if "worklist-groups" in page:
        assert ">С решением</th>" in page and ">В дефекте</th>" not in page
