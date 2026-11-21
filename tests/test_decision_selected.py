"""Одно решение на отмеченные находки SAST (план dev7, раздел 7). Данные выдуманы, сети нет."""

from __future__ import annotations

import re

import pytest

from test_defect_selected import setup as selected_project
from test_hub_defects import FIX, REASON
from test_web import ORIGIN, web  # noqa: F401

FP = "Имя таблицы задано константой, внешний ввод в запрос не попадает."


def url(pid: int) -> str:
    return f"/projects/{pid}/hub/decide-selected"


def preview(web, pid, ids=("101", "102"), outcome="false_positive", comment=FP, fix=""):
    r = web.client.post(url(pid), data={"hub_id": list(ids), "outcome": outcome, "comment": comment, "fix": fix, "action": "preview"}, headers=ORIGIN)
    return r


def shown_snapshot(html: str) -> str:
    return re.search(r'name="snapshot" value="([^"]+)"', html).group(1)


def apply(web, pid, html, ids=("101", "102"), outcome="false_positive", comment=FP, fix="", **extra):
    return web.client.post(url(pid), data={"hub_id": list(ids), "outcome": outcome, "comment": comment, "fix": fix, "action": "apply",
                                           "snapshot": shown_snapshot(html), "confirm": "1", **extra}, headers=ORIGIN, follow_redirects=False)


def test_preview_shows_composition_and_saves_nothing(web):
    pid = selected_project(web)
    r = preview(web, pid)
    assert r.status_code == 200 and 'id="decide-apply"' in r.text and FP in r.text
    assert web.app.state.db.get_review(pid, "101") is None or not web.app.state.db.get_review(pid, "101")["decision"]


def test_false_positive_saved_on_all_with_reviewed_mark(web):
    pid = selected_project(web)
    db = web.app.state.db
    r = apply(web, pid, preview(web, pid).text)
    assert r.status_code == 303, r.text
    for hub_id in ("101", "102"):
        review = db.get_review(pid, hub_id)
        assert review["final_verdict"] == "false_positive" and review["final_comment"] == FP and review["reviewed"] == 1 and not review["entered_hub"]
    assert not db._all("SELECT * FROM hub_ops ORDER BY 1, 2"), "в Hub ничего не уходит"


def test_true_positive_needs_reason_and_recommendation(web):
    pid = selected_project(web)
    assert "рекомендацию" in preview(web, pid, outcome="true_positive", comment=REASON).text
    assert preview(web, pid, outcome="true_positive", comment="", fix=FIX).status_code == 400
    assert preview(web, pid, outcome="").status_code == 400
    ok = preview(web, pid, outcome="true_positive", comment=REASON, fix=FIX)
    assert ok.status_code == 200
    assert apply(web, pid, ok.text, outcome="true_positive", comment=REASON, fix=FIX).status_code == 303
    review = web.app.state.db.get_review(pid, "101")
    assert review["final_verdict"] == "true_positive" and review["final_fix"]


def test_changed_decision_makes_page_stale_and_nothing_is_saved(web):
    pid = selected_project(web)
    db = web.app.state.db
    html = preview(web, pid).text
    db.save_review(pid, "102", decision="later", final_verdict="", final_comment="", reviewed=False)
    r = apply(web, pid, html)
    assert r.status_code == 409 and "изменились после показа" in r.text
    assert db.get_review(pid, "101") is None or not db.get_review(pid, "101")["decision"], "всё или ничего"


def test_replaced_decisions_need_confirmation(web):
    pid = selected_project(web)
    db = web.app.state.db
    db.save_review(pid, "102", decision="disagree", final_verdict="false_positive", final_comment="Прежний текст оператора о другом.", reviewed=True)
    html = preview(web, pid).text
    assert 'id="decide-replacements"' in html and "Прежний текст оператора о другом." in html
    r = apply(web, pid, html)
    assert r.status_code == 409 and "замену" in r.text
    assert db.get_review(pid, "102")["final_comment"] == "Прежний текст оператора о другом."
    assert apply(web, pid, html, overwrite="1").status_code == 303
    assert db.get_review(pid, "102")["final_comment"] == FP


def test_postponed_decision_is_shown_as_postponed(web):
    pid = selected_project(web)
    web.app.state.db.save_review(pid, "102", decision="later", final_verdict="true_positive", final_comment="Вернуться после уточнения.", reviewed=False)
    html = preview(web, pid).text
    block = html.split('id="decide-replacements"')[1].split("</details>")[0]
    assert "отложено" in block and "истинн" not in block.lower() and "подтверждаю" not in block.lower(), block


@pytest.mark.parametrize("hub_id, why", [("999999", "нет в текущей выгрузке")])
def test_unknown_finding_is_excluded_with_reason(web, hub_id, why):
    pid = selected_project(web)
    r = preview(web, pid, ids=("101", hub_id))
    assert r.status_code == 200 and why in r.text


def test_too_many_is_refused(web):
    pid = selected_project(web)
    from app.routes.hub_bulk import MAX_SELECTED
    r = web.client.get(url(pid), params={"hub_id": [str(n) for n in range(MAX_SELECTED + 1)]})
    assert r.status_code == 400
