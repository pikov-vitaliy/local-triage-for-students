"""Совет агента «не применимо» против принятого исследования компонента (план dev7, раздел 2): оператор видит расхождение, ложное срабатывание
само не подставляется, «Согласен с агентом» требует явного подтверждения. Данные выдуманы."""

from __future__ import annotations

import re

import pytest

from app import sca
from app.models import Finding
from test_component_research_ui import answer_document, build_task, expect_accepted, project_with_components
from test_sca import AS_JSON, answer, answers_json, form_fields, post_answers, sca_card
from test_web import web  # noqa: F401

COMMENT = "Версия вне диапазона уязвимости: проверено по бюллетеню производителя."


def conflict_project(web, *, conclusion="not_applicable") -> tuple[int, str]:
    pid = project_with_components(web)
    manifest = build_task(web, pid)
    expect_accepted(web, pid, answer_document(manifest))
    finding = web.app.state.db.get_finding_by_hub_id(pid, "73001")["data"]
    own = [*(finding.get("vuln_ids") or []), *(finding.get("cve") or [])]
    r = post_answers(web, pid, answers_json(answer("example-parser", "1.4.2", conclusion=conclusion, ids={}, vulnerabilities=own,
                                                   explanation="Версия вне затронутого диапазона.")))
    assert r.status_code == 303, r.text
    return pid, "73001"


def post_review(web, pid, hub_id, **data):
    fid, card = sca_card(web, pid, hub_id)
    shown = re.search(r'name="research_shown" value="(\d+)"', card).group(1)
    return web.client.post(f"/projects/{pid}/sca/findings/{fid}/review", headers=AS_JSON,
                           data={**form_fields(card), "research_shown": shown, "action": "save", "reviewed": "1", **data})


@pytest.mark.parametrize("status, applicable, expected", [
    ("vulnerable", 2, "исследование компонента: уязвим, применимых уязвимостей 2"),
    ("no_known_vulnerabilities", 0, ""),
    ("incomplete", 0, ""),
    ("incomplete", 1, "исследование компонента: неполное, применимых уязвимостей 1"),
])
def test_conflict_is_about_applicable_vulnerabilities(status, applicable, expected):
    label = {"vulnerable": "уязвим"}.get(status, "неполное")
    assert sca.research_conflict({"conclusion": "not_applicable"}, status, label, applicable) == expected


@pytest.mark.parametrize("answer_fields", [{"conclusion": "update"}, {"conclusion": "unclear"}, {"conclusion": "not_applicable", "origin": "research"}])
def test_other_advice_and_research_itself_are_no_conflict(answer_fields):
    assert sca.research_conflict(answer_fields, "vulnerable", "уязвим", 2) == ""
    assert sca.research_conflict(None, "vulnerable", "уязвим", 2) == ""


def test_card_warns_and_does_not_prefill_false_positive(web):
    pid, hub_id = conflict_project(web)
    _, card = sca_card(web, pid, hub_id)
    assert 'id="advice-conflict"' in card and "расходится с исследованием" in card and 'id="advice-conflict-confirm"' in card
    assert 'value="false_positive" selected' not in card
    assert '<textarea name="comment"' in card or 'name="comment"' in card
    assert "Не применимо: " not in card.split('name="comment"', 1)[1].split("</textarea>", 1)[0]


def test_agree_needs_confirmation_and_saves_with_it(web):
    pid, hub_id = conflict_project(web)
    db = web.app.state.db
    refused = post_review(web, pid, hub_id, decision="agree", comment=COMMENT)
    assert refused.status_code >= 400 and "расходится с исследованием" in refused.text, refused.text
    assert db.get_review(pid, hub_id) is None or not db.get_review(pid, hub_id)["decision"], "без подтверждения решение не сохранено"
    saved = post_review(web, pid, hub_id, decision="agree", comment=COMMENT, confirm_conflict="1")
    assert saved.status_code == 200, saved.text
    review = db.get_review(pid, hub_id)
    assert review["decision"] == "agree" and review["final_verdict"] == "false_positive"


def test_new_research_after_page_was_opened_makes_it_stale(web):
    """Совет принимается по исследованию, которое видел оператор; принято новое – страница устарела, в том числе с подтверждением."""
    pid = project_with_components(web)
    finding = web.app.state.db.get_finding_by_hub_id(pid, "73001")["data"]
    own = [*(finding.get("vuln_ids") or []), *(finding.get("cve") or [])]
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2", conclusion="not_applicable", ids={}, vulnerabilities=own))).status_code == 303
    fid, card = sca_card(web, pid, "73001")
    assert 'name="research_shown" value="0"' in card and 'id="advice-conflict"' not in card
    expect_accepted(web, pid, answer_document(build_task(web, pid)))
    data = {**form_fields(card), "action": "save", "reviewed": "1", "decision": "agree", "comment": COMMENT, "research_shown": "0", "confirm_conflict": "1"}
    stale = web.client.post(f"/projects/{pid}/sca/findings/{fid}/review", headers=AS_JSON, data=data)
    assert stale.status_code >= 400, stale.text
    assert web.app.state.db.get_review(pid, "73001") is None or not web.app.state.db.get_review(pid, "73001")["decision"]


def test_own_decision_is_not_blocked(web):
    pid, hub_id = conflict_project(web)
    saved = post_review(web, pid, hub_id, decision="disagree", final_verdict="true_positive", comment=COMMENT)
    assert saved.status_code == 200, saved.text


def test_no_conflict_keeps_prefill_and_agree(web):
    """Совет «обновить» или совпадающий с исследованием: всё как раньше."""
    pid, hub_id = conflict_project(web, conclusion="update")
    _, card = sca_card(web, pid, hub_id)
    assert 'id="advice-conflict"' not in card and 'id="advice-conflict-confirm"' not in card
    assert post_review(web, pid, hub_id, decision="agree", comment=COMMENT).status_code == 200


def test_send_waits_for_operator_when_research_came_after_decision(web):
    """Согласие сохранено до исследования: отправка статуса ждёт оператора; подтверждение сохранением её открывает."""
    from app.routes.sca import unconfirmed_conflict
    from test_hub_defects import hub_settings
    from test_hub_status_routes import shown_send_fields
    pid = project_with_components(web)
    hub_settings(web, pid)
    db = web.app.state.db
    finding = db.get_finding_by_hub_id(pid, "73001")["data"]
    own = [*(finding.get("vuln_ids") or []), *(finding.get("cve") or [])]
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2", conclusion="not_applicable", ids={}, vulnerabilities=own))).status_code == 303
    fid, _ = sca_card(web, pid, "73001")
    assert db.save_review(pid, "73001", decision="agree", final_verdict="false_positive", final_comment=COMMENT, reviewed=True)
    with db._tx() as c:
        c.execute("UPDATE reviews SET reviewed_at = '2020-01-01T00:00:00+00:00' WHERE project_id = ? AND hub_id = '73001'", (pid,))
    expect_accepted(web, pid, answer_document(build_task(web, pid)))
    f = Finding.from_dict(db.get_finding_by_hub_id(pid, "73001")["data"])
    assert unconfirmed_conflict(db, pid, f, db.get_review(pid, "73001"))
    _, card = sca_card(web, pid, "73001")
    assert 'id="hub-send-conflict"' in card and 'id="go-send"' not in card and 'id="hub-send-form"' not in card
    saved = post_review(web, pid, "73001", decision="agree", comment=COMMENT, confirm_conflict="1")
    assert saved.status_code == 200, saved.text
    assert not unconfirmed_conflict(db, pid, f, db.get_review(pid, "73001")), "подтверждено оператором"
    assert shown_send_fields(web, pid, "73001", kind="sca/findings"), "форма отправки вернулась"


def test_list_names_the_filter_and_shows_conflict_with_reason(web):
    pid, _ = conflict_project(web)
    page = web.client.get(f"/projects/{pid}/sca?show=not_applicable").text
    assert "Совет агента: не применимо" in page
    assert "расходится: исследование компонента" in page and "Версия вне затронутого диапазона." in page
