"""Форма «Решение оператора» на карточке компонента: календарь и быстрый срок
пересмотра +30/+90/+180 от даты приложения (вариант А), «Заполнить по исследованию» – черновик пустых полей по фактам
исследования (вариант Б). Пакеты и идентификаторы выдуманы."""

from __future__ import annotations

import json
import re
from datetime import date, timedelta

from app import sca_research as research
from test_component_research_ui import (FIXED_VERSION, LATEST_VERSION, VULN_ID, answer_document, build_task,
                                        expect_accepted, project_with_components, section)
from test_web import ORIGIN, web  # noqa: F401

TODAY = date(2026, 10, 25)


def view(**overrides) -> dict:
    """Строка исследования так, как её отдаёт sca_research.row_view (только нужные черновику поля)."""
    base = {"researched": True, "version": "1.4.2", "revision": 3, "fresh_at": "2026-10-25T21:31:00Z",
            "findings": [{"id": "CVE-2099-10001", "applies": "yes"}, {"id": "CVE-2099-20002", "applies": "no"},
                         {"id": "CVE-2099-30003", "applies": "unknown"}],
            "advice_detail": {"action": "update", "target_version": "9.9.9", "compatibility_notes": None,
                              "remaining_risks": ["Нужна проверка в приложении"]},
            "latest_stable": "9.9.9", "support_state": "supported", "support_label": "поддерживается",
            "gaps_items": [{"code": "COVERAGE_INCOMPLETE", "code_label": "охват источников неполный"}]}
    return {**base, **overrides}


def test_draft_follows_the_research_advice_and_facts():
    draft = research.decision_draft(view(), TODAY)
    assert draft["action"] == "update" and draft["target_version"] == "9.9.9" and draft["review_at"] == ""
    text = draft["rationale"]
    for needle in ("от 2026-10-25, ревизия 3", "К версии 1.4.2 применимы уязвимости (1 из 3): CVE-2099-10001.",
                   "Применимость не установлена: CVE-2099-30003.", "Совет исследования: обновить до 9.9.9.",
                   "Последний стабильный релиз – 9.9.9.", "Поддержка: поддерживается.",
                   "Остаточные риски: Нужна проверка в приложении.", "Пробелы исследования: охват источников неполный."):
        assert needle in text, needle
    assert len(text) <= research.RATIONALE_CHARS


def test_draft_without_clear_advice_is_investigate_with_a_review_date():
    draft = research.decision_draft(view(advice_detail={"action": "insufficient_data"}, findings=[]), TODAY)
    assert draft["action"] == "investigate" and draft["target_version"] == ""
    assert draft["review_at"] == (TODAY + timedelta(days=90)).isoformat()
    assert "Публичных уязвимостей версии 1.4.2 не найдено." in draft["rationale"]
    risk = research.decision_draft(view(advice_detail={"action": "accept_risk"}), TODAY)
    assert risk["action"] == "accept_risk" and risk["review_at"] == "2027-01-23"
    assert research.decision_draft(view(advice_detail={"action": "no_action"}), TODAY)["action"] == "keep"
    assert research.decision_draft({"researched": False}, TODAY) == {}


def test_draft_names_many_vulnerabilities_by_count_and_stays_within_the_limit():
    many = [{"id": f"CVE-2099-{n:05d}", "applies": "yes"} for n in range(40)]
    risks = ["Длинный остаточный риск " + "х" * 300 for _ in range(10)]
    text = research.decision_draft(view(findings=many, advice_detail={"action": "update", "target_version": "2.0",
                                                                         "remaining_risks": risks}), TODAY)["rationale"]
    assert "CVE-2099-00004 и ещё 35" in text and "CVE-2099-00005" not in text
    assert len(text) == research.RATIONALE_CHARS and text.endswith("…")


def test_review_presets_count_from_the_app_date():
    assert research.review_presets(TODAY) == [(30, "2026-11-24"), (90, "2027-01-23"), (180, "2027-04-23")]


def test_batch_draft_merges_versions_and_marks_different_advice():
    one = view()
    assert research.batch_decision_draft([one], TODAY) == {**research.decision_draft(one, TODAY), "note": "", "skipped": 0}
    other = view(version="1.4.3", findings=[{"id": "CVE-2099-10001", "applies": "no"}],
                 advice_detail={"action": "keep", "target_version": "", "compatibility_notes": None, "remaining_risks": []})
    both = research.batch_decision_draft([one, other, {"researched": False, "version": "1.4.4"}], TODAY)
    assert both["action"] == "" and both["target_version"] == "" and both["skipped"] == 1
    assert "1.4.2 – обновить" in both["note"] and "1.4.3 – оставить" in both["note"]
    assert both["rationale"].startswith("Версия 1.4.2: По исследованию") and "Версия 1.4.3: По исследованию" in both["rationale"]
    same = research.batch_decision_draft([one, view(version="1.4.3")], TODAY)
    assert same["action"] == "update" and same["target_version"] == "9.9.9" and same["note"] == ""
    assert research.batch_decision_draft([{"researched": False, "version": "1"}], TODAY) == {}


def test_batch_decision_page_has_calendar_presets_and_research_draft(web):  # noqa: F811
    from hub_fixtures import SCA_ROWS
    second = dict(SCA_ROWS[0], **{"Issue id": "73009", "Component version": "1.4.3"})
    pid = project_with_components(web, rows=[SCA_ROWS[0], second])
    manifest = build_task(web, pid)
    expect_accepted(web, pid, answer_document(manifest))
    refs = [r["input_ref"] for r in manifest["rows"]]
    page = web.client.post(f"/projects/{pid}/components/decisions/preview", headers=ORIGIN, data={"input_ref": refs[:1]})
    assert page.status_code == 200, page.text
    html = page.text
    assert re.search(r'<input type="date" name="review_at" id="batch-review-at"', html)
    today = date.today()
    presets = re.findall(r'data-review-date="([^"]+)"[^>]*>\+(\d+) дней', html)
    assert presets == [((today + timedelta(days=d)).isoformat(), str(d)) for d in (30, 90, 180)]
    draft = json.loads(re.search(r"id=\"fill-from-research\" data-draft='([^']*)'", html).group(1))
    assert draft["action"] == "update" and draft["target_version"] == FIXED_VERSION and VULN_ID in draft["rationale"]
    # две версии с разным советом: действие пустое, пояснение на странице, обоснование по обеим версиям
    both = web.client.post(f"/projects/{pid}/components/decisions/preview", headers=ORIGIN, data={"input_ref": refs}).text
    draft = json.loads(re.search(r"id=\"fill-from-research\" data-draft='([^']*)'", both).group(1))
    assert draft["action"] == "" and "Версия 1.4.2:" in draft["rationale"] and "Версия 1.4.3:" in draft["rationale"]
    assert "Совет исследования у версий разный" in both
    # неверная дата после отказа остаётся видна в текстовом поле
    bad = web.client.post(f"/projects/{pid}/components/decisions/apply", headers=ORIGIN, data={
        "snapshots": re.search(r'name="snapshots" value="([^"]*)"', html).group(1).replace("&#34;", '"').replace("&quot;", '"'),
        "action": "keep", "rationale": "x", "review_at": "31.12.2026", "confirm": "1"})
    assert bad.status_code == 422 and 'type="text" name="review_at" id="batch-review-at" value="31.12.2026"' in bad.text


def test_component_card_has_calendar_presets_and_research_draft(web):  # noqa: F811
    pid = project_with_components(web)
    manifest = build_task(web, pid)
    expect_accepted(web, pid, answer_document(manifest))
    input_ref = manifest["rows"][0]["input_ref"]
    html = section(web.client.get(f"/projects/{pid}/components/{input_ref}").text, "operator-decision")
    assert re.search(r'<input type="date" name="review_at" id="decision-review-at"', html)
    today = date.today()
    presets = re.findall(r'data-review-date="([^"]+)"[^>]*>\+(\d+) дней', html)
    assert presets == [((today + timedelta(days=d)).isoformat(), str(d)) for d in (30, 90, 180)]
    draft = json.loads(re.search(r"id=\"fill-from-research\" data-draft='([^']*)'", html).group(1))
    assert draft["action"] == "update" and draft["target_version"] == FIXED_VERSION
    assert VULN_ID in draft["rationale"] and f"Последний стабильный релиз – {LATEST_VERSION}." in draft["rationale"]
    # строка без исследования (вторая строка ответа исследована как «нет уязвимостей») – тоже с черновиком
    second = section(web.client.get(f"/projects/{pid}/components/{manifest['rows'][1]['input_ref']}").text,
                     "operator-decision")
    assert json.loads(re.search(r"data-draft='([^']*)'", second).group(1))["action"] == "keep"
