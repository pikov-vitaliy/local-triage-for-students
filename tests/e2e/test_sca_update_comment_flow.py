"""Комментарий SCA при выборе «обновить» в браузере (план dev7, раздел 6): подставляется из исследования, текст оператора остаётся.
Данные выдуманы, сеть – только приложение на 127.0.0.1. Снимки пишутся, если задан E2E_SHOTS."""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import no_horizontal_scroll, open_page  # noqa: E402
from test_component_research_ui import answer_document, build_task, expect_accepted, project_with_components  # noqa: E402
from test_defect_where_flow import stand  # noqa: E402,F401
from test_sca import answer, answers_json, post_answers, sca_card  # noqa: E402
from test_web import web  # noqa: E402,F401

pytestmark = pytest.mark.e2e
WIDTH = 1600


def shot(page, name: str) -> None:
    folder = os.environ.get("E2E_SHOTS")
    if not folder:
        return
    for theme in ("light", "dark"):
        page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
        page.wait_for_timeout(500)
        page.screenshot(path=str(Path(folder) / f"{name}-{theme}.png"), full_page=True)


def test_update_fills_comment_and_keeps_operator_text(browser, stand):  # noqa: F811
    web, url = stand
    pid = project_with_components(web)
    expect_accepted(web, pid, answer_document(build_task(web, pid)))
    finding = web.app.state.db.get_finding_by_hub_id(pid, "73001")["data"]
    own = [*(finding.get("vuln_ids") or []), *(finding.get("cve") or [])]
    assert post_answers(web, pid, answers_json(answer("example-parser", "1.4.2", conclusion="not_applicable", ids={}, vulnerabilities=own))).status_code == 303
    fid, _ = sca_card(web, pid, "73001")
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/sca/findings/{fid}")
        comment = page.locator('[name="comment"]').first
        select = page.locator("#final-verdict")
        select.select_option("false_positive")
        comment.fill("Текст оператора: проверено вручную.")
        select.select_option("true_positive")
        expect(comment).to_have_value("Текст оператора: проверено вручную.")
        comment.fill("")
        select.select_option("false_positive")
        select.select_option("true_positive")
        expect(comment).to_have_value(re.compile(r"^Обновить example-parser до версии .+\. Применимые уязвимости: "))
        no_horizontal_scroll(page)
        shot(page, "s6-update-comment")
        # заготовка агента сохранена вместе с согласием: выбор «обновить» заменяет её, «Согласен» становится своим решением
        suggestion = page.locator("#review-form").get_attribute("data-model-comment")
        assert suggestion and suggestion.startswith("Не применимо")
        web.app.state.db.save_review(pid, "73001", decision="agree", final_verdict="false_positive", final_comment=suggestion, reviewed=True)
        fresh = context.new_page()  # черновик правок формы живёт в своей вкладке: здесь – то, что сохранено
        fresh.goto(f"/projects/{pid}/sca/findings/{fid}")
        saved = fresh.locator('[name="comment"]').first
        expect(saved).to_have_value(suggestion)
        fresh.locator("#final-verdict").select_option("true_positive")
        expect(saved).to_have_value(re.compile(r"^Обновить example-parser до версии "))
        expect(fresh.locator('input[name="decision"][value="disagree"]')).to_be_checked()
        assert watch.page_errors == []
    finally:
        context.close()
