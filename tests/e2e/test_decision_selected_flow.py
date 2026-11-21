"""«Решение на отмеченные» в браузере (план dev7, раздел 7): оператор отмечает находки в списке, задаёт одно решение, видит состав и сохраняет.
Данные выдуманы, сеть – только приложение на 127.0.0.1. Снимки пишутся, если задан E2E_SHOTS."""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import no_horizontal_scroll, open_page  # noqa: E402
from test_defect_selected import setup as selected_project  # noqa: E402
from test_defect_where_flow import stand  # noqa: E402,F401
from test_web import web  # noqa: E402,F401

pytestmark = pytest.mark.e2e
WIDTH = 1600
FP = "Имя таблицы задано константой, внешний ввод в запрос не попадает."


def shot(page, name: str) -> None:
    folder = os.environ.get("E2E_SHOTS")
    if not folder:
        return
    for theme in ("light", "dark"):
        page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
        page.wait_for_timeout(500)
        page.screenshot(path=str(Path(folder) / f"{name}-{theme}.png"), full_page=True)


def test_operator_applies_one_decision_to_marked_findings(browser, stand):  # noqa: F811
    web, url = stand
    pid = selected_project(web)
    db = web.app.state.db
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/findings?kind=SAST")
        for hub_id in ("101", "102"):
            page.locator(f'input.row-check[value="{hub_id}"]').check()
        expect(page.locator("#decide-selected")).to_be_enabled()
        page.locator("#decide-selected").click()
        page.wait_for_url(re.compile(r"/hub/decide-selected"))
        expect(page.locator("#decide-included")).to_contain_text("101")
        expect(page.locator("#decide-included")).to_contain_text("102")
        page.locator('input[name="outcome"][value="false_positive"]').check()
        page.locator("#decide-comment").fill(FP)
        no_horizontal_scroll(page)
        shot(page, "s7-form")
        page.locator("#decide-preview").click()
        expect(page.locator("#decide-comment-shown")).to_have_text(FP)
        expect(page.locator("#decide-apply")).to_contain_text("Сохранить на 2")
        no_horizontal_scroll(page)
        shot(page, "s7-preview")
        page.locator("#decide-confirm").check()
        page.locator("#decide-apply").click()
        page.wait_for_url(re.compile(r"ok=decide_selected"))
        for hub_id in ("101", "102"):
            review = db.get_review(pid, hub_id)
            assert review["final_verdict"] == "false_positive" and review["final_comment"] == FP and review["reviewed"] == 1
        assert not db.get_review(pid, "103") or not db.get_review(pid, "103")["decision"]
        assert watch.page_errors == []
    finally:
        context.close()
