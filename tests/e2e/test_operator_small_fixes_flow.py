"""Мелочи оператора в браузере (план dev7, раздел 5): вывод, выбранный рукой, отмечает своё решение и сохраняется без второго выбора; счётчик
показывает длину текста для Hub; вкладка «Дефекты» считает как заголовок. Данные выдуманы, сеть – только приложение на 127.0.0.1."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import no_horizontal_scroll, open_page  # noqa: E402
from test_defect_where_flow import stand  # noqa: E402,F401
from test_hub_status_routes import fid, project, sca  # noqa: E402
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


def test_verdict_chosen_by_hand_is_own_decision(browser, stand):  # noqa: F811
    web, url = stand
    pid = project(web, [sca("50001")])
    db = web.app.state.db
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/sca/findings/{fid(web, pid, '50001')}")
        expect(page.locator('input[name="decision"]:checked')).to_have_count(0)
        page.locator("#final-verdict").select_option("false_positive")
        expect(page.locator('input[name="decision"][value="disagree"]')).to_be_checked()
        expect(page.locator("#final-verdict")).to_have_value("false_positive")
        comment = page.locator('[name="comment"]').first
        comment.fill("Версия вне затронутого диапазона: проверено по бюллетеню производителя.")
        expect(page.locator("#comment-count, [id$='comment-count']").first).to_contain_text("в Hub уйдёт")
        no_horizontal_scroll(page)
        shot(page, "s5-sca-own")
        page.locator("#save-btn, button[name='action'][value='save']").first.click()
        for _ in range(50):
            review = db.get_review(pid, "50001")
            if review and review["decision"]:
                break
            page.wait_for_timeout(100)
        assert review["decision"] == "disagree" and review["final_verdict"] == "false_positive"
        assert watch.page_errors == []
    finally:
        context.close()
