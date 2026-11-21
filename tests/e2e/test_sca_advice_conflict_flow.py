"""Расхождение совета агента с исследованием в браузере (план dev7, раздел 2): оператор идёт от фильтра к карточке, видит предупреждение,
пустые вывод и комментарий; «Согласен с агентом» без подтверждения не сохраняется. Данные выдуманы, сеть – только приложение на 127.0.0.1."""

from __future__ import annotations

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import no_horizontal_scroll, open_page  # noqa: E402
from test_hub_block_version_flow import WIDTH, shot, stand  # noqa: E402,F401
from test_sca_advice_conflict import COMMENT, conflict_project  # noqa: E402
from test_web import web  # noqa: E402,F401

pytestmark = pytest.mark.e2e


def test_filter_card_warning_and_confirmation(browser, stand):  # noqa: F811
    web, url = stand
    db = web.app.state.db
    pid, hub_id = conflict_project(web)
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/sca")
        page.get_by_role("link", name="Совет агента: не применимо").first.click()
        row = page.locator("table tbody tr").filter(has_text="расходится: исследование компонента").first
        expect(row).to_contain_text("Версия вне затронутого диапазона.")
        no_horizontal_scroll(page)
        shot(page, "s2-list")
        fid = db.get_finding_by_hub_id(pid, hub_id)["id"]
        page.goto(f"/projects/{pid}/sca/findings/{fid}")
        expect(page.locator("#advice-conflict")).to_contain_text("расходится с исследованием")
        expect(page.locator("#finding-summary")).to_contain_text("расходится с исследованием")
        assert page.locator('#review-form [name="comment"], [name="comment"][form="review-form"]').first.input_value() == ""
        no_horizontal_scroll(page)
        shot(page, "s2-card")
        # «Согласен» без подтверждения – понятный отказ, решения нет
        page.locator('input[name="decision"][value="agree"]').check(force=True)
        assert page.locator('#review-form select[name="final_verdict"], select[name="final_verdict"][form="review-form"]').first.input_value() == "", "вывод не подставлен"
        assert page.locator('[name="comment"]').first.input_value() == "", "текст не подставлен"
        assert not page.locator("#reviewed-box").is_checked(), "«Проверено» само не ставится"
        page.locator('[name="comment"]').first.fill(COMMENT)
        page.locator('#review-form button[type="submit"], button[type="submit"][form="review-form"]').first.click()
        expect(page.get_by_text("чтобы всё же принять совет").first).to_be_visible()
        assert not (db.get_review(pid, hub_id) or {}).get("decision")
        shot(page, "s2-refused")
        page.locator('#advice-conflict-confirm input').check()
        # ответ агента не про вторую уязвимость: находка 73002 с тем же советом не решается, её галочка снимается
        page.locator('input[name="apply_to"][value="73002"]').uncheck()
        page.locator('#review-form button[type="submit"], button[type="submit"][form="review-form"]').first.click()
        for _ in range(40):
            if (db.get_review(pid, hub_id) or {}).get("decision") == "agree":
                break
            page.wait_for_timeout(250)
        assert db.get_review(pid, hub_id)["final_verdict"] == "false_positive"
        assert watch.page_errors == []
    finally:
        context.close()
