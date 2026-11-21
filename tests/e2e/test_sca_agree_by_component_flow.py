"""«Согласен с агентом» по выводу исследования компонента, в Chrome (0.10.0.dev28, ADR-0154): у находки только
внутренний номер, исследование его не опознаёт – карточка предупреждает, согласие доступно и сохраняется.
Данные выдуманы, сеть – только приложение на 127.0.0.1."""

from __future__ import annotations

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import no_horizontal_scroll, open_page, save_sca_decision  # noqa: E402
from test_component_research_ui import answer_document, build_task, expect_accepted, project_with_components  # noqa: E402
from test_defect_where_flow import stand  # noqa: E402,F401
from test_sca import sca_card  # noqa: E402
from test_web import web  # noqa: E402,F401

pytestmark = pytest.mark.e2e
WIDTH = 1600


def test_operator_agrees_with_the_component_conclusion(browser, stand):  # noqa: F811
    web, url = stand  # noqa: F811
    pid = project_with_components(web)
    expect_accepted(web, pid, answer_document(build_task(web, pid)))
    fid, _ = sca_card(web, pid, "73001")
    context, page, watch = open_page(browser, url, width=WIDTH, height=1000)
    try:
        page.goto(f"/projects/{pid}/sca/findings/{fid}")
        warning = page.locator("#answer-by-component")
        expect(warning).to_be_visible()
        expect(warning).to_contain_text("AST-2026-000101")
        expect(warning).to_contain_text("вывод исследования по компоненту в целом")
        expect(page.locator("#answer-stale")).to_have_count(0)
        agree = page.locator('input[name="decision"][value="agree"]')
        expect(agree).to_be_enabled()
        # как оператор: щелчок по подписи переключателя (сам переключатель закрыт подписью)
        page.locator("label").filter(has=agree).click()
        expect(agree).to_be_checked()
        expect(page.locator("#final-verdict")).to_have_value("true_positive")
        assert no_horizontal_scroll(page)
        save_sca_decision(page)
        review = web.app.state.db.get_review(pid, "73001")
        assert (review["decision"], review["final_verdict"]) == ("agree", "true_positive")
        assert str(review["answer_sig"]).startswith("research:")
        # после сохранения решение действует: карточка не просит сверить его с ответом
        expect(page.locator("#answer-changed")).to_have_count(0)
        expect(page.locator('input[name="decision"][value="agree"]')).to_be_checked()
        assert watch.page_errors == []
    finally:
        context.close()
