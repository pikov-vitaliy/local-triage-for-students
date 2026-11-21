"""Последняя непроверенная находка возвращает оператора к решению."""

import pytest
from playwright.sync_api import expect

from test_defect_where_flow import stand  # noqa: F401
from test_hub_status_routes import fid, project, sca
from test_web import web  # noqa: F401

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize("decision", ["later", "disagree"])
def test_last_next_keeps_decision(browser, stand, decision):
    web, url = stand
    pid = project(web, [sca("101")])
    context = browser.new_context(base_url=url, java_script_enabled=False)
    page = context.new_page()
    try:
        page.goto(f"/projects/{pid}/sca/findings/{fid(web, pid, '101')}")
        page.locator(f'label:has(input[name="decision"][value="{decision}"])').click()
        if decision == "disagree":
            page.locator("#final-verdict").select_option("false_positive")
            page.locator('[name="comment"]').first.fill("Версия вне затронутого диапазона.")
        page.locator('input[name="reviewed"]').uncheck()
        page.locator('button[name="action"][value="next"]').click()
        expect(page).to_have_url(f"{url}/projects/{pid}/sca/findings/{fid(web, pid, '101')}"
                                 f"?ok=sca_no_other&back=%2Fprojects%2F{pid}%2Fsca#decision")
        expect(page.locator("#decision")).to_be_in_viewport()
    finally:
        context.close()
