"""Отбор по принятому статусу Hub в Chrome, без обращения к Hub."""

import pytest
from playwright.sync_api import expect

from app.models import Finding
from e2e_support import open_page
from test_defect_where_flow import stand  # noqa: F401
from test_finding_status_now import accept_state
from test_hub_status_routes import fid, project
from test_web import web  # noqa: F401

pytestmark = pytest.mark.e2e


def test_accepted_status_filter(browser, stand):
    web, url = stand
    pid = project(web, [Finding(hub_id="101", kind="SAST", status="Open"),
                        Finding(hub_id="102", kind="SAST", status="Open")])
    accept_state(web, pid, "101", "Fixed")
    context, page, watch = open_page(browser, url)
    try:
        page.goto(f"/projects/{pid}/findings")
        page.locator("#findings-filters > summary").click()
        page.locator('nav[aria-labelledby="filter-hub_status"] a', has_text="Fixed").click()
        expect(page.locator("table.table-findings tbody tr")).to_have_count(1)
        expect(page.locator(f"#finding-{fid(web, pid, '101')}")).to_be_visible()
        assert not watch.problems()
    finally:
        context.close()
