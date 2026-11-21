"""HUB-AUD-09 в браузере (аудит 01.11.2026, раздел 7): после принятия «Pull из Hub» список («Отправить выбранные») и
карточка одинаково видят исключённых и готовых участников группы SAST – статус, поставленный в Hub извне, исключает
находку с причиной, готовая уходит одна. Hub, номера и данные выдуманы; сеть – только приложение на 127.0.0.1."""

from __future__ import annotations

import re

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import expect  # noqa: E402

from e2e_support import open_page  # noqa: E402
from test_hub_sync_flow import sync_server  # noqa: E402,F401

pytestmark = pytest.mark.e2e

REASON = "Значение задано константой."


def test_pull_then_list_and_card_agree_on_excluded_member(browser, sync_server):
    from app.db import loads
    from app.models import Finding
    from app.triage import order_findings
    from test_hub_pull import PullHub, finish_pull

    url, app = sync_server
    db = app.state.db
    pid = db.create_project("Демо HUB-AUD-09")
    db.update_project(pid, hub_app_id=7)
    db.save_import(pid, "demo.csv", "csv", [], {}, [], order_findings([
        Finding(hub_id=h, kind="SAST", rule="Внедрение SQL", cwe=["CWE-89"], codebase="demo", file="demo.py", line=2,
                snippet="query = 'SELECT ' + value", severity="high") for h in ("1", "2")]))
    for h in ("1", "2"):
        db.save_review(pid, h, decision="agree", final_verdict="false_positive", final_comment=REASON, reviewed=True)
    ids = {h: db._scalar("SELECT id FROM findings WHERE project_id=? AND hub_id=?", (pid, h)) for h in ("1", "2")}
    hub = PullHub(2, defects=False)
    for item in hub.issues.values():
        item["status"] = "To verify"
        item["issueBranchBriefData"][0]["status"] = "To verify"
    hub.decision(2, reason=REASON)  # в Hub находке 2 статус поставили извне
    context, page, watch = open_page(browser, url)
    try:
        page.goto(f"/projects/{pid}/defects")
        page.locator("#hub-sync-start").click()
        page.locator("#hub-sync-confirm").click()
        expect(page.locator("#hub-sync-progress")).to_be_visible()
        rid = db._scalar("SELECT MAX(id) FROM hub_defect_sync_runs")
        finish_pull(db, hub, rid)
        expect(page.locator("#hub-sync-apply")).to_be_visible()
        page.locator('#hub-sync-apply-form input[name="confirm"]').check()
        page.locator("#hub-sync-apply").click()
        expect(page.locator("#hub-sync-applied")).to_contain_text("Состояние Hub принято")
        # список: обе выбраны – в предпросмотре готова одна, вторая исключена с причиной
        page.goto(f"/projects/{pid}/findings?kind=SAST")
        page.locator("table thead .check-all").check()
        page.click("#send-selected")
        page.wait_for_url(re.compile(r"/hub/send-selected\?"))
        expect(page.locator("#bulk-ready tbody tr")).to_have_count(1)
        expect(page.locator("#bulk-excluded li")).to_have_count(1)
        expect(page.locator("#bulk-excluded")).to_contain_text("2")
        expect(page.locator("#bulk-excluded")).to_contain_text("статус уже внесён в Hub")
        # карточка 2: решение и отметка из Hub
        page.goto(f"/projects/{pid}/findings/{ids['2']}")
        expect(page.locator("#entered-badge")).to_be_visible()
        expect(page.locator("#hub-accepted-state")).to_contain_text(REASON)
        # карточка 1: постановка из карточки уходит одной находкой и называет пропущенную соседку
        page.goto(f"/projects/{pid}/findings/{ids['1']}")
        page.locator("#hub-send [data-date-value]", has_text="+90 дней").click()
        page.locator("#hub-send-button").click()
        expect(page.locator("#hub-send-status")).to_contain_text("В очереди")
        expect(page.locator("#toasts")).to_contain_text("Уже внесена в Hub и не отправляется: 2")
        op = db._one("SELECT request_json FROM hub_ops WHERE purpose='status' ORDER BY id DESC LIMIT 1")
        assert loads(op["request_json"], {})["body"]["issueId"] == 1
        assert not watch.problems(), watch.problems()
    finally:
        context.close()
